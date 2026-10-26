//! Independent time retention. Unknown controller timestamps are preserved.
use crate::{dsm::BoundaryError, model::HardwareLog, store::Store};
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub events_days: u32,
    pub hardware_logs_days: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            events_days: 90,
            hardware_logs_days: 90,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.events_days <= 36500 && self.hardware_logs_days <= 36500,
            BoundaryError("retention_invalid")
        );
        Ok(())
    }
    pub fn accepts(&self, log: &HardwareLog, now: i64) -> bool {
        if self.hardware_logs_days == 0 {
            return true;
        }
        log.created
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .is_none_or(|t| t.timestamp() >= now - i64::from(self.hardware_logs_days) * 86400)
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub events: u64,
    pub hardware_logs: u64,
    pub undated_hardware_logs: u64,
}
pub fn initialize(conn: &Connection) -> Result<()> {
    conn.create_scalar_function(
        "hardware_log_time",
        1,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let raw = ctx.get::<String>(0)?;
            let value = serde_json::from_str::<serde_json::Value>(&raw).ok();
            Ok(value
                .as_ref()
                .and_then(|v| v.get("created"))
                .and_then(serde_json::Value::as_str)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.timestamp()))
        },
    )?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS history_settings(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT NOT NULL,revision INTEGER NOT NULL);")?;
    conn.execute(
        "INSERT OR IGNORE INTO history_settings VALUES(1,?1,0)",
        [serde_json::to_string(&Settings::default())?],
    )?;
    // Persist the daily deadline across service restarts. Give existing installations
    // a full day after migration to make a complete backup or review the new rules.
    conn.execute(
        "INSERT OR IGNORE INTO counters(name,value) VALUES('history_cleanup_due',?1)",
        [crate::now() + 86400],
    )?;
    Ok(())
}
pub fn settings(conn: &Connection) -> Result<(Settings, i64)> {
    let (raw, revision): (String, i64) = conn.query_row(
        "SELECT config,revision FROM history_settings WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let settings: Settings = serde_json::from_str(&raw)?;
    settings.validate()?;
    Ok((settings, revision))
}
impl Store {
    pub fn retention_settings(&self) -> Result<(Settings, i64)> {
        settings(&self.0)
    }
    pub fn save_retention(
        &mut self,
        settings: &Settings,
        revision: i64,
        actor: &str,
    ) -> Result<()> {
        settings.validate()?;
        let tx = self.0.transaction()?;
        let old = crate::retention::settings(&tx)?.0;
        anyhow::ensure!(tx.execute("UPDATE history_settings SET config=?1,revision=revision+1 WHERE id=1 AND revision=?2", params![serde_json::to_string(settings)?,revision])? == 1, BoundaryError("retention_conflict"));
        // A wider window can expose controller entries whose fingerprints were
        // deliberately expired. Import them as history, rather than new alerts.
        if old.hardware_logs_days > 0
            && (settings.hardware_logs_days == 0
                || settings.hardware_logs_days > old.hardware_logs_days)
        {
            tx.execute("UPDATE devices SET logs_initialized=0", [])?;
        }
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'history.settings','application','ok',?2)",params![actor,crate::now()])?;
        tx.commit()?;
        Ok(())
    }
}

// A pending submission must never disappear as a side effect of time retention.
const ELIGIBLE: &str = "NOT EXISTS(SELECT 1 FROM outbox o WHERE o.event_id=e.id AND o.delivered IS NULL AND o.cancelled=0 AND (o.transport IS NULL OR o.transport<>'smtp' OR EXISTS(SELECT 1 FROM mail_recipient m WHERE m.outbox_id=o.id AND m.delivered IS NULL AND m.permanent=0 AND m.attempts<8))) AND NOT EXISTS(SELECT 1 FROM desktop_jobs d WHERE d.event_id=e.id AND d.delivered IS NULL AND d.cancelled=0 AND d.attempts<8) AND NOT EXISTS(SELECT 1 FROM mail_replay r WHERE r.event_id=e.id AND r.state='queued')";
const LOG_TIME: &str = "hardware_log_time(data)";
fn cutoffs(settings: &Settings, now: i64) -> (i64, i64) {
    (
        now - i64::from(settings.events_days) * 86400,
        now - i64::from(settings.hardware_logs_days) * 86400,
    )
}
pub fn preview(conn: &Connection, settings: &Settings, now: i64) -> Result<Counts> {
    settings.validate()?;
    let (events, logs) = cutoffs(settings, now);
    Ok(Counts {
        events: if settings.events_days == 0 {
            0
        } else {
            conn.query_row(
                &format!("SELECT count(*) FROM events e WHERE e.created<?1 AND {ELIGIBLE}"),
                [events],
                |r| r.get(0),
            )?
        },
        hardware_logs: if settings.hardware_logs_days == 0 {
            0
        } else {
            conn.query_row(
                &format!("SELECT count(*) FROM hardware_logs WHERE {LOG_TIME}<?1"),
                [logs],
                |r| r.get(0),
            )?
        },
        undated_hardware_logs: conn.query_row(
            &format!(
                "SELECT count(*) FROM hardware_logs WHERE {LOG_TIME} IS NULL OR {LOG_TIME}>?1"
            ),
            [now + 300],
            |r| r.get(0),
        )?,
    })
}
/// Bounded transactions release the writer lock between batches. Callback supports cancellation.
pub fn cleanup(
    conn: &mut Connection,
    settings: &Settings,
    now: i64,
    progress: impl FnMut(u64) -> Result<()>,
) -> Result<Counts> {
    let revision: i64 = conn.query_row(
        "SELECT revision FROM history_settings WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    cleanup_at_revision(conn, settings, now, revision, progress)
}
pub fn cleanup_at_revision(
    conn: &mut Connection,
    settings: &Settings,
    now: i64,
    revision: i64,
    mut progress: impl FnMut(u64) -> Result<()>,
) -> Result<Counts> {
    settings.validate()?;
    let (event_cutoff, log_cutoff) = cutoffs(settings, now);
    let mut counts = Counts::default();
    let unchanged = |tx: &Connection| -> Result<()> {
        let current: i64 = tx.query_row(
            "SELECT revision FROM history_settings WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        anyhow::ensure!(current == revision, BoundaryError("retention_conflict"));
        Ok(())
    };
    unchanged(conn)?;
    if settings.hardware_logs_days > 0 {
        let mut cursor = 0i64;
        loop {
            progress(counts.hardware_logs + counts.events)?;
            let tx = conn.transaction()?;
            unchanged(&tx)?;
            let ids = {
                let mut q=tx.prepare(&format!("SELECT rowid FROM hardware_logs WHERE rowid>?1 AND {LOG_TIME}<?2 ORDER BY rowid LIMIT 2000"))?;
                let ids = q
                    .query_map(params![cursor, log_cutoff], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                ids
            };
            if ids.is_empty() {
                break;
            }
            cursor = *ids.last().unwrap();
            let mut delete = tx.prepare("DELETE FROM hardware_logs WHERE rowid=?1")?;
            for id in ids {
                counts.hardware_logs += delete.execute([id])? as u64;
            }
            drop(delete);
            tx.commit()?;
        }
    }
    // Paused devices can retain a snapshot indefinitely. Prune its log details too,
    // without replacing a newer poll or altering observations/active alarm state.
    if settings.hardware_logs_days > 0 {
        let mut cursor = String::new();
        loop {
            progress(counts.hardware_logs + counts.events)?;
            let next: Option<(String, Option<String>)> = {
                use rusqlite::OptionalExtension;
                conn.query_row(
                    "SELECT id,snapshot FROM devices WHERE id>?1 ORDER BY id LIMIT 1",
                    [&cursor],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
            };
            let Some((id, raw)) = next else { break };
            cursor = id.clone();
            if let Some(raw) = raw {
                let mut snapshot: crate::model::Snapshot = serde_json::from_str(&raw)?;
                let before = snapshot.logs.len();
                snapshot.logs.retain(|log| settings.accepts(log, now));
                if snapshot.logs.len() != before {
                    let tx = conn.transaction()?;
                    unchanged(&tx)?;
                    tx.execute(
                        "UPDATE devices SET snapshot=?1 WHERE id=?2 AND snapshot=?3",
                        params![serde_json::to_string(&snapshot)?, id, raw],
                    )?;
                    tx.commit()?;
                }
            }
        }
    }
    if settings.events_days > 0 {
        loop {
            progress(counts.hardware_logs + counts.events)?;
            let tx = conn.transaction()?;
            unchanged(&tx)?;
            let ids = {
                let mut q=tx.prepare(&format!("SELECT e.id FROM events e WHERE e.created<?1 AND {ELIGIBLE} ORDER BY e.id LIMIT 2000"))?;
                let ids = q
                    .query_map([event_cutoff], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                ids
            };
            if ids.is_empty() {
                break;
            }
            for id in ids {
                tx.execute("DELETE FROM outbox WHERE event_id=?1", [id])?;
                tx.execute("DELETE FROM desktop_jobs WHERE event_id=?1", [id])?;
                counts.events += tx.execute("DELETE FROM events WHERE id=?1", [id])? as u64;
            }
            tx.commit()?;
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{Device, HardwareLog, Health, Observation, Snapshot},
        vault::Vault,
    };
    fn device() -> Device {
        serde_json::from_value(serde_json::json!({"id":"retention-test","name":"Test","endpoint":"https://bmc.example/","username":"reader","interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true,"ca_file":null})).unwrap()
    }
    fn log(fingerprint: &str, created: Option<&str>) -> HardwareLog {
        HardwareLog {
            fingerprint: fingerprint.into(),
            message: "Hardware event".into(),
            severity: Health::Warning,
            created: created.map(str::to_owned),
        }
    }
    #[test]
    fn policies_are_independent_and_old_logs_cannot_be_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let vault = Vault::open(&dir.path().join("master.key")).unwrap();
        let mut d = device();
        store
            .put(&d, &vault.seal(&d.id, b"synthetic-password").unwrap())
            .unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-26T12:00:00Z")
            .unwrap()
            .timestamp();
        let logs = vec![
            log("old", Some("2021-07-23T04:46:34Z")),
            log("young", Some("2026-10-25T12:00:00Z")),
            log("undated", None),
            log("invalid", Some("2026-02-30T12:00:00Z")),
            log("future", Some("2030-01-01T00:00:00Z")),
        ];
        for entry in &logs {
            store
                .0
                .execute(
                    "INSERT INTO hardware_logs VALUES(?1,?2,?3)",
                    params![
                        d.id,
                        entry.fingerprint,
                        serde_json::to_string(entry).unwrap()
                    ],
                )
                .unwrap();
        }
        store.0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(1,?1,'old','alarm','\"warning\"','Old retained event',?2)",params![d.id,now-100*86400]).unwrap();
        store
            .0
            .execute(
                "INSERT INTO alarm_state VALUES(?1,'psu','\"critical\"','PSU',1,1)",
                [&d.id],
            )
            .unwrap();
        let settings = Settings {
            events_days: 0,
            hardware_logs_days: 90,
        };
        store.save_retention(&settings, 0, "admin").unwrap();
        let expected = preview(&store.0, &settings, now).unwrap();
        assert_eq!(expected.hardware_logs, 1);
        assert_eq!(expected.events, 0);
        assert_eq!(expected.undated_hardware_logs, 3);
        let counts = cleanup(&mut store.0, &settings, now, |_| Ok(())).unwrap();
        assert_eq!(counts.hardware_logs, 1);
        assert_eq!(
            store
                .0
                .query_row("SELECT count(*) FROM alarm_state", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let snapshot = Snapshot {
            logs: logs.clone(),
            logs_complete: true,
            ..Default::default()
        };
        store.apply(&d, &snapshot, now).unwrap();
        assert_eq!(
            store
                .0
                .query_row(
                    "SELECT count(*) FROM hardware_logs WHERE fingerprint='old'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .0
                .query_row("SELECT count(*) FROM hardware_logs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            4
        );
        // Disabling collection does not disable independent cleanup of existing rows.
        d.hardware_log = crate::model::HardwareLogRead::Disabled;
        store
            .put(&d, &vault.seal(&d.id, b"synthetic-password").unwrap())
            .unwrap();
        let settings = Settings {
            events_days: 90,
            hardware_logs_days: 0,
        };
        let counts = cleanup(&mut store.0, &settings, now, |_| Ok(())).unwrap();
        assert_eq!(counts.events, 1);
        assert_eq!(counts.hardware_logs, 0);
        store
            .apply(
                &d,
                &Snapshot {
                    logs: vec![log("disabled-new", Some("2026-10-26T12:00:00Z"))],
                    ..Default::default()
                },
                now,
            )
            .unwrap();
        assert_eq!(
            store
                .0
                .query_row(
                    "SELECT count(*) FROM hardware_logs WHERE fingerprint='disabled-new'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
    #[test]
    fn pending_automatic_and_manual_submissions_survive_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device();
        store.put(&d, b"").unwrap();
        store
            .save_mail(
                &crate::mail::Settings {
                    enabled: true,
                    host: "smtp.example.invalid".into(),
                    from_address: "sender@example.invalid".into(),
                    recipients: vec!["alarm@example.invalid".into()],
                    ..Default::default()
                },
                b"",
                0,
                "admin",
            )
            .unwrap();
        let snapshot = Snapshot {
            observations: vec![Observation {
                key: "fan".into(),
                label: "Fan".into(),
                health: Health::Critical,
                reading: None,
                unit: None,
            }],
            ..Default::default()
        };
        store.apply(&d, &snapshot, 100).unwrap();
        let event: i64 = store
            .0
            .query_row("SELECT id FROM events", [], |r| r.get(0))
            .unwrap();
        let preview = store
            .preview_mail_replay(event, "alarm@example.invalid", "admin", 200)
            .unwrap();
        store
            .enqueue_mail_replay(preview["id"].as_str().unwrap(), "admin", 200)
            .unwrap();
        let now = 100 + 100 * 86400;
        assert_eq!(
            cleanup(&mut store.0, &Settings::default(), now, |_| Ok(()))
                .unwrap()
                .events,
            0
        );
        let mail = store.pending_mail(now).unwrap().unwrap();
        store
            .finish_mail(&mail, Some("mail_rejected"), now)
            .unwrap();
        assert_eq!(
            cleanup(&mut store.0, &Settings::default(), now, |_| Ok(()))
                .unwrap()
                .events,
            0
        );
        store
            .0
            .execute("UPDATE mail_replay SET state='cancelled'", [])
            .unwrap();
        assert_eq!(
            cleanup(&mut store.0, &Settings::default(), now, |_| Ok(()))
                .unwrap()
                .events,
            1
        );
        assert_eq!(
            store
                .0
                .query_row("SELECT count(*) FROM alarm_state", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn policy_changes_interrupt_batches_and_snapshot_cleanup_preserves_measurements() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device();
        store.put(&d, b"").unwrap();
        let old = log("old", Some("2021-07-23T04:46:34Z"));
        let snapshot = Snapshot {
            logs: vec![old.clone()],
            logs_complete: true,
            observations: vec![Observation {
                key: "fan".into(),
                label: "Fan".into(),
                health: Health::Critical,
                reading: None,
                unit: None,
            }],
            ..Default::default()
        };
        store
            .0
            .execute(
                "UPDATE devices SET snapshot=?1",
                [serde_json::to_string(&snapshot).unwrap()],
            )
            .unwrap();
        let now = crate::now();
        cleanup(&mut store.0, &Settings::default(), now, |_| Ok(())).unwrap();
        let raw: String = store
            .0
            .query_row("SELECT snapshot FROM devices", [], |r| r.get(0))
            .unwrap();
        let after: Snapshot = serde_json::from_str(&raw).unwrap();
        assert!(after.logs.is_empty());
        assert_eq!(after.observations.len(), 1);
        assert_eq!(after.observations[0].health, Health::Critical);
        for index in 0..2001 {
            store
                .0
                .execute(
                    "INSERT INTO hardware_logs VALUES(?1,?2,?3)",
                    params![
                        d.id,
                        index.to_string(),
                        serde_json::to_string(&old).unwrap()
                    ],
                )
                .unwrap();
        }
        let mut other = Store::open(dir.path()).unwrap();
        let mut changed = false;
        let result = cleanup_at_revision(&mut store.0, &Settings::default(), now, 0, |processed| {
            if processed >= 2000 && !changed {
                changed = true;
                other
                    .save_retention(
                        &Settings {
                            events_days: 0,
                            hardware_logs_days: 0,
                        },
                        0,
                        "admin",
                    )
                    .unwrap();
            }
            Ok(())
        });
        assert_eq!(
            crate::dsm::error_code(&result.unwrap_err()),
            "retention_conflict"
        );
        assert_eq!(
            store
                .0
                .query_row("SELECT count(*) FROM hardware_logs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn widening_hardware_retention_establishes_a_baseline_without_replaying_old_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device();
        store.put(&d, b"").unwrap();
        let now = crate::now();
        let old = log("old-refetched", Some("2021-07-23T04:46:34Z"));
        store
            .apply(
                &d,
                &Snapshot {
                    logs: vec![old.clone()],
                    logs_complete: true,
                    ..Default::default()
                },
                now,
            )
            .unwrap();
        assert_eq!(
            store
                .0
                .query_row("SELECT logs_initialized FROM devices", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        store
            .save_retention(
                &Settings {
                    events_days: 90,
                    hardware_logs_days: 0,
                },
                0,
                "admin",
            )
            .unwrap();
        assert_eq!(
            store
                .0
                .query_row("SELECT logs_initialized FROM devices", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        store
            .apply(
                &d,
                &Snapshot {
                    logs: vec![old],
                    logs_complete: true,
                    ..Default::default()
                },
                now + 1,
            )
            .unwrap();
        assert_eq!(
            store
                .0
                .query_row("SELECT count(*) FROM hardware_logs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .0
                .query_row(
                    "SELECT count(*) FROM events WHERE kind='hardware_log'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
}

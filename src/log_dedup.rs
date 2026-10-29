//! Redfish log identity is source time + original text, scoped by the store's device key.
use crate::model::HardwareLog;
use anyhow::Result;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

const KEY_PREFIX: &str = "time-text-v1:";
const LEGACY_PREFIX: &str = "legacy-time-text-v1:";
const MIGRATION: &str = "redfish_time_text_v1";

/// Normalize equivalent RFC3339 offsets/precision without losing subsecond identity.
/// No receipt-time fallback: undated logs retain their existing resource identity.
pub(crate) fn fingerprint(created: Option<&str>, message: &str) -> Option<String> {
    let date = chrono::DateTime::parse_from_rfc3339(created?).ok()?;
    let bytes =
        serde_json::to_vec(&(date.timestamp(), date.timestamp_subsec_nanos(), message)).ok()?;
    Some(format!("{KEY_PREFIX}{:x}", Sha256::digest(bytes)))
}

fn legacy_prefix(created: Option<&str>, message: &str) -> Option<String> {
    let prefix: String = message.chars().take(1000).collect();
    fingerprint(created, &prefix).map(|key| key.replacen(KEY_PREFIX, LEGACY_PREFIX, 1))
}

/// Called within startup/restore's transaction. Rekey the cache, never historical
/// events or delivery jobs. Batches bound memory even for large retained logs.
/// The counter is part of backups, so restoring a legacy archive migrates again.
pub(crate) fn migrate(conn: &Connection) -> Result<()> {
    let complete: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM counters WHERE name=?1 AND value=1)",
        [MIGRATION],
        |r| r.get(0),
    )?;
    if complete {
        return Ok(());
    }
    let mut cursor = 0i64;
    loop {
        let rows = {
            let mut query = conn.prepare(
                "SELECT l.rowid,l.device,l.fingerprint,l.data FROM hardware_logs l JOIN devices d ON d.id=l.device
                 WHERE l.rowid>?1 AND COALESCE(json_extract(d.config,'$.primary_protocol'),'redfish')='redfish'
                 ORDER BY l.rowid LIMIT 128",
            )?;
            let rows = query
                .query_map([cursor], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        if rows.is_empty() {
            break;
        }
        for (rowid, device, old_key, raw) in rows {
            cursor = rowid;
            if old_key.starts_with(KEY_PREFIX) || old_key.starts_with(LEGACY_PREFIX) {
                continue;
            }
            let Ok(mut log) = serde_json::from_str::<HardwareLog>(&raw) else {
                // Preserve legacy opaque records that do not have a usable time/text pair.
                continue;
            };
            let key = if log.message.chars().count() == 1000 {
                // Old collectors stored only the first 1000 characters. Adopt
                // one future full-text match without inventing the missing suffix.
                legacy_prefix(log.created.as_deref(), &log.message)
            } else {
                fingerprint(log.created.as_deref(), &log.message)
            };
            let Some(key) = key else { continue };
            log.fingerprint = key.clone();
            let changed = conn.execute(
                "UPDATE OR IGNORE hardware_logs SET fingerprint=?2,data=?3 WHERE rowid=?1",
                params![rowid, key, serde_json::to_string(&log)?],
            )?;
            if changed == 0 {
                // Several old position-based records can describe one occurrence.
                // Remove only the redundant cache row; event history stays intact.
                conn.execute(
                    "DELETE FROM hardware_logs WHERE rowid=?1 AND device=?2 AND fingerprint=?3",
                    params![rowid, device, old_key],
                )?;
            }
        }
    }
    conn.execute(
        "INSERT INTO counters(name,value) VALUES(?1,1) ON CONFLICT(name) DO UPDATE SET value=1",
        [MIGRATION],
    )?;
    Ok(())
}

/// A legacy truncated cache row can be consumed once. Subsequent messages with
/// the same prefix but different original suffixes remain distinct.
pub(crate) fn adopt_truncated(conn: &Connection, device: &str, log: &HardwareLog) -> Result<bool> {
    if !log.fingerprint.starts_with(KEY_PREFIX) || log.message.chars().count() < 1000 {
        return Ok(false);
    }
    let Some(key) = legacy_prefix(log.created.as_deref(), &log.message) else {
        return Ok(false);
    };
    Ok(conn.execute(
        "DELETE FROM hardware_logs WHERE device=?1 AND fingerprint=?2",
        params![device, key],
    )? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::*, store::Store};
    use serde_json::json;

    const TIME: &str = "2026-10-27T06:22:56Z";
    const MESSAGE: &str = "eRS - Device Unregistration Failed: Http Server Protocol Error 403";

    fn device(id: &str) -> Device {
        serde_json::from_value(
            json!({"id":id,"name":"Synthetic server","endpoint":"https://bmc.example/",
            "username":"monitor","interval_seconds":60,"alerts_enabled":true,"enabled":true}),
        )
        .unwrap()
    }
    fn log(uri: &str, id: &str, time: Option<&str>, message: &str) -> HardwareLog {
        let value = json!({"@odata.id":uri,"Id":id,"Created":time,"EntryType":"Oem","Message":message,"Severity":"Warning"});
        let mut logs = Vec::new();
        crate::collector::normalize(uri, &value, &mut Default::default(), &mut logs);
        logs.remove(0)
    }
    fn snapshot(logs: Vec<HardwareLog>) -> Snapshot {
        Snapshot {
            logs,
            logs_complete: true,
            ..Default::default()
        }
    }
    fn count(store: &Store, table: &str) -> i64 {
        store
            .0
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn timestamp_text_ignores_positions_manufacturers_and_log_services() {
        let a = log(
            "/redfish/v1/Managers/1/LogServices/IEL/Entries/189/",
            "189",
            Some(TIME),
            MESSAGE,
        );
        for (uri, id) in [
            ("/redfish/v1/Managers/1/LogServices/IEL/Entries/115/", "115"),
            (
                "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Lclog/Entries/42",
                "42",
            ),
            ("/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Sel", "other"),
        ] {
            assert_eq!(a.fingerprint, log(uri, id, Some(TIME), MESSAGE).fingerprint);
        }
        assert_eq!(
            a.fingerprint,
            log("other", "x", Some("2026-10-27T07:22:56.000+01:00"), MESSAGE).fingerprint
        );
        assert_ne!(
            a.fingerprint,
            log(
                "same",
                "189",
                Some("2026-10-27T06:22:56.000000001Z"),
                MESSAGE
            )
            .fingerprint
        );
        assert_ne!(
            a.fingerprint,
            log("same", "189", Some("2026-10-28T06:22:56Z"), MESSAGE).fingerprint
        );
        assert_ne!(
            a.fingerprint,
            log("same", "189", Some(TIME), "Different text").fingerprint
        );
        let long = "x".repeat(1000);
        let b = log("a", "1", Some(TIME), &(long.clone() + "A"));
        let c = log("a", "1", Some(TIME), &(long + "B"));
        assert_ne!(b.fingerprint, c.fingerprint);
        assert_eq!(b.message.len(), 1000);
    }

    #[test]
    fn timestamp_text_undated_or_invalid_logs_keep_resource_identity() {
        for created in [None, Some("invalid"), Some("")] {
            assert!(fingerprint(created, MESSAGE).is_none());
            let a = log("/redfish/v1/log/1", "1", created, MESSAGE);
            assert_eq!(
                a.fingerprint,
                log("/redfish/v1/log/1", "1", created, MESSAGE).fingerprint
            );
            assert_ne!(
                a.fingerprint,
                log("/redfish/v1/log/2", "2", created, MESSAGE).fingerprint
            );
        }
    }

    #[test]
    fn timestamp_text_100_reads_restart_devices_and_delivery_queues() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let a = device("first");
        let b = device("second");
        for d in [&a, &b] {
            store.put(d, b"encrypted").unwrap();
            store.apply(d, &snapshot(vec![]), 1).unwrap();
        }
        store
            .save_mail(
                &crate::mail::Settings {
                    enabled: true,
                    host: "smtp.example.invalid".into(),
                    from_address: "from@example.invalid".into(),
                    recipients: vec!["to@example.invalid".into()],
                    ..Default::default()
                },
                b"",
                0,
                "admin",
            )
            .unwrap();
        store
            .save_notifications(
                &crate::notification::Input {
                    language: Default::default(),
                    revision: 0,
                    desktop_enabled: true,
                    selection: Default::default(),
                },
                "admin",
            )
            .unwrap();
        let vault = crate::vault::Vault::open(&dir.path().join("master.key")).unwrap();
        let endpoint = store
            .prepare_webhook(
                &crate::webhook::Input {
                    id: None,
                    revision: 0,
                    credential: None,
                    url: Some("https://example.invalid/synthetic-webhook".into()),
                    settings: crate::webhook::Settings {
                        name: "Synthetic target".into(),
                        enabled: true,
                        ..Default::default()
                    },
                },
                &vault,
            )
            .unwrap();
        store.save_webhook(&endpoint, &vault, "admin").unwrap();
        for index in 0..100 {
            let entry = log(
                &format!("/redfish/v1/log/{}", 189 - index),
                &(189 - index).to_string(),
                Some(TIME),
                MESSAGE,
            );
            store.apply(&a, &snapshot(vec![entry]), 10 + index).unwrap();
            if index == 49 {
                drop(store);
                store = Store::open(dir.path()).unwrap();
            }
        }
        assert_eq!(count(&store, "events"), 1);
        assert_eq!(count(&store, "outbox"), 1);
        assert_eq!(count(&store, "desktop_jobs"), 1);
        assert_eq!(count(&store, "webhook_jobs"), 1);
        let mail = store.pending_mail(200).unwrap().unwrap();
        store.finish_mail(&mail, None, 200).unwrap();
        assert!(store.pending_mail(201).unwrap().is_none());
        let desktop = store.pending_desktop(200).unwrap().unwrap();
        assert_eq!(desktop.kind, "hardware_log");
        store
            .apply(
                &b,
                &snapshot(vec![log("same", "1", Some(TIME), MESSAGE)]),
                210,
            )
            .unwrap();
        store
            .apply(
                &a,
                &snapshot(vec![log(
                    "same",
                    "1",
                    Some("2026-10-28T06:22:56Z"),
                    MESSAGE,
                )]),
                211,
            )
            .unwrap();
        store
            .apply(
                &a,
                &snapshot(vec![log("same", "1", Some(TIME), "New message")]),
                212,
            )
            .unwrap();
        assert_eq!(count(&store, "events"), 4);
        assert_eq!(count(&store, "outbox"), 4);
        assert_eq!(count(&store, "desktop_jobs"), 4);
        assert_eq!(count(&store, "webhook_jobs"), 4);
    }

    #[test]
    fn timestamp_text_upgrade_rekeys_known_logs_without_replaying_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device("legacy");
        store.put(&d, b"encrypted").unwrap();
        store.apply(&d, &snapshot(vec![]), 1).unwrap();
        let mut old = log("old", "189", Some("2026-10-27T07:22:56+01:00"), MESSAGE);
        for key in ["old-189", "old-185"] {
            old.fingerprint = key.into();
            store
                .0
                .execute(
                    "INSERT INTO hardware_logs VALUES(?1,?2,?3)",
                    params![d.id, key, serde_json::to_string(&old).unwrap()],
                )
                .unwrap();
        }
        store.0.execute("INSERT INTO events(device,key,kind,health,message,created) VALUES(?1,'log:old-189','hardware_log','\"warning\"','Historical event',1)",[&d.id]).unwrap();
        store
            .0
            .execute("DELETE FROM counters WHERE name=?1", [MIGRATION])
            .unwrap();
        drop(store);
        let mut store = Store::open(dir.path()).unwrap();
        assert_eq!(count(&store, "hardware_logs"), 1);
        store
            .apply(
                &d,
                &snapshot(vec![log("new", "115", Some(TIME), MESSAGE)]),
                2,
            )
            .unwrap();
        assert_eq!(count(&store, "events"), 1);
        assert_eq!(count(&store, "outbox"), 0);
        assert_eq!(
            store
                .0
                .query_row("SELECT message FROM events", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "Historical event"
        );
        store
            .apply(
                &d,
                &snapshot(vec![log("new", "115", Some(TIME), "Genuinely new")]),
                3,
            )
            .unwrap();
        assert_eq!(count(&store, "events"), 2);
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(count(&store, "hardware_logs"), 2);
    }

    #[test]
    fn timestamp_text_upgrade_adopts_truncated_text_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device("long");
        store.put(&d, b"encrypted").unwrap();
        store.apply(&d, &snapshot(vec![]), 1).unwrap();
        let prefix = "ä".repeat(1000);
        let mut old = log("old", "1", Some(TIME), &prefix);
        old.fingerprint = "old-truncated".into();
        store
            .0
            .execute(
                "INSERT INTO hardware_logs VALUES(?1,?2,?3)",
                params![d.id, old.fingerprint, serde_json::to_string(&old).unwrap()],
            )
            .unwrap();
        store
            .0
            .execute("DELETE FROM counters WHERE name=?1", [MIGRATION])
            .unwrap();
        drop(store);
        let mut store = Store::open(dir.path()).unwrap();
        let full = log("new", "2", Some(TIME), &(prefix.clone() + "A"));
        store
            .apply(&d, &snapshot(vec![full.clone(), full]), 2)
            .unwrap();
        assert_eq!(count(&store, "events"), 0);
        assert_eq!(count(&store, "hardware_logs"), 1);
        store
            .apply(
                &d,
                &snapshot(vec![log("new", "2", Some(TIME), &(prefix + "B"))]),
                3,
            )
            .unwrap();
        assert_eq!(count(&store, "events"), 1);
    }
    #[test]
    fn timestamp_text_restore_and_failed_migration_preserve_known_logs() {
        let dir = tempfile::tempdir().unwrap();
        let vault = crate::vault::Vault::open(&dir.path().join("master.key")).unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device("restored");
        store
            .put(&d, &vault.seal(&d.id, b"synthetic-device-secret").unwrap())
            .unwrap();
        store.apply(&d, &snapshot(vec![]), 1).unwrap();
        let mut old = log("old", "189", Some(TIME), MESSAGE);
        old.fingerprint = "legacy-key".into();
        store
            .0
            .execute(
                "INSERT INTO hardware_logs VALUES(?1,?2,?3)",
                params![d.id, old.fingerprint, serde_json::to_string(&old).unwrap()],
            )
            .unwrap();
        store
            .0
            .execute("DELETE FROM counters WHERE name=?1", [MIGRATION])
            .unwrap();
        // Startup and restore call migration inside a transaction: a failure
        // must roll back both the rekey and the completion marker.
        {
            let tx = store.0.transaction().unwrap();
            migrate(&tx).unwrap();
            assert_eq!(
                tx.query_row("SELECT fingerprint FROM hardware_logs", [], |r| r
                    .get::<_, String>(0))
                    .unwrap(),
                fingerprint(Some(TIME), MESSAGE).unwrap()
            );
            tx.rollback().unwrap();
        }
        assert_eq!(
            store
                .0
                .query_row("SELECT fingerprint FROM hardware_logs", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "legacy-key"
        );
        let archive = store.make_archive(&vault).unwrap();
        let target = tempfile::tempdir().unwrap();
        let target_vault = crate::vault::Vault::open(&target.path().join("master.key")).unwrap();
        let mut restored = Store::open(target.path()).unwrap();
        restored
            .restore_archive(&archive, &target_vault, "admin", 0)
            .unwrap();
        let (mut d, _, revision) = restored.get(&d.id).unwrap().unwrap();
        d.enabled = true;
        d.alerts_enabled = true;
        restored
            .save_admin(&d, b"opaque", Some(revision), "admin")
            .unwrap();
        restored
            .apply(
                &d,
                &snapshot(vec![log("new", "115", Some(TIME), MESSAGE)]),
                2,
            )
            .unwrap();
        assert_eq!(count(&restored, "events"), 0);
        assert_eq!(count(&restored, "hardware_logs"), 1);
        restored
            .apply(
                &d,
                &snapshot(vec![log("new", "115", Some(TIME), "New after restore")]),
                3,
            )
            .unwrap();
        assert_eq!(count(&restored, "events"), 1);
    }
}

//! Query diagnostics have a different lifecycle from retained hardware faults.
use crate::model::{Device, HardwareLogRead, Health, PrimaryProtocol, Snapshot};
use anyhow::Result;
use rusqlite::{params, Connection};
use std::collections::BTreeSet;

fn log_coverage(key: &str) -> bool {
    key.strip_prefix("coverage:")
        .is_some_and(crate::collector::log_resource)
}

fn retire(conn: &Connection, device: &str, key: &str, reason: &str) -> Result<()> {
    // Preserve event contents and completed deliveries. Configuration changes
    // are not measured recoveries; cancel only pending automatic deliveries.
    for (queue, column) in [
        ("outbox", "mail_reason"),
        ("desktop_jobs", "desktop_reason"),
    ] {
        conn.execute(
            &format!("UPDATE events SET {column}=?3 WHERE device=?1 AND key=?2 AND kind!='hardware_log' AND id IN (SELECT event_id FROM {queue} WHERE delivered IS NULL AND cancelled=0)"),
            params![device, key, reason],
        )?;
        conn.execute(
            &format!("UPDATE {queue} SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1 AND key=?2 AND kind!='hardware_log' AND {column}=?3)"),
            params![device, key, reason],
        )?;
    }
    // alarm_control follows via its existing foreign-key cascade.
    conn.execute(
        "DELETE FROM alarm_state WHERE device=?1 AND key=?2",
        params![device, key],
    )?;
    Ok(())
}

/// Called inside the device-save/startup/restore transaction. No poll required.
pub(crate) fn disabled(conn: &Connection, d: &Device) -> Result<()> {
    if d.primary_protocol != PrimaryProtocol::Redfish || d.hardware_log != HardwareLogRead::Disabled
    {
        return Ok(());
    }
    let (raw, last_poll): (Option<String>, Option<i64>) = conn.query_row(
        "SELECT snapshot,last_poll FROM devices WHERE id=?1",
        [&d.id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut snapshot: Option<Snapshot> =
        raw.as_ref().map(|s| serde_json::from_str(s)).transpose()?;
    let mut keys = {
        let mut q = conn.prepare("SELECT key FROM alarm_state WHERE device=?1 UNION SELECT key FROM events WHERE device=?1 AND (id IN (SELECT event_id FROM outbox WHERE delivered IS NULL AND cancelled=0) OR id IN (SELECT event_id FROM desktop_jobs WHERE delivered IS NULL AND cancelled=0))")?;
        let rows = q
            .query_map([&d.id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
        rows
    };
    keys.retain(|key| log_coverage(key));
    if let Some(snapshot) = &mut snapshot {
        snapshot.logs_complete = false;
        let removed_failure = snapshot
            .capabilities
            .iter()
            .any(|c| crate::collector::log_resource(&c.uri) && c.outcome != "available");
        snapshot
            .capabilities
            .retain(|c| !crate::collector::log_resource(&c.uri));
        snapshot.observations.retain(|o| !log_coverage(&o.key));
        if removed_failure
            && snapshot
                .capabilities
                .iter()
                .all(|c| c.outcome == "available")
        {
            snapshot
                .observations
                .retain(|o| o.key != "collector" || o.health != Health::Warning);
            // Failed polls keep the previous snapshot but record a Critical
            // collector alarm. Preserve that independent reachability fault.
            conn.execute(
                "DELETE FROM alarm_state WHERE device=?1 AND key='collector' AND health='\"warning\"' AND label='Management-Abfrage unvollständig' AND observed=?2",
                params![d.id, last_poll],
            )?;
            for (queue, column) in [
                ("outbox", "mail_reason"),
                ("desktop_jobs", "desktop_reason"),
            ] {
                conn.execute(
                    &format!("UPDATE events SET {column}='log_reading_disabled' WHERE device=?1 AND key='collector' AND health='\"warning\"' AND json_extract(message_context,'$.label')='Management-Abfrage unvollständig' AND id IN (SELECT event_id FROM {queue} WHERE delivered IS NULL AND cancelled=0)"),
                    [&d.id],
                )?;
                conn.execute(
                    &format!("UPDATE {queue} SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1 AND key='collector' AND {column}='log_reading_disabled')"),
                    [&d.id],
                )?;
            }
        }
        snapshot
            .assessment_exclusions
            .retain(|key, _| !log_coverage(key));
        snapshot.notification_groups.retain(|key, causes| {
            causes.retain(|key| !log_coverage(key));
            !log_coverage(key) && !causes.is_empty()
        });
        let cleaned = serde_json::to_string(snapshot)?;
        if raw.as_ref() != Some(&cleaned) {
            conn.execute(
                "UPDATE devices SET snapshot=?2 WHERE id=?1",
                params![d.id, cleaned],
            )?;
        }
    }
    for key in keys {
        retire(conn, &d.id, &key, "log_reading_disabled")?;
    }
    Ok(())
}

pub(crate) fn reconcile_all_disabled(conn: &Connection) -> Result<()> {
    let devices = {
        let mut q = conn.prepare("SELECT config FROM devices WHERE json_extract(config,'$.hardware_log.mode')='disabled'")?;
        let rows = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for raw in devices {
        disabled(conn, &serde_json::from_str(&raw)?)?;
    }
    Ok(())
}

/// Fresh success supersedes a diagnostic whose key included an old query.
/// Other missing resources remain unassessable and keep their diagnostics.
pub(crate) fn fresh(conn: &Connection, d: &Device, snapshot: &Snapshot) -> Result<()> {
    if d.primary_protocol != PrimaryProtocol::Redfish || d.hardware_log == HardwareLogRead::Disabled
    {
        return Ok(());
    }
    let mut q = conn.prepare("SELECT key FROM alarm_state WHERE device=?1")?;
    let keys = q
        .query_map([&d.id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(q);
    for key in keys.into_iter().filter(|key| log_coverage(key)) {
        let uri = key.strip_prefix("coverage:").unwrap();
        if !snapshot.observations.iter().any(|o| o.key == key)
            && snapshot.capabilities.iter().any(|c| {
                c.outcome == "available"
                    && c.uri.split(['?', '#']).next() == uri.split(['?', '#']).next()
            })
            && !snapshot.capabilities.iter().any(|c| {
                c.outcome != "available"
                    && c.uri.split(['?', '#']).next() == uri.split(['?', '#']).next()
            })
        {
            retire(conn, &d.id, &key, "query_superseded")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{model::*, store::Store, vault::Vault};

    const FAULT: &str = "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/FaultList/Entries";
    const SEL: &str = "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries";
    const OTHER: &str = "/redfish/v1/Systems/1/Storage";

    fn device() -> Device {
        serde_json::from_value(serde_json::json!({"id":"test","name":"Synthetic",
            "endpoint":"https://bmc.example.invalid/","username":"monitor",
            "interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true}))
        .unwrap()
    }
    fn observation(key: &str, health: Health) -> Observation {
        Observation {
            key: key.into(),
            label: key.into(),
            health,
            reading: None,
            unit: None,
        }
    }
    fn snapshot(other: bool) -> Snapshot {
        let mut s = Snapshot::default();
        for (uri, outcome) in [(FAULT, "http_error"), (SEL, "log_selection_unsupported")]
            .into_iter()
            .chain(other.then_some((OTHER, "forbidden_permission_or_license")))
        {
            s.capabilities.push(Capability {
                uri: uri.into(),
                outcome: outcome.into(),
                http_status: (uri == FAULT).then_some(501),
                attempts: 1,
                optional: false,
            });
            s.observations
                .push(observation(&format!("coverage:{uri}"), Health::Warning));
        }
        let mut collector = observation("collector", Health::Warning);
        collector.label = "Management-Abfrage unvollständig".into();
        s.observations.push(collector);
        s.observations.push(observation("fan", Health::Ok));
        s
    }
    fn setup() -> (tempfile::TempDir, Store, Device) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device();
        store.put(&d, b"synthetic-envelope").unwrap();
        (dir, store, d)
    }
    fn queue_events(store: &Store) {
        store
            .0
            .execute(
                "INSERT OR IGNORE INTO outbox(event_id,transport) SELECT id,'smtp' FROM events",
                [],
            )
            .unwrap();
        store.0.execute("INSERT OR IGNORE INTO desktop_jobs(event_id,recipient,revision) SELECT id,'synthetic',1 FROM events", []).unwrap();
    }
    fn count(store: &Store, sql: &str) -> i64 {
        store.0.query_row(sql, [], |r| r.get(0)).unwrap()
    }
    fn disable(store: &mut Store, d: &mut Device) {
        d.hardware_log = HardwareLogRead::Disabled;
        store.put(d, b"synthetic-envelope").unwrap();
    }

    #[test]
    fn disabling_retires_only_log_diagnostics_without_poll_or_recovery() {
        let (_dir, mut store, mut d) = setup();
        let mut s = snapshot(false);
        s.observations
            .push(observation("snmp:fan", Health::Critical));
        store.apply(&d, &s, 100).unwrap();
        store.0.execute("UPDATE alarm_control SET acknowledged=1,actor='operator',acknowledged_at=100,reason='Known fault' WHERE key='snmp:fan'", []).unwrap();
        store
            .0
            .execute("INSERT INTO hardware_logs VALUES('test','old','{}')", [])
            .unwrap();
        queue_events(&store);
        // Completed delivery and its original explanation must survive.
        store.0.execute("UPDATE outbox SET delivered=101 WHERE event_id=(SELECT MIN(id) FROM events WHERE key LIKE 'coverage:%')", []).unwrap();
        let events_before = count(&store, "SELECT COUNT(*) FROM events");
        disable(&mut store, &mut d);
        let view = store.dashboard().unwrap();
        let alarms = view["devices"][0]["alarms"].as_array().unwrap();
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0]["key"], "snmp:fan");
        assert_eq!(alarms[0]["assessment"]["status"], "acknowledged");
        assert!(view["devices"][0]["snapshot"]["capabilities"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(view["devices"][0]["last_poll"], 100);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM events"), events_before);
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM events WHERE kind='recovery'"),
            0
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM hardware_logs"), 1);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM alarm_control WHERE key LIKE 'coverage:%' OR key='collector'"
            ),
            0
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM outbox o JOIN events e ON e.id=o.event_id WHERE e.key!='snmp:fan' AND o.cancelled=0 AND o.delivered IS NULL"), 0);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM desktop_jobs j JOIN events e ON e.id=j.event_id WHERE e.key!='snmp:fan' AND j.cancelled=0"), 0);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM outbox WHERE delivered=101 AND cancelled=0"
            ),
            1
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM outbox o JOIN events e ON e.id=o.event_id WHERE e.key='snmp:fan' AND o.cancelled=0"), 1);
    }

    #[test]
    fn disabled_logs_allow_healthy_assessment_without_claiming_new_measurement() {
        let (_dir, mut store, mut d) = setup();
        store.apply(&d, &snapshot(false), crate::now()).unwrap();
        disable(&mut store, &mut d);
        assert_eq!(
            store.dashboard().unwrap()["devices"][0]["overall_status"],
            "ok"
        );
    }

    #[test]
    fn exact_keys_preserve_hardware_on_same_uri_and_other_devices() {
        let (_dir, mut store, mut d) = setup();
        let mut other = d.clone();
        other.id = "other".into();
        store.put(&other, b"synthetic-envelope").unwrap();
        let mut s = snapshot(true);
        let mut hardware = observation(FAULT, Health::Critical);
        hardware.label = s.observations[0].label.clone();
        s.observations.push(hardware);
        store.apply(&d, &s, 100).unwrap();
        store.apply(&other, &s, 100).unwrap();
        disable(&mut store, &mut d);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM alarm_state WHERE device='other' AND key LIKE 'coverage:%'"
            ),
            3
        );
        let retained: String = store
            .0
            .query_row(
                "SELECT health FROM alarm_state WHERE device='test' AND key=?1",
                [FAULT],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retained, "\"critical\"");
    }

    #[test]
    fn unrelated_coverage_and_later_connection_failure_survive() {
        for other in [false, true] {
            let (_dir, mut store, mut d) = setup();
            store.apply(&d, &snapshot(other), 100).unwrap();
            if !other {
                store.poll_error(&d, 101).unwrap();
            }
            queue_events(&store);
            disable(&mut store, &mut d);
            assert_eq!(
                count(
                    &store,
                    "SELECT COUNT(*) FROM alarm_state WHERE key='collector'"
                ),
                1
            );
            assert_eq!(count(&store, "SELECT COUNT(*) FROM desktop_jobs j JOIN events e ON e.id=j.event_id WHERE e.key='collector' AND j.cancelled=0"), 1);
            let expected = if other { "warning" } else { "critical" };
            let view = store.dashboard().unwrap();
            assert!(view["devices"][0]["alarms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "collector" && a["health"] == expected));
            assert_eq!(
                count(
                    &store,
                    "SELECT COUNT(*) FROM alarm_state WHERE key LIKE 'coverage:%Storage'"
                ),
                i64::from(other)
            );
        }
    }

    #[test]
    fn old_poll_is_rejected_and_reactivation_can_report_fresh_failures() {
        let (_dir, mut store, mut d) = setup();
        let old = d.clone();
        let s = snapshot(false);
        store.apply_revision(&d, &s, 100, Some(1)).unwrap();
        disable(&mut store, &mut d);
        assert!(!store.apply_revision(&old, &s, 101, Some(1)).unwrap());
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM alarm_state WHERE health!='\"ok\"'"
            ),
            0
        );
        d.hardware_log = HardwareLogRead::All;
        store.put(&d, b"synthetic-envelope").unwrap();
        assert!(store.apply_revision(&d, &s, 102, Some(3)).unwrap());
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM alarm_state WHERE key LIKE 'coverage:%'"
            ),
            2
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM events WHERE kind='recovery'"),
            0
        );
    }

    #[test]
    fn startup_and_both_restore_paths_reconcile_already_disabled_devices() {
        let (dir, mut store, mut d) = setup();
        let vault = Vault::open(&dir.path().join("master.key")).unwrap();
        store
            .put(&d, &vault.seal(&d.id, b"synthetic-password").unwrap())
            .unwrap();
        store.apply(&d, &snapshot(false), 100).unwrap();
        d.hardware_log = HardwareLogRead::Disabled;
        // Simulate an older build's persisted disabled configuration.
        store
            .0
            .execute(
                "UPDATE devices SET config=?1",
                [serde_json::to_string(&d).unwrap()],
            )
            .unwrap();
        let archive = store.make_archive(&vault).unwrap();
        for staged in [false, true] {
            let target = tempfile::tempdir().unwrap();
            let mut restored = Store::open(target.path()).unwrap();
            let target_vault = Vault::open(&target.path().join("master.key")).unwrap();
            if staged {
                restored
                    .restore_staged(&store.0, &vault, "admin", 0, &mut || Ok(()))
                    .unwrap();
            } else {
                restored
                    .restore_archive(&archive, &target_vault, "admin", 0)
                    .unwrap();
            }
            assert_eq!(
                count(
                    &restored,
                    "SELECT COUNT(*) FROM alarm_state WHERE health!='\"ok\"'"
                ),
                0
            );
            assert_eq!(count(&restored, "SELECT COUNT(*) FROM events"), 3);
        }
        drop(store);
        let reopened = Store::open(dir.path()).unwrap();
        assert_eq!(
            count(
                &reopened,
                "SELECT COUNT(*) FROM alarm_state WHERE health!='\"ok\"'"
            ),
            0
        );
        let raw = reopened.dashboard().unwrap();
        drop(reopened);
        assert_eq!(
            Store::open(dir.path()).unwrap().dashboard().unwrap()["devices"],
            raw["devices"]
        );
    }

    #[test]
    fn fresh_all_query_retires_only_superseded_selection_key() {
        let (_dir, mut store, mut d) = setup();
        d.hardware_log = HardwareLogRead::Latest { limit: 2 };
        store.put(&d, b"synthetic-envelope").unwrap();
        let mut old = snapshot(false);
        old.capabilities[1].uri = format!("{SEL}?$orderby=Created+desc&$top=2");
        old.observations[1].key = format!("coverage:{}", old.capabilities[1].uri);
        store.apply(&d, &old, 100).unwrap();
        d.hardware_log = HardwareLogRead::All;
        store.put(&d, b"synthetic-envelope").unwrap();
        // Changing mode without a successful query must retain both warnings.
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM alarm_state WHERE key LIKE 'coverage:%'"
            ),
            2
        );
        let mut current = Snapshot::default();
        current.capabilities.push(Capability {
            uri: SEL.into(),
            outcome: "available".into(),
            http_status: Some(200),
            attempts: 1,
            optional: false,
        });
        let mut failed_selection = current.capabilities[0].clone();
        failed_selection.uri = format!("{SEL}?$orderby=Created+desc&$top=3");
        failed_selection.outcome = "log_selection_unsupported".into();
        current.capabilities.push(failed_selection);
        store.apply(&d, &current, 101).unwrap();
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM alarm_state WHERE key LIKE 'coverage:%'"
            ),
            2
        );
        current.capabilities.pop();
        store.apply(&d, &current, 102).unwrap();
        let key: String = store
            .0
            .query_row(
                "SELECT key FROM alarm_state WHERE key LIKE 'coverage:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(key, format!("coverage:{FAULT}"));
    }
}

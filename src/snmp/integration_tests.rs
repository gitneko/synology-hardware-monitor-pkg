//! Synthetic trust-boundary/reducer tests. No claim of wire authentication here;
//! the separate Net-SNMP test supplies independently authenticated input.
use super::*;
use crate::{
    snmp::{
        persistence::prepare_secrets,
        secrets::{Credentials, SecretUpdate, SecretUpdates},
    },
    vault::Vault,
};
use serde_json::json;
const FAN: &str = "/redfish/v1/Chassis/1/Thermal#/Fans/Fan1";
const PSU: &str = "/redfish/v1/Chassis/1/Power#/PowerSupplies/1";
const ENGINE: &str = "800000000102030405";
fn setup() -> (tempfile::TempDir, Store, Device, Vault, i64) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(&dir.path().join("master.key")).unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let d:Device=serde_json::from_value(json!({"id":"p4","name":"Synthetic P4","endpoint":"https://example.invalid/","username":"reader","interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true,"snmp_traps":{"enabled":true,"profile":"dell_idrac","allowed_sources":["127.0.0.1"],"engine_ids":[ENGINE],"security":{"version":"v3","username":"synthetic"}}})).unwrap();
    let updates = SecretUpdates {
        snmp_traps: SecretUpdate::Replace {
            credentials: Credentials::Usm {
                auth_password: "synthetic-auth-pass".into(),
                priv_password: "synthetic-priv-pass".into(),
            },
        },
        ..Default::default()
    };
    let prepared = prepare_secrets(&store, &vault, &d, &updates).unwrap();
    store
        .save_admin_with_snmp(
            &d,
            &vault.seal(&d.id, b"synthetic-rf").unwrap(),
            None,
            "synthetic",
            Some(&prepared),
        )
        .unwrap();
    let settings = crate::notification::Settings {
        desktop_enabled: true,
        desktop_recipient: Some("synthetic-admin".into()),
        ..Default::default()
    };
    store
        .save_notifications(
            &crate::notification::Input {
                language: Default::default(),
                revision: 0,
                desktop_enabled: true,
                selection: settings.selection,
            },
            "synthetic",
        )
        .unwrap();
    let now = crate::now();
    (dir, store, d, vault, now)
}
fn snap(fan: Health, psu: Health) -> Snapshot {
    let mut s = Snapshot {
        logs_complete: true,
        observations: vec![
            Observation {
                key: FAN.into(),
                label: "Fan 1".into(),
                health: fan,
                reading: Some(1234.),
                unit: Some("rpm".into()),
            },
            Observation {
                key: PSU.into(),
                label: "PSU 1".into(),
                health: psu,
                reading: None,
                unit: None,
            },
        ],
        ..Default::default()
    };
    for (key, kind, alias) in [
        (FAN, "Fan", "Fan.Embedded.1"),
        (PSU, "PowerSupply", "PSU.Slot.1"),
    ] {
        s.resources.insert(
            key.into(),
            crate::correlation::Resource {
                kind: kind.into(),
                ..Default::default()
            },
        );
        s.component_identities.push(crate::identity::Component {
            key: key.into(),
            locator: key.into(),
            aliases: vec![alias.into()],
        });
    }
    s
}
fn poll(store: &mut Store, d: &Device, s: &Snapshot, now: i64, start: i64) {
    let epoch = store.receiver_epoch().unwrap();
    assert!(store
        .apply_poll(d, s, now, Some(1), Some(epoch), Some(start))
        .unwrap());
}
fn receipt(condition: &str, class: Class, health: Health) -> Receipt {
    Receipt {
        event: Some(super::super::traps::Event {
            class,
            health,
            component_kind: "fan".into(),
            identity: Some(Identity::Fqdd {
                value: "Fan.Embedded.1".into(),
            }),
            condition: condition.into(),
            message: "Synthetic trap".into(),
            occurrence: None,
        }),
        fingerprint: format!("synthetic-{condition}"),
        trap_oid: "1.3.6.1.4.1.674.10892.5.3.2.1.0.2153".into(),
        source: "127.0.0.1".parse().unwrap(),
        verified: true,
        component_key: None,
        restored: false,
        version: Some("v3".into()),
        engine_id: Some(ENGINE.into()),
        engine_boots: Some(1),
        uptime: Some(123),
        handling: None,
    }
}
fn ingest(s: &mut Store, d: &Device, r: &Receipt, now: i64) {
    let epoch = s.receiver_epoch().unwrap();
    assert!(s.ingest_snmp_receipt(&d.id, 1, epoch, r, now).unwrap().0);
}
fn health(s: &Store, d: &Device, key: &str) -> Health {
    current_health(&s.0, &d.id, key).unwrap()
}
fn count(s: &Store, kind: &str) -> i64 {
    s.0.query_row("SELECT COUNT(*) FROM events WHERE kind=?1", [kind], |r| {
        r.get(0)
    })
    .unwrap()
}
fn queued(s: &Store) -> i64 {
    s.0.query_row("SELECT COUNT(*) FROM outbox WHERE cancelled=0", [], |r| {
        r.get(0)
    })
    .unwrap()
}

#[test]
fn mapped_partial_trap_preserves_snapshot_unrelated_faults_and_log_baseline() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Warning), now, 0);
    let before: (String, i64, bool) =
        s.0.query_row(
            "SELECT snapshot,last_poll,logs_initialized FROM devices",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    assert_eq!(health(&s, &d, FAN), Health::Critical);
    assert_eq!(health(&s, &d, PSU), Health::Warning);
    let after =
        s.0.query_row(
            "SELECT snapshot,last_poll,logs_initialized FROM devices",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, bool>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(before, after);
    let e = alarm_evidence(&s.0, &d.id, FAN).unwrap().unwrap();
    assert!(e.provisional && e.active);
    assert_eq!(count(&s, "alarm"), 2);
    let receipt = s.snmp_receipts(None, 20).unwrap().pop().unwrap();
    assert_eq!(receipt.receipt.component_key.as_deref(), Some(FAN));
    let before = count(&s, "alarm");
    let started = s.trap_sequence(&d.id).unwrap();
    poll(
        &mut s,
        &d,
        &snap(Health::Critical, Health::Warning),
        now + 2,
        started,
    );
    assert_eq!(count(&s, "alarm"), before);
    assert!(
        !alarm_evidence(&s.0, &d.id, FAN)
            .unwrap()
            .unwrap()
            .provisional
    );
}
#[test]
fn newer_trap_blocks_old_ok_but_saves_unrelated_recovery_and_later_ok_clears_once() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Warning), now, 0);
    let started = s.trap_sequence(&d.id).unwrap();
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now + 2, started);
    assert_eq!(health(&s, &d, FAN), Health::Critical);
    assert_eq!(health(&s, &d, PSU), Health::Ok);
    assert_eq!(
        alarm_evidence(&s.0, &d.id, FAN)
            .unwrap()
            .unwrap()
            .confirmation,
        "newer_trap"
    );
    ingest(
        &mut s,
        &d,
        &receipt("dell:normal", Class::Recovery, Health::Unknown),
        now + 3,
    );
    assert_eq!(health(&s, &d, FAN), Health::Critical);
    let started = s.trap_sequence(&d.id).unwrap();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now + 4, started);
    assert_eq!(health(&s, &d, FAN), Health::Ok);
    assert!(s
        .recovered_since_receipt(
            &d.id,
            1,
            &receipt("dell:FAN0001", Class::Fault, Health::Critical).fingerprint
        )
        .unwrap());
    assert_eq!(count(&s, "recovery"), 2);
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now + 5, started);
    assert_eq!(count(&s, "recovery"), 2);
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 6,
    );
    assert_eq!(count(&s, "alarm"), 3);
}
#[test]
fn confirming_poll_first_then_trap_does_not_duplicate_alarm_submission() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Critical, Health::Ok), now, 0);
    assert_eq!(count(&s, "alarm"), 1);
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    assert_eq!(count(&s, "alarm"), 1);
    assert_eq!(queued(&s), 1);
}
#[test]
fn missing_unknown_partial_replaced_and_stale_aliases_cannot_clear_or_guess() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    for mode in 0..4 {
        let mut snapshot = snap(Health::Ok, Health::Ok);
        match mode {
            0 => {
                snapshot.observations.retain(|o| o.key != FAN);
            }
            1 => snapshot.observations[0].health = Health::Unknown,
            2 => snapshot.capabilities.push(Capability {
                optional: false,
                uri: "synthetic".into(),
                outcome: "timeout".into(),
                http_status: None,
                attempts: 1,
            }),
            _ => snapshot.component_identities[0].aliases = vec!["Fan.Replacement".into()],
        };
        let started = s.trap_sequence(&d.id).unwrap();
        poll(&mut s, &d, &snapshot, now + 2 + mode, started);
        assert_eq!(health(&s, &d, FAN), Health::Critical);
    }
    let r = receipt("dell:FAN0002", Class::Fault, Health::Critical);
    ingest(&mut s, &d, &r, now + 1000);
    assert_eq!(
        s.snmp_receipts(None, 1).unwrap()[0]
            .receipt
            .handling
            .as_deref(),
        Some("event_only_pending")
    );
}
#[test]
fn ambiguous_alias_and_redfish_index_are_event_only_with_explicit_default_off_selection() {
    for mode in 0..3 {
        let (_dir, mut s, d, _v, now) = setup();
        let mut snapshot = snap(Health::Ok, Health::Ok);
        let mut r = receipt("dell:FAN0001", Class::Fault, Health::Critical);
        if mode == 0 {
            snapshot.resources.get_mut(PSU).unwrap().kind = "Fan".into();
            snapshot.component_identities[1].aliases = vec!["Fan.Embedded.1".into()];
        }
        if mode == 1 {
            r.event.as_mut().unwrap().identity = Some(Identity::Index {
                locator: "1.3.6.1.4.1.232.6.2.6.7.1.1.1".into(),
            });
        }
        if mode == 2 {
            r.event.as_mut().unwrap().identity = None;
        }
        poll(&mut s, &d, &snapshot, now, 0);
        ingest(&mut s, &d, &r, now + 1);
        assert_eq!(health(&s, &d, FAN), Health::Ok);
        assert_eq!(queued(&s), 0);
        assert_eq!(count(&s, "snmp_trap"), 1);
        let mut policy = s.notification_settings().unwrap().0;
        policy.selection.snmp_trap = true;
        s.save_notifications(
            &crate::notification::Input {
                language: Default::default(),
                revision: 1,
                desktop_enabled: true,
                selection: policy.selection,
            },
            "synthetic",
        )
        .unwrap();
        ingest(&mut s, &d, &r, now + 2);
        assert_eq!(queued(&s), 1);
    }
}
#[test]
fn unverified_unknown_test_and_recovery_never_generate_fault_deliveries() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
    let mut policy = s.notification_settings().unwrap().0;
    policy.selection.snmp_trap = true;
    s.save_notifications(
        &crate::notification::Input {
            language: Default::default(),
            revision: 1,
            desktop_enabled: true,
            selection: policy.selection,
        },
        "synthetic",
    )
    .unwrap();
    for (i, class) in [
        Class::Unknown,
        Class::Test,
        Class::Recovery,
        Class::UnsupportedPet,
        Class::Fault,
    ]
    .into_iter()
    .enumerate()
    {
        let mut r = receipt("synthetic", class, Health::Critical);
        if i == 4 {
            r.verified = false;
            r.version = Some("v1".into());
        }
        ingest(&mut s, &d, &r, now + i as i64 + 1);
    }
    assert_eq!(health(&s, &d, FAN), Health::Ok);
    assert_eq!(queued(&s), 0);
    assert_eq!(count(&s, "alarm"), 0);
}
#[test]
fn acknowledgement_survives_same_condition_and_ends_for_new_or_worse_condition() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    let token = s.dashboard().unwrap()["devices"][0]["alarm_statuses"][FAN]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    s.acknowledge_alarm(
        &d.id,
        1,
        FAN,
        &token,
        true,
        "synthetic maintenance",
        "admin",
        now + 2,
    )
    .unwrap();
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 3,
    );
    assert_eq!(
        s.dashboard().unwrap()["devices"][0]["alarm_statuses"][FAN]["status"],
        "acknowledged"
    );
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0002", Class::Fault, Health::Critical),
        now + 4,
    );
    assert_eq!(
        s.dashboard().unwrap()["devices"][0]["alarm_statuses"][FAN]["status"],
        "critical"
    );
    assert_eq!(count(&s, "alarm"), 2);
    assert_eq!(
        alarm_evidence(&s.0, &d.id, FAN)
            .unwrap()
            .unwrap()
            .conditions
            .len(),
        2
    );
}
#[test]
fn stale_measurements_do_not_hide_known_verified_trap_fault_or_become_fresh() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now - 400, 0);
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now,
    );
    let dashboard = s.dashboard().unwrap();
    let dev = &dashboard["devices"][0];
    assert_eq!(dev["stale"], true);
    assert_eq!(dev["overall_status"], "critical");
    assert_eq!(dev["last_poll"], now - 400);
    assert_eq!(dev["last_trap_received"], now);
}
#[test]
fn csv_trap_category_includes_provenance_and_neutralizes_vendor_formula() {
    let (_dir, mut s, d, _v, now) = setup();
    let mut r = receipt("synthetic", Class::Unknown, Health::Unknown);
    r.event.as_mut().unwrap().message = "=malicious;\"text\"".into();
    ingest(&mut s, &d, &r, now);
    let (csv, row_count) = s
        .events_csv(&crate::history::Filter {
            category: "trap".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(row_count, 1);
    assert!(
        csv.contains("snmp_trap") && csv.contains("Verifiziert") && csv.contains("Empfangsbeleg")
    );
    assert_eq!(count(&s, "alarm"), 0);
}

#[test]
fn duplicate_cache_preserves_known_fault_recovery_fault_with_identical_payload() {
    let mut cache = super::super::traps::Duplicates::default();
    let r = receipt("dell:FAN0001", Class::Fault, Health::Critical);
    assert!(!cache.contains("device", &r));
    cache.insert("device", &r);
    assert!(cache.contains("device", &r));
    let mut recovery = r.clone();
    recovery.fingerprint = "recovery".into();
    recovery.event.as_mut().unwrap().class = Class::Recovery;
    assert!(!cache.contains("device", &recovery));
    cache.insert("device", &recovery);
    assert!(!cache.contains("device", &r));
    cache.insert("device", &r);
    assert!(cache.contains("device", &r));
}
#[test]
fn proven_occurrence_correlates_both_arrival_orders_but_message_type_does_not() {
    for log_first in [false, true] {
        for proven in [false, true] {
            let (_dir, mut s, d, _v, now) = setup();
            poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
            let occurrence = Occurrence {
                vendor: "synthetic-proven-id-contract".into(),
                record_id: "record-7".into(),
                component: FAN.into(),
                generation: "boot-3".into(),
            };
            let mut r = receipt("dell:FAN0001", Class::Fault, Health::Critical);
            if proven {
                r.event.as_mut().unwrap().occurrence = Some(occurrence.clone());
            }
            let mut logged = snap(
                if log_first {
                    Health::Ok
                } else {
                    Health::Critical
                },
                Health::Ok,
            );
            logged.logs = vec![HardwareLog {
                identity: Some(LogIdentity {
                    record_id: Some("record-7".into()),
                    message_id: Some("FAN0001".into()),
                    component: Some(FAN.into()),
                    occurrence: proven.then_some(occurrence),
                }),
                fingerprint: "synthetic-log".into(),
                message: "Synthetic physical event".into(),
                severity: Health::Critical,
                created: None,
            }];
            if log_first {
                poll(&mut s, &d, &logged, now + 1, 0);
                ingest(&mut s, &d, &r, now + 2);
            } else {
                ingest(&mut s, &d, &r, now + 1);
                let start = s.trap_sequence(&d.id).unwrap();
                poll(&mut s, &d, &logged, now + 2, start);
            }
            assert_eq!(count(&s, "hardware_log"), 1);
            assert_eq!(count(&s, "alarm"), 1);
            assert_eq!(queued(&s), if proven { 1 } else { 2 });
            let reason: i64 =
                s.0.query_row(
                    "SELECT COUNT(*) FROM events WHERE mail_reason='same_occurrence'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(reason, if proven { 1 } else { 0 });
            let jobs: i64 =
                s.0.query_row(
                    "SELECT COUNT(*) FROM desktop_jobs WHERE cancelled=0",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(jobs, if proven { 1 } else { 2 });
        }
    }
}
#[test]
fn snmp_index_mapping_requires_same_authenticated_engine_generation() {
    for matching in [false, true] {
        let (_dir, mut s, mut d, _v, now) = setup();
        d.primary_protocol = PrimaryProtocol::Snmp;
        // Fixture setup models the stored primary configuration without changing
        // revisions; no network or authentication assertion is made by this test.
        s.0.execute(
            "UPDATE devices SET config=?1",
            [serde_json::to_string(&d).unwrap()],
        )
        .unwrap();
        let mut snapshot = snap(Health::Ok, Health::Ok);
        snapshot.snmp = Some(crate::snmp::polling::Metadata {
            system_information: Default::default(),
            network: None,
            hpe: None,
            version: "v3".into(),
            profile: crate::snmp::config::Profile::HpeIlo5,
            target: "127.0.0.1:161".parse().unwrap(),
            sys_object_id: "1.3.6.1.4.1.232".into(),
            sys_name: None,
            sys_descr: None,
            uptime_ticks: 123,
            generation: 9,
            agent_restart: false,
            engine_id: Some(ENGINE.into()),
            engine_boots: Some(1),
            complete: true,
            statistics: Default::default(),
            identities: vec![crate::identity::Component {
                key: FAN.into(),
                locator: "1.3.6.1.4.1.232.6.2.6.7.1.1.2".into(),
                aliases: vec![],
            }],
        });
        poll(&mut s, &d, &snapshot, now, 0);
        let mut r = receipt("hpe:fan", Class::Fault, Health::Critical);
        r.event.as_mut().unwrap().identity = Some(Identity::Index {
            locator: "1.3.6.1.4.1.232.6.2.6.7.1.1.2".into(),
        });
        if !matching {
            r.engine_boots = Some(2);
        }
        ingest(&mut s, &d, &r, now + 1);
        assert_eq!(
            health(&s, &d, FAN),
            if matching {
                Health::Critical
            } else {
                Health::Ok
            }
        );
    }
}
#[test]
fn clock_survives_receipt_and_history_pruning_and_restart() {
    let (dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    let sequence = s.trap_sequence(&d.id).unwrap();
    s.clear_events("synthetic").unwrap();
    s.prune_snmp_receipts(now + 9 * 86400).unwrap();
    assert_eq!(s.trap_sequence(&d.id).unwrap(), sequence);
    drop(s);
    let mut s = Store::open(dir.path()).unwrap();
    assert_eq!(s.trap_sequence(&d.id).unwrap(), sequence);
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now + 3, 0);
    assert_eq!(health(&s, &d, FAN), Health::Critical);
}
#[test]
fn event_history_capacity_keeps_pending_jobs_and_records_visible_limit() {
    let (_dir, mut s, d, _v, now) = setup();
    {
        let tx = s.0.transaction().unwrap();
        for id in 1..=10000 {
            tx.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(?1,?2,'synthetic','snmp_trap','\"critical\"','Synthetic',?3)",params![id,d.id,now]).unwrap();
            tx.execute("INSERT INTO outbox(event_id) VALUES(?1)", [id])
                .unwrap();
        }
        tx.commit().unwrap();
    }
    ingest(
        &mut s,
        &d,
        &receipt("synthetic", Class::Unknown, Health::Unknown),
        now + 1,
    );
    assert_eq!(count(&s, "snmp_trap"), 10000);
    assert_eq!(queued(&s), 10000);
    assert_eq!(
        s.snmp_receipts(None, 1).unwrap()[0]
            .receipt
            .handling
            .as_deref(),
        Some("event_history_full")
    );
    s.0.execute("UPDATE outbox SET delivered=?1", [now + 2])
        .unwrap();
    ingest(
        &mut s,
        &d,
        &receipt("synthetic", Class::Unknown, Health::Unknown),
        now + 3,
    );
    assert_eq!(count(&s, "snmp_trap"), 10000);
}
#[test]
fn explicit_inventory_fields_are_required_and_names_member_ids_never_become_aliases() {
    let mut inventory = crate::identity::TrapIdentities::default();
    inventory.observe(FAN,&json!({"Name":"Fan.Embedded.1","MemberId":"Fan.Embedded.1","@odata.type":"#Fan.v1_0_0.Fan"}));
    assert!(inventory.finish(&BTreeMap::new()).is_empty());
    let mut inventory = crate::identity::TrapIdentities::default();
    inventory.observe(
        FAN,
        &json!({"Oem":{"Dell":{"Explicit":{"FQDD":"Fan.Embedded.1"}}}}),
    );
    let result = inventory.finish(&BTreeMap::new());
    assert_eq!(result[0].aliases, vec!["Fan.Embedded.1"]);
}

#[test]
fn new_fault_condition_capacity_is_bounded_without_discarding_known_faults() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
    for i in 0..30 {
        ingest(
            &mut s,
            &d,
            &receipt(&format!("dell:FAN{i:04}"), Class::Fault, Health::Critical),
            now + i + 1,
        );
    }
    let e = alarm_evidence(&s.0, &d.id, FAN).unwrap().unwrap();
    assert!(e.conditions.len() <= 16);
    assert!(e.conditions.contains_key("additional_conditions"));
    assert!(serde_json::to_vec(&e).unwrap().len() <= 4096);
    assert_eq!(health(&s, &d, FAN), Health::Critical);
}
#[test]
fn older_ok_cannot_clear_dependent_summary_while_unrelated_data_commits() {
    let (_dir, mut s, d, _v, now) = setup();
    let mut before = snap(Health::Ok, Health::Warning);
    let parent = "/redfish/v1/Chassis/1";
    before.resources.insert(
        parent.into(),
        crate::correlation::Resource {
            kind: "#Chassis.v1_0_0.Chassis".into(),
            children: [FAN.into()].into_iter().collect(),
            rollup: Some(Health::Warning),
            ..Default::default()
        },
    );
    before.observations.push(Observation {
        key: parent.into(),
        label: "Chassis".into(),
        health: Health::Warning,
        reading: None,
        unit: None,
    });
    poll(&mut s, &d, &before, now, 0);
    let started = s.trap_sequence(&d.id).unwrap();
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    let mut older = before;
    older
        .observations
        .iter_mut()
        .for_each(|o| o.health = Health::Ok);
    poll(&mut s, &d, &older, now + 2, started);
    assert_eq!(health(&s, &d, parent), Health::Warning);
    assert_eq!(health(&s, &d, PSU), Health::Ok);
}
#[test]
fn normalization_limits_roundtrip_in_logical_backup_and_restore_stays_inactive() {
    let (_dir, mut s, d, v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now + 1,
    );
    let oid = std::iter::once("2".to_owned())
        .chain((0..127).map(|_| u32::MAX.to_string()))
        .collect::<Vec<_>>()
        .join(".");
    let mut r = receipt("unknown", Class::Unknown, Health::Unknown);
    r.trap_oid = oid.clone();
    r.event = Some(super::super::traps::normalize(
        crate::snmp::config::Profile::Generic,
        &oid.parse().unwrap(),
        &[],
    ));
    ingest(&mut s, &d, &r, now + 2);
    let archive = s.make_archive(&v).unwrap();
    let dest = tempfile::tempdir().unwrap();
    let vault = Vault::open(&dest.path().join("master.key")).unwrap();
    let mut restored = Store::open(dest.path()).unwrap();
    restored
        .restore_archive(&archive, &vault, "synthetic", 0)
        .unwrap();
    let e = alarm_evidence(&restored.0, &d.id, FAN).unwrap().unwrap();
    assert!(!e.active && !e.provisional);
    assert_eq!(e.confirmation, "restored");
    assert_eq!(restored.trap_sequence(&d.id).unwrap(), 0);
    assert_eq!(restored.snmp_receipts(None, 20).unwrap().len(), 2);
}

#[test]
fn delayed_consumer_uses_current_inventory_age_without_rewriting_receive_time() {
    let (_dir, mut s, d, _v, now) = setup();
    poll(&mut s, &d, &snap(Health::Ok, Health::Ok), now, 0);
    // The datagram was received before a poll committed but waits behind the
    // submission gate. Its original receive timestamp is not the processing clock.
    ingest(
        &mut s,
        &d,
        &receipt("dell:FAN0001", Class::Fault, Health::Critical),
        now - 1,
    );
    assert_eq!(health(&s, &d, FAN), Health::Critical);
    assert_eq!(
        alarm_evidence(&s.0, &d.id, FAN).unwrap().unwrap().received,
        now - 1
    );
}

#[test]
fn operator_reset_ends_old_provisional_evidence_but_fresh_faults_rearm() {
    for fresh_trap in [false, true] {
        let (_dir, mut s, d, _v, now) = setup();
        poll(&mut s, &d, &snap(Health::Ok, Health::Warning), now, 0);
        ingest(
            &mut s,
            &d,
            &receipt("before-reset", Class::Fault, Health::Critical),
            now + 1,
        );
        let old_token = s.dashboard().unwrap()["devices"][0]["alarm_statuses"][FAN]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let before_receipts: i64 =
            s.0.query_row("SELECT COUNT(*) FROM snmp_receipts", [], |r| r.get(0))
                .unwrap();
        let before_events = count(&s, "alarm");
        let recovery = count(&s, "recovery");
        s.reset_alarm(&d.id, 1, FAN, &old_token, "reset-admin", now + 2)
            .unwrap();
        assert!(s.dashboard().unwrap()["devices"][0]["alarm_statuses"]
            .get(FAN)
            .is_none());
        assert_eq!(
            s.0.query_row("SELECT COUNT(*) FROM snmp_receipts", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            before_receipts
        );
        assert_eq!(count(&s, "alarm"), before_events);
        assert_eq!(count(&s, "recovery"), recovery);
        assert_eq!(health(&s, &d, PSU), Health::Warning);
        let start = s.trap_sequence(&d.id).unwrap();
        poll(
            &mut s,
            &d,
            &snap(Health::Unknown, Health::Warning),
            now + 3,
            start,
        );
        assert!(s.dashboard().unwrap()["devices"][0]["alarm_statuses"]
            .get(FAN)
            .is_none());
        assert_eq!(count(&s, "alarm"), before_events);
        if fresh_trap {
            ingest(
                &mut s,
                &d,
                &receipt("after-reset", Class::Fault, Health::Critical),
                now + 4,
            );
        } else {
            let start = s.trap_sequence(&d.id).unwrap();
            poll(
                &mut s,
                &d,
                &snap(Health::Critical, Health::Warning),
                now + 4,
                start,
            );
        }
        assert_eq!(health(&s, &d, FAN), Health::Critical);
        assert_ne!(
            s.dashboard().unwrap()["devices"][0]["alarm_statuses"][FAN]["token"],
            old_token
        );
        assert_eq!(count(&s, "alarm"), before_events + 1);
        assert_eq!(count(&s, "recovery"), recovery);
    }
}

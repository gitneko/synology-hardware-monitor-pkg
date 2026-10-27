//! SNMP configuration contract tests use temporary state only; no NAS or network access.
use hardware_monitor::{
    archive,
    model::{Device, Health, Observation, PrimaryProtocol, Snapshot},
    snmp::{config::*, engine::LocalEngine, persistence::*, secrets::*},
    store::Store,
    vault::Vault,
};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

fn redfish() -> Device {
    serde_json::from_value(json!({"id":"p1-test","name":"Synthetic P1","endpoint":"https://bmc.example/","username":"reader","interval_seconds":60,"repeat_seconds":300,"alerts_enabled":true,"ca_file":null})).unwrap()
}
fn snmp() -> Device {
    serde_json::from_value(json!({"id":"p1-test","name":"Synthetic SNMP","primary_protocol":"snmp","snmp_poll":{"host":"::1","security":{"version":"v1"}},"interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true,"ca_file":null})).unwrap()
}
fn updates(marker: &str) -> SecretUpdates {
    SecretUpdates {
        snmp_poll: SecretUpdate::Replace {
            credentials: Credentials::Community {
                community: marker.into(),
            },
        },
        ..Default::default()
    }
}
fn fault() -> Snapshot {
    Snapshot {
        observations: vec![Observation {
            key: "fan".into(),
            label: "Synthetic fan".into(),
            health: Health::Critical,
            reading: None,
            unit: None,
        }],
        ..Default::default()
    }
}
fn count(store: &Store, table: &str) -> i64 {
    store
        .0
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn converted(archive: archive::Archive, format: u32) -> archive::Archive {
    let mut value = serde_json::to_value(archive).unwrap();
    value["format"] = json!(format);
    let tables = value["tables"].as_object_mut().unwrap();
    tables.remove("history_settings");
    for (table, _) in TABLES {
        tables.remove(*table);
    }
    if format <= 3 {
        tables.remove("mail_replay");
    }
    if format <= 2 {
        tables.remove("alarm_control");
    }
    if format == 1 {
        for row in tables["events"].as_array().unwrap() {
            assert_eq!(row.as_array().unwrap().len(), 14);
        }
        for row in tables.get_mut("events").unwrap().as_array_mut().unwrap() {
            row.as_array_mut().unwrap().pop();
        }
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn legacy_defaults_and_protocol_limits_are_explicit() {
    let legacy = redfish();
    legacy.validate().unwrap();
    assert_eq!(legacy.primary_protocol, PrimaryProtocol::Redfish);
    assert!(legacy.snmp_poll.is_none() && legacy.snmp_traps.is_none());
    let mut d = snmp();
    d.validate().unwrap();
    assert_eq!(d.poll_timeout_seconds(), 60);
    d.snmp_poll.as_mut().unwrap().port = 0;
    assert!(d.validate().is_err());
    d.snmp_poll.as_mut().unwrap().port = 161;
    d.snmp_poll.as_mut().unwrap().host = "udp://127.0.0.1:161".into();
    assert!(d.validate().is_err());
    d.snmp_poll.as_mut().unwrap().host = "bmc.example..".into();
    assert!(d.validate().is_err());
    d.snmp_poll.as_mut().unwrap().host = "bmc.example".into();
    d.snmp_poll.as_mut().unwrap().security = Security::V3 {
        username: "ü".repeat(16),
        auth: AuthProtocol::Sha256,
        privacy: PrivacyProtocol::Aes128,
    };
    d.validate().unwrap();
    if let Security::V3 { username, .. } = &mut d.snmp_poll.as_mut().unwrap().security {
        username.push('x');
    }
    assert!(d.validate().is_err());
    assert!(
        serde_json::from_value::<Security>(json!({"version":"v1","username":"ignored"})).is_err()
    );
    assert!(serde_json::from_value::<SecretUpdate>(json!({"action":"keep","credentials":{"kind":"community","community":"must-not-be-ignored"}})).is_err());
    let mut settings = ReceiverSettings {
        listen_port: 162,
        ..Default::default()
    };
    settings.validate().unwrap();
    settings.listen_port = 0;
    assert!(settings.validate().is_err());
    settings.listen_port = 1162;
    settings.listen_addresses.push("127.0.0.1".parse().unwrap());
    assert!(settings.validate().is_err());
    settings.listen_addresses = vec!["0.0.0.0".parse().unwrap(), "::".parse().unwrap()];
    settings.validate().unwrap();
}

#[test]
fn trap_clock_compatibility_is_explicit_and_v3_only() {
    let mut config: hardware_monitor::snmp::config::TrapConfig = serde_json::from_value(json!({
        "enabled":true,"allowed_sources":["127.0.0.1"],
        "security":{"version":"v3","username":"reader"},"engine_ids":["8000000001"]
    }))
    .unwrap();
    assert!(!config.timeliness_poll_only);
    config.timeliness_poll_only = true;
    config.validate().unwrap();
    config.security = hardware_monitor::snmp::config::Security::V2c {};
    config.engine_ids.clear();
    assert!(config.validate().is_err());
    config.timeliness_poll_only = false;
    config.validate().unwrap();
}

#[test]
fn purpose_aad_rotation_conflicts_and_target_state_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(&dir.path().join("master.key")).unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let mut d = snmp();
    let prepared = prepare_secrets(&store, &vault, &d, &updates(" synthetic community ")).unwrap();
    store
        .save_admin_with_snmp(&d, b"", None, "admin", Some(&prepared))
        .unwrap();
    let cipher = store
        .protocol_secret(&d.id, Purpose::SnmpPoll)
        .unwrap()
        .unwrap();
    let plain = vault
        .unseal(&Purpose::SnmpPoll.aad(&d.id), &cipher)
        .unwrap();
    let secret: Credentials = serde_json::from_slice(&plain).unwrap();
    assert!(!format!("{secret:?}").contains("synthetic"));
    assert!(String::from_utf8_lossy(&plain).contains(" synthetic community "));
    assert!(vault
        .unseal(&Purpose::SnmpTraps.aad(&d.id), &cipher)
        .is_err());
    assert!(vault
        .unseal(&Purpose::SnmpPoll.aad("other"), &cipher)
        .is_err());
    store.apply_revision(&d, &fault(), 100, Some(1)).unwrap();
    let epoch = store.receiver_epoch().unwrap();
    let rotation = prepare_secrets(&store, &vault, &d, &updates("rotated-synthetic")).unwrap();
    store
        .save_admin_with_snmp(&d, b"", Some(1), "admin", Some(&rotation))
        .unwrap();
    assert!(store.receiver_epoch().unwrap() > epoch);
    assert_eq!(count(&store, "alarm_state"), 1);
    assert!(!store
        .apply_revision(&d, &Snapshot::default(), 101, Some(1))
        .unwrap());
    let stable = store.protocol_secret(&d.id, Purpose::SnmpPoll).unwrap();
    assert!(store
        .save_admin_with_snmp(&d, b"", Some(1), "admin", Some(&prepared))
        .is_err());
    assert_eq!(
        store.protocol_secret(&d.id, Purpose::SnmpPoll).unwrap(),
        stable
    );
    d.snmp_poll.as_mut().unwrap().host = "other.example".into();
    assert!(prepare_secrets(&store, &vault, &d, &SecretUpdates::default()).is_err());
    let replacement =
        prepare_secrets(&store, &vault, &d, &updates("new-target-synthetic")).unwrap();
    store
        .save_admin_with_snmp(&d, b"", Some(2), "admin", Some(&replacement))
        .unwrap();
    assert_eq!(count(&store, "alarm_state"), 0);
    assert!(count(&store, "events") > 0);
    let last: Option<i64> = store
        .0
        .query_row("SELECT last_poll FROM devices", [], |r| r.get(0))
        .unwrap();
    assert!(last.is_none());
    let rendered = store.dashboard().unwrap().to_string();
    assert!(
        !rendered.contains("new-target-synthetic") && rendered.contains("has_snmp_poll_secret")
    );
    d.enabled = false;
    let clear = SecretUpdates {
        snmp_poll: SecretUpdate::Clear {},
        ..Default::default()
    };
    let prepared = prepare_secrets(&store, &vault, &d, &clear).unwrap();
    store
        .save_admin_with_snmp(&d, b"", Some(3), "admin", Some(&prepared))
        .unwrap();
    assert_eq!(count(&store, "protocol_secrets"), 0);
}

#[test]
fn schema_one_upgrade_backs_up_and_preserves_existing_records_once() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(&dir.path().join("master.key")).unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let d = redfish();
    let cipher = vault.seal(&d.id, b"synthetic-redfish").unwrap();
    store.put(&d, &cipher).unwrap();
    store.apply(&d, &fault(), 123).unwrap();
    store.0.execute("UPDATE alarm_control SET acknowledged=1,actor='admin',acknowledged_at=124,reason='Known synthetic fault'",[]).unwrap();
    let controls: String = store
        .0
        .query_row(
            "SELECT group_concat(token || signature || acknowledged || reason) FROM alarm_control",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let snapshot: String = store
        .0
        .query_row("SELECT snapshot FROM devices", [], |r| r.get(0))
        .unwrap();
    let mut legacy = serde_json::to_value(&d).unwrap();
    for key in ["primary_protocol", "snmp_poll", "snmp_traps"] {
        legacy.as_object_mut().unwrap().remove(key);
    }
    store
        .0
        .execute("UPDATE devices SET config=?1", [legacy.to_string()])
        .unwrap();
    for (table, _) in TABLES.iter().rev() {
        store.0.execute(&format!("DROP TABLE {table}"), []).unwrap();
    }
    store
        .0
        .execute_batch("DROP TABLE snmp_runtime; UPDATE schema_version SET version=1;")
        .unwrap();
    drop(store);
    let migrated = Store::open(dir.path()).unwrap();
    assert_eq!(migrated.get(&d.id).unwrap().unwrap().1, cipher);
    assert_eq!(
        migrated
            .0
            .query_row("SELECT snapshot FROM devices", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        snapshot
    );
    assert_eq!(migrated.0.query_row("SELECT group_concat(token || signature || acknowledged || reason) FROM alarm_control",[],|r|r.get::<_,String>(0)).unwrap(),controls);
    assert_eq!(
        migrated
            .0
            .query_row("SELECT version FROM schema_version", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    let backups: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("pre-snmp-schema1-")
        })
        .collect();
    assert_eq!(backups.len(), 1);
    let old = Connection::open(backups[0].join("monitor.db")).unwrap();
    assert_eq!(
        old.query_row("SELECT version FROM schema_version", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let key = Vault::open(&backups[0].join("master.key")).unwrap();
    assert_eq!(&*key.unseal(&d.id, &cipher).unwrap(), b"synthetic-redfish");
    assert_eq!(
        std::fs::metadata(backups[0].join("monitor.db"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    drop(migrated);
    Store::open(dir.path()).unwrap();
    assert_eq!(
        std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|p| p
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with("pre-snmp-schema1-"))
            .count(),
        1
    );
}

#[test]
fn failed_migration_rolls_back_schema_and_future_schema_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let conn = Connection::open(dir.path().join("monitor.db")).unwrap();
    conn.execute_batch("CREATE TABLE schema_version(version INTEGER NOT NULL);INSERT INTO schema_version VALUES(1);CREATE TABLE devices(id TEXT PRIMARY KEY,config TEXT NOT NULL,secret BLOB NOT NULL,last_poll INTEGER,snapshot TEXT,logs_initialized INTEGER NOT NULL DEFAULT 0);INSERT INTO devices(id,config,secret) VALUES('bad','{}',x'00');").unwrap();
    assert!(Store::open(dir.path()).is_err());
    assert_eq!(
        conn.query_row("SELECT version FROM schema_version", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(!conn
        .prepare("PRAGMA table_info(devices)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .any(|s| s.unwrap() == "revision"));
    assert!(!conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='protocol_secrets')",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    conn.execute("UPDATE schema_version SET version=999", [])
        .unwrap();
    assert!(Store::open(dir.path()).is_err());
    assert_eq!(
        conn.query_row("SELECT version FROM schema_version", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        999
    );
}

#[test]
fn legacy_archives_one_through_four_convert_to_current_without_secret_loss() {
    let source = tempfile::tempdir().unwrap();
    let v = Vault::open(&source.path().join("master.key")).unwrap();
    let mut s = Store::open(source.path()).unwrap();
    let d = redfish();
    s.put(&d, &v.seal(&d.id, b"legacy-synthetic-password").unwrap())
        .unwrap();
    s.apply(&d, &fault(), 100).unwrap();
    for version in 1..=4 {
        let old = converted(s.make_archive(&v).unwrap(), version);
        let decoded = archive::decrypt(
            &archive::encrypt(&old, "synthetic-backup-password").unwrap(),
            "synthetic-backup-password",
        )
        .unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap()["format"], 7);
        let target = tempfile::tempdir().unwrap();
        let v2 = Vault::open(&target.path().join("master.key")).unwrap();
        let mut t = Store::open(target.path()).unwrap();
        t.restore_archive(&decoded, &v2, "admin", 0).unwrap();
        let (d, cipher, _) = t.get(&d.id).unwrap().unwrap();
        assert!(!d.enabled && d.primary_protocol == PrimaryProtocol::Redfish);
        assert_eq!(
            &*v2.unseal(&d.id, &cipher).unwrap(),
            b"legacy-synthetic-password"
        );
        assert_eq!(count(&t, "alarm_state"), 1);
        assert!(!t.receiver_settings().unwrap().0.enabled);
    }
}

#[test]
fn snmp_archive_rekeys_pauses_inputs_preserves_local_engine_and_rolls_back_invalid_data() {
    let source = tempfile::tempdir().unwrap();
    let v = Vault::open(&source.path().join("master.key")).unwrap();
    let mut s = Store::open(source.path()).unwrap();
    let mut d = snmp();
    d.snmp_traps=Some(serde_json::from_value(json!({"enabled":true,"allowed_sources":["127.0.0.1"],"security":{"version":"v3","username":"shared"},"engine_ids":["800013700150304141"]})).unwrap());
    let mut change = updates("synthetic-poll-community");
    change.snmp_traps = SecretUpdate::Replace {
        credentials: Credentials::Usm {
            auth_password: "synthetic-auth-key".into(),
            priv_password: "synthetic-privacy-key".into(),
        },
    };
    let prepared = prepare_secrets(&s, &v, &d, &change).unwrap();
    s.save_admin_with_snmp(&d, b"", None, "admin", Some(&prepared))
        .unwrap();
    let receiver = ReceiverSettings {
        enabled: true,
        listen_port: 162,
        ..Default::default()
    };
    s.save_receiver_settings(&receiver, 0, "admin").unwrap();
    let identity=json!({"source":"snmp_poll","locator":"1.3.6.1.2.1.1.5.0","aliases":["synthetic-fan"],"generation":1,"revision":1}).to_string();
    s.0.execute(
        "INSERT INTO component_identity VALUES(?1,'fan',?2)",
        params![d.id, identity],
    )
    .unwrap();
    let receipt=json!({"fingerprint":"synthetic-event","trap_oid":"1.3.6.1.6.3.1.1.5.3","source":"127.0.0.1","verified":true,"component_key":"fan"}).to_string();
    s.apply(&d, &fault(), 100).unwrap();
    s.0.execute(
        "INSERT INTO snmp_receipts VALUES(1,?1,1,100,(SELECT MIN(id) FROM events),?2)",
        params![d.id, receipt],
    )
    .unwrap();
    let evidence=json!({"source":"snmp_trap","revision":1,"generation":1,"health":"critical","received":100,"active":true}).to_string();
    s.0.execute(
        "INSERT INTO observation_evidence VALUES(?1,'fan',1,?2)",
        params![d.id, evidence],
    )
    .unwrap();
    let archive = s.make_archive(&v).unwrap();
    let encrypted = archive::encrypt(&archive, "synthetic-backup-password").unwrap();
    assert!(!encrypted.contains("synthetic-auth-key"));
    let decoded = archive::decrypt(&encrypted, "synthetic-backup-password").unwrap();
    let target = tempfile::tempdir().unwrap();
    let v2 = Vault::open(&target.path().join("master.key")).unwrap();
    let mut t = Store::open(target.path()).unwrap();
    let engine = LocalEngine::start(target.path()).unwrap();
    let engine_bytes = std::fs::read(target.path().join("snmp-engine.json")).unwrap();
    let epoch = t.receiver_epoch().unwrap();
    t.restore_archive(&decoded, &v2, "admin", 0).unwrap();
    assert_eq!(
        std::fs::read(target.path().join("snmp-engine.json")).unwrap(),
        engine_bytes
    );
    assert_eq!(
        LocalEngine::start(target.path()).unwrap().boots,
        engine.boots + 1
    );
    assert!(t.receiver_epoch().unwrap() > epoch);
    let (restored, _, revision) = t.get(&d.id).unwrap().unwrap();
    assert!(!restored.enabled && !restored.snmp_traps.unwrap().enabled);
    assert!(!t.receiver_settings().unwrap().0.enabled);
    assert_eq!(count(&t, "component_identity"), 1);
    let raw: String =
        t.0.query_row("SELECT data FROM observation_evidence", [], |r| r.get(0))
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["active"],
        false
    );
    for purpose in [Purpose::SnmpPoll, Purpose::SnmpTraps] {
        let original = s.protocol_secret(&d.id, purpose).unwrap().unwrap();
        let restored = t.protocol_secret(&d.id, purpose).unwrap().unwrap();
        assert_ne!(original, restored);
        assert_eq!(
            *v.unseal(&purpose.aad(&d.id), &original).unwrap(),
            *v2.unseal(&purpose.aad(&d.id), &restored).unwrap()
        );
    }
    t.clear_events("admin").unwrap();
    assert_eq!(
        t.0.query_row("SELECT event_id FROM snmp_receipts", [], |r| r
            .get::<_, Option<i64>>(0))
            .unwrap(),
        None
    );
    // Clearing history must leave a fully restorable archive, and pruning a
    // receipt must null the evidence link rather than create a dangling ID.
    let after_clear = t.make_archive(&v2).unwrap();
    let check = tempfile::tempdir().unwrap();
    let check_vault = Vault::open(&check.path().join("master.key")).unwrap();
    let mut check_store = Store::open(check.path()).unwrap();
    check_store
        .restore_archive(&after_clear, &check_vault, "admin", 0)
        .unwrap();
    check_store
        .0
        .execute("DELETE FROM snmp_receipts", [])
        .unwrap();
    assert_eq!(
        check_store
            .0
            .query_row("SELECT receipt_id FROM observation_evidence", [], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .unwrap(),
        None
    );
    let stable = t.protocol_secret(&d.id, Purpose::SnmpPoll).unwrap();
    let epoch = t.receiver_epoch().unwrap();
    let cursor = t.audit_cursor().unwrap();
    let mut invalid = serde_json::to_value(archive).unwrap();
    invalid["tables"]["snmp_receiver_settings"][0][1]["value"] =
        json!("{\"enabled\":true,\"listen_port\":0,\"listen_addresses\":[\"0.0.0.0\"]}");
    let invalid: archive::Archive = serde_json::from_value(invalid).unwrap();
    assert!(t.restore_archive(&invalid, &v2, "admin", cursor).is_err());
    assert_eq!(t.protocol_secret(&d.id, Purpose::SnmpPoll).unwrap(), stable);
    assert_eq!(t.get(&d.id).unwrap().unwrap().2, revision);
    assert_eq!(t.receiver_epoch().unwrap(), epoch);
    assert_eq!(t.audit_cursor().unwrap(), cursor);
    for case in 0..4 {
        let mut invalid = serde_json::to_value(&decoded).unwrap();
        match case {
            0 => {
                use base64::Engine;
                invalid["tables"]["protocol_secrets"][0][2]["value"]=json!(base64::engine::general_purpose::STANDARD.encode(br#"{"kind":"usm","auth_password":"synthetic-auth-key","priv_password":"synthetic-privacy-key"}"#));
            }
            1 => {
                invalid["tables"]["component_identity"][0][2]["value"] = json!(
                    r#"{"source":"snmp_poll","locator":"example","aliases":[],"revision":1,"generation":1,"password":"synthetic-extra-field"}"#
                )
            }
            2 => invalid["tables"]["snmp_receipts"] = json!([]),
            _ => {
                invalid["tables"]["protocol_secrets"][0]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
        }
        let invalid: archive::Archive = serde_json::from_value(invalid).unwrap();
        assert!(
            t.restore_archive(&invalid, &v2, "admin", cursor).is_err(),
            "invalid case {case}"
        );
        assert_eq!(t.protocol_secret(&d.id, Purpose::SnmpPoll).unwrap(), stable);
        assert_eq!(t.get(&d.id).unwrap().unwrap().2, revision);
        assert_eq!(t.receiver_epoch().unwrap(), epoch);
        assert_eq!(t.audit_cursor().unwrap(), cursor);
    }
}

#[test]
fn local_engine_restart_advances_boots_and_invalid_state_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let a = LocalEngine::start(dir.path()).unwrap();
    let b = LocalEngine::start(dir.path()).unwrap();
    assert_eq!(a.engine_id, b.engine_id);
    assert_eq!(b.boots, a.boots + 1);
    let path = dir.path().join("snmp-engine.json");
    let mut exhausted = serde_json::to_value(&b).unwrap();
    exhausted["boots"] = json!(i32::MAX);
    std::fs::write(&path, serde_json::to_vec(&exhausted).unwrap()).unwrap();
    assert!(LocalEngine::start(dir.path()).is_err());
    std::fs::write(&path, b"broken").unwrap();
    assert!(LocalEngine::start(dir.path()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"broken");
    std::fs::remove_file(&path).unwrap();
    assert_ne!(
        LocalEngine::start(dir.path()).unwrap().engine_id,
        a.engine_id
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalEngine::start(dir.path()).is_err());
}

#[test]
fn trap_policy_and_credentials_do_not_reset_primary_redfish_faults() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(&dir.path().join("master.key")).unwrap();
    let mut s = Store::open(dir.path()).unwrap();
    let mut d = redfish();
    d.snmp_traps = Some(
        serde_json::from_value(
            json!({"enabled":true,"allowed_sources":["127.0.0.1"],"security":{"version":"v1"}}),
        )
        .unwrap(),
    );
    let cipher = vault.seal(&d.id, b"synthetic-redfish-password").unwrap();
    let change = |marker: &str| SecretUpdates {
        snmp_traps: SecretUpdate::Replace {
            credentials: Credentials::Community {
                community: marker.into(),
            },
        },
        ..Default::default()
    };
    let prepared = prepare_secrets(&s, &vault, &d, &change("synthetic-trap-community")).unwrap();
    s.save_admin_with_snmp(&d, &cipher, None, "admin", Some(&prepared))
        .unwrap();
    s.apply_revision(&d, &fault(), 100, Some(1)).unwrap();
    let before: String =
        s.0.query_row("SELECT snapshot FROM devices", [], |r| r.get(0))
            .unwrap();
    let epoch = s.receiver_epoch().unwrap();
    d.snmp_traps.as_mut().unwrap().allowed_sources = vec!["127.0.0.2".parse().unwrap()];
    assert!(prepare_secrets(&s, &vault, &d, &SecretUpdates::default()).is_err());
    let replacement = prepare_secrets(&s, &vault, &d, &change("new-trap-community")).unwrap();
    s.save_admin_with_snmp(&d, &cipher, Some(1), "admin", Some(&replacement))
        .unwrap();
    assert_eq!(count(&s, "alarm_state"), 1);
    assert_eq!(
        s.0.query_row("SELECT snapshot FROM devices", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        before
    );
    assert!(s.receiver_epoch().unwrap() > epoch);
    assert_eq!(s.get(&d.id).unwrap().unwrap().1, cipher);
    let trap = s
        .protocol_secret(&d.id, Purpose::SnmpTraps)
        .unwrap()
        .unwrap();
    assert!(vault.unseal(&d.id, &trap).is_err());
}

#[test]
fn cli_preserves_legacy_import_and_accepts_separate_protocol_credentials_on_stdin() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("device.json");
    std::fs::write(&config, serde_json::to_vec(&redfish()).unwrap()).unwrap();
    let execute = |input: &str, structured: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hardware-monitor"));
        cmd.arg("--state")
            .arg(dir.path())
            .arg("device-put")
            .arg("--file")
            .arg(&config);
        if structured {
            cmd.arg("--protocol-secrets");
        }
        let mut process = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        process
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        process.wait_with_output().unwrap()
    };
    assert!(execute("synthetic-cli-redfish\n", false).status.success());
    let mut d = snmp();
    d.id = "snmp-cli".into();
    std::fs::write(&config, serde_json::to_vec(&d).unwrap()).unwrap();
    let payload=json!({"snmp":{"snmp_poll":{"action":"replace","credentials":{"kind":"community","community":" synthetic-cli-community "}}}}).to_string();
    let result = execute(&payload, true);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("community"));
    let store = Store::open(dir.path()).unwrap();
    let v = Vault::open(&dir.path().join("master.key")).unwrap();
    let (_, rf, _) = store.get("p1-test").unwrap().unwrap();
    assert_eq!(
        &*v.unseal("p1-test", &rf).unwrap(),
        b"synthetic-cli-redfish"
    );
    let cipher = store
        .protocol_secret(&d.id, Purpose::SnmpPoll)
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&v.unseal(&Purpose::SnmpPoll.aad(&d.id), &cipher).unwrap())
            .contains(" synthetic-cli-community ")
    );
    let bad = execute("{\"unexpected-private-marker\":\"synthetic-secret\"}", true);
    assert!(!bad.status.success());
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("unexpected-private-marker"));
    let check = Command::new(env!("CARGO_BIN_EXE_hardware-monitor"))
        .arg("--state")
        .arg(dir.path())
        .arg("device-test")
        .arg("--file")
        .arg(&config)
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("invalid credential document"));
}

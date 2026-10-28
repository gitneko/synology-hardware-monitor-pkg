use super::*;
use crate::{
    model::{Device, Health, Observation, Snapshot},
    store::Store,
    vault::Vault,
};
use serde_json::{json, Value};
fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        id: new_id(),
        name: name.into(),
        value: value.into(),
        secret,
        content_type: String::new(),
    }
}
fn input() -> Input {
    Input {
        id: None,
        revision: 0,
        settings: Settings {
            name: "Synthetic target".into(),
            enabled: true,
            ..Default::default()
        },
        url: Some("http://127.0.0.1:12345/synthetic-url-secret".into()),
        credential: None,
    }
}
fn device() -> Device {
    serde_json::from_value(json!({"id":"test","name":"Synthetic server","endpoint":"https://bmc.example/","username":"monitor","interval_seconds":60,"repeat_seconds":300,"alerts_enabled":true,"enabled":true})).unwrap()
}
fn snapshot(health: Health) -> Snapshot {
    Snapshot {
        observations: vec![Observation {
            key: "fan".into(),
            label: "Fan".into(),
            health,
            reading: None,
            unit: None,
        }],
        ..Default::default()
    }
}
fn setup() -> (tempfile::TempDir, Store, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let vault = Vault::open(&dir.path().join("master.key")).unwrap();
    (dir, store, vault)
}
fn save(store: &mut Store, vault: &Vault, input: &Input) -> String {
    let e = store.prepare_webhook(input, vault).unwrap();
    store.save_webhook(&e, vault, "synthetic-admin").unwrap();
    e.id
}
fn event(store: &mut Store, kind: &str, key: &str, now: i64) -> i64 {
    let tx = store.0.transaction().unwrap();
    let id = crate::store::event(
        &tx,
        &device(),
        key,
        kind,
        if kind == "recovery" {
            Health::Ok
        } else {
            Health::Critical
        },
        "Synthetic fault",
        now,
    )
    .unwrap();
    tx.commit().unwrap();
    id
}
#[test]
fn typed_json_and_text_are_bounded_single_pass_and_escape_vendor_values() {
    let mut e = Event::sample();
    e.message = "Quotes \"\n{{unknown}} \\ end".into();
    let v = e.values("delivery");
    let out=template::json(r#"{"id":"{{event_id}}","verified":"{{verified}}","nested":["prefix {{message}}", "{{source}}"],"missing":"{{provisional}}"}"#,&v).unwrap();
    assert_eq!(out["id"], 123);
    assert_eq!(out["verified"], true);
    assert_eq!(out["nested"][0], format!("prefix {}", e.message));
    assert_eq!(out["missing"], false);
    assert_eq!(template::text("{{message}}", &v).unwrap(), e.message);
    for bad in ["{{nope}}", "{{message", "oops }}"] {
        assert!(template::text(bad, &v).is_err());
    }
    assert!(template::json("{bad}", &v).is_err());
    assert!(template::json(r#"{"{{device}}":1}"#, &v).is_err());
    assert!(template::text(&"a".repeat(MAX_BODY + 1), &v).is_err());
}
#[test]
fn form_and_multipart_preserve_order_repeated_names_unicode_and_secret_literals() {
    let mut s = Settings {
        name: "Forms".into(),
        format: Format::Form,
        fields: vec![
            field("a b", "x & ü + =", false),
            field("a b", "{{event_id}}", false),
            field("token", "{{not_a_template}}", true),
        ],
        ..Default::default()
    };
    s.validate().unwrap();
    let body = render(&s, &Event::sample(), "delivery", false).unwrap();
    assert_eq!(
        url::form_urlencoded::parse(&body.body)
            .into_owned()
            .collect::<Vec<_>>(),
        vec![
            ("a b".into(), "x & ü + =".into()),
            ("a b".into(), "123".into()),
            ("token".into(), "{{not_a_template}}".into())
        ]
    );
    assert!(
        !String::from_utf8(render(&s, &Event::sample(), "delivery", true).unwrap().body)
            .unwrap()
            .contains("not_a_template")
    );
    s.format = Format::Multipart;
    s.fields[0].name = "quoted\"name".into();
    s.fields[0].content_type = "text/plain; charset=utf-8".into();
    s.validate().unwrap();
    let rendered = render(&s, &Event::sample(), "delivery", false).unwrap();
    let body = String::from_utf8(rendered.body).unwrap();
    let boundary = rendered.content_type.split("boundary=").nth(1).unwrap();
    assert!(body.ends_with(&format!("--{boundary}--\r\n")));
    assert_eq!(body.matches("Content-Disposition:").count(), 3);
    assert!(body.contains("name=\"quoted\\\"name\""));
    assert!(body.contains("x & ü + =\r\n"));
}
#[test]
fn validation_rejects_unsafe_headers_urls_and_invalid_templates() {
    let mut s = input().settings.clone();
    for name in [
        "Host",
        "Content-Type",
        "Proxy-Authorization",
        "X-Hardware-Monitor-Delivery",
        "Connection",
    ] {
        s.headers = vec![field(name, "literal", false)];
        assert!(s.validate().is_err(), "{name}");
    }
    s.headers = vec![field("Authorization", "Token synthetic-custom-token", true)];
    s.validate().unwrap();
    s.auth = Auth::Bearer;
    assert!(s.validate().is_err());
    s.auth = Auth::None;
    s.headers = vec![field("X-Key", "value\r\ninjected: yes", false)];
    assert!(s.validate().is_err());
    s.headers.clear();
    for value in [
        "file:///tmp/x",
        "http://user:pass@host/",
        "https://host/#fragment",
    ] {
        assert!(url(value).is_err());
    }
    assert!(url("http://host/path?q=x").is_ok());
    assert!(url("https://host/path").is_ok());
    s.fields = vec![field("bad\r\nname", "value", false)];
    assert!(s.validate().is_err());
}
#[test]
fn secrets_are_encrypted_redacted_preserved_and_bound_to_identity() {
    let (_dir, mut store, vault) = setup();
    let mut i = input();
    i.settings.format = Format::Form;
    i.settings.auth = Auth::Bearer;
    i.credential = Some("synthetic-bearer-marker".into());
    i.settings
        .fields
        .push(field("token", "synthetic-field-marker", true));
    i.settings
        .headers
        .push(field("X-Token", "synthetic-header-marker", true));
    let id = save(&mut store, &vault, &i);
    let view = store.webhook_views(&vault).unwrap();
    let serialized = serde_json::to_string(&view).unwrap();
    for secret in [
        "synthetic-url-secret",
        "synthetic-bearer-marker",
        "synthetic-field-marker",
        "synthetic-header-marker",
    ] {
        assert!(!serialized.contains(secret));
    }
    let (raw, blob): (String, Vec<u8>) = store
        .0
        .query_row("SELECT config,secret FROM webhook_endpoints", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert!(!raw.contains("synthetic-field-marker"));
    assert!(!blob.windows(22).any(|v| v == b"synthetic-field-marker"));
    assert!(vault.unseal(&aad(&new_id()), &blob).is_err());
    i.id = Some(id.clone());
    i.revision = 1;
    i.url = None;
    i.credential = None;
    for f in i
        .settings
        .fields
        .iter_mut()
        .chain(i.settings.headers.iter_mut())
    {
        f.value.clear();
    }
    save(&mut store, &vault, &i);
    let e = store.webhook_endpoint(&id, &vault).unwrap().unwrap();
    assert_eq!(e.secrets.credential, "synthetic-bearer-marker");
    let hydrated = e.settings.hydrate(&e.secrets).unwrap();
    let preview = render(&hydrated, &Event::sample(), "id", true).unwrap();
    assert!(!String::from_utf8(preview.body)
        .unwrap()
        .contains("synthetic-field-marker"));
    i.revision = 2;
    i.url = Some("https://other.example/".into());
    assert!(store.prepare_webhook(&i, &vault).is_err());
    i.url = None;
    i.settings.fields[0].name = "changed".into();
    assert!(store.prepare_webhook(&i, &vault).is_err());
}
#[test]
fn destinations_have_independent_filters_no_backfill_and_scoped_revision_cancellation() {
    let (_dir, mut s, v) = setup();
    let now = crate::now();
    event(&mut s, "alarm", "fan", now);
    let a = save(&mut s, &v, &input());
    let mut i = input();
    i.settings.selection.critical = false;
    let b = save(&mut s, &v, &i);
    assert!(s.claim_webhook(&v, now).unwrap().is_none());
    let e = event(&mut s, "alarm", "fan", now + 1);
    let statuses = s.webhook_event_status(e).unwrap();
    assert_eq!(statuses.len(), 2);
    let excluded = statuses.iter().find(|j| j["endpoint"] == b).unwrap();
    assert_eq!(excluded["error"], "filtered");
    assert_eq!(excluded["cancelled"], true);
    assert_eq!(excluded["attempts"], 0);
    let settings = crate::notification::Input {
        language: Default::default(),
        revision: 0,
        desktop_enabled: false,
        selection: crate::notification::Selection {
            critical: false,
            ..Default::default()
        },
    };
    s.save_notifications(&settings, "admin").unwrap();
    assert!(s.claim_webhook(&v, now + 1).unwrap().is_some());
    let e2 = event(&mut s, "alarm", "psu", now + 2);
    assert_eq!(s.webhook_event_status(e2).unwrap().len(), 2);
    i.id = Some(b.clone());
    i.revision = 1;
    save(&mut s, &v, &i);
    let statuses = s.webhook_event_status(e2).unwrap();
    assert_eq!(
        statuses.iter().find(|j| j["endpoint"] == a).unwrap()["cancelled"],
        false
    );
    assert_eq!(
        statuses.iter().find(|j| j["endpoint"] == b).unwrap()["error"],
        "filtered"
    );
    let mut change = input();
    change.id = Some(a.clone());
    change.revision = 1;
    save(&mut s, &v, &change);
    assert!(s
        .webhook_event_status(e2)
        .unwrap()
        .iter()
        .all(|j| j["cancelled"] == true));
    assert!(s.prepare_webhook(&change, &v).is_err());
    s.delete_webhook(&a, 2, "admin").unwrap();
    assert!(s.delete_webhook(&a, 2, "admin").is_err());
}
#[test]
fn all_excluded_destinations_retain_selection_history_without_queuing_or_backfill() {
    let (dir, mut store, vault) = setup();
    let now = crate::now();
    let mut excluded = input();
    excluded.settings.selection.critical = false;
    let a = save(&mut store, &vault, &excluded);
    let b = save(&mut store, &vault, &excluded);
    let mut disabled = input();
    disabled.settings.enabled = false;
    save(&mut store, &vault, &disabled);
    let mut other_device = input();
    other_device.settings.devices = vec!["another-device".into()];
    let c = save(&mut store, &vault, &other_device);
    let e = event(&mut store, "alarm", "fan", now);
    let statuses = store.webhook_event_status(e).unwrap();
    assert_eq!(statuses.len(), 3);
    assert!(statuses.iter().all(|j| j["error"]
        == if j["endpoint"] == c {
            "device_filtered"
        } else {
            "filtered"
        }
        && j["cancelled"] == true
        && j["attempts"] == 0
        && j["permanent"] == false));
    assert!(store
        .claim_webhook(&vault, now + MAX_AGE)
        .unwrap()
        .is_none());
    assert!(store
        .webhook_views(&vault)
        .unwrap()
        .iter()
        .all(|v| v["pending"] == 0 && v["status"].is_null()));
    let archive = store.make_archive(&vault).unwrap();
    let (_restored_dir, mut restored, restored_vault) = setup();
    restored
        .restore_archive(&archive, &restored_vault, "admin", 0)
        .unwrap();
    assert_eq!(restored.webhook_event_status(e).unwrap(), statuses);
    excluded.id = Some(a);
    excluded.revision = 1;
    excluded.settings.selection.critical = true;
    save(&mut store, &vault, &excluded);
    store.delete_webhook(&b, 1, "admin").unwrap();
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    assert_eq!(store.webhook_event_status(e).unwrap(), statuses);
    assert!(store
        .claim_webhook(&vault, now + MAX_AGE + 1)
        .unwrap()
        .is_none());
    let future = event(&mut store, "alarm", "psu", now + MAX_AGE + 2);
    assert_eq!(store.webhook_event_status(future).unwrap().len(), 2);
    assert!(store
        .claim_webhook(&vault, now + MAX_AGE + 2)
        .unwrap()
        .is_some());
}
#[test]
fn device_selection_exclusions_are_explicit_even_when_no_destination_matches() {
    let (_dir, mut store, vault) = setup();
    let now = crate::now();
    let mut restricted = input();
    restricted.settings.devices = vec!["another-device".into()];
    // Device selection is evaluated first when both selections exclude delivery.
    restricted.settings.selection.critical = false;
    let id = save(&mut store, &vault, &restricted);
    save(&mut store, &vault, &restricted);
    let e = event(&mut store, "alarm", "fan", now);
    let statuses = store.webhook_event_status(e).unwrap();
    assert_eq!(statuses.len(), 2);
    assert!(statuses
        .iter()
        .all(|j| j["error"] == "device_filtered" && j["cancelled"] == true && j["attempts"] == 0));
    assert!(store.claim_webhook(&vault, now).unwrap().is_none());
    restricted.id = Some(id);
    restricted.revision = 1;
    restricted.settings.devices = vec![device().id];
    restricted.settings.selection.critical = true;
    save(&mut store, &vault, &restricted);
    assert_eq!(store.webhook_event_status(e).unwrap(), statuses);
    assert!(store.claim_webhook(&vault, now + 1).unwrap().is_none());
    let future = event(&mut store, "alarm", "psu", now + 2);
    let statuses = store.webhook_event_status(future).unwrap();
    assert_eq!(statuses.len(), 2);
    assert_eq!(
        statuses
            .iter()
            .filter(|j| j["error"] == "device_filtered")
            .count(),
        1
    );
    assert!(store.claim_webhook(&vault, now + 2).unwrap().is_some());
}
#[test]
fn leases_survive_restart_and_retry_order_does_not_block_other_causes_or_targets() {
    let (dir, mut s, v) = setup();
    let now = crate::now();
    let a = save(&mut s, &v, &input());
    let b = save(&mut s, &v, &input());
    let fault = event(&mut s, "alarm", "fan", now);
    event(&mut s, "recovery", "fan", now + 1);
    let j = s.claim_webhook(&v, now + 1).unwrap().unwrap();
    let other = s.claim_webhook(&v, now + 1).unwrap().unwrap();
    assert_ne!(j.endpoint.id, other.endpoint.id);
    assert_eq!(j.event.id, fault);
    assert!(s.claim_webhook(&v, now + 1).unwrap().is_none());
    let failure = Outcome {
        code: Some("webhook_http_error"),
        status: Some(429),
        retry_after: Some(120),
        permanent: false,
    };
    s.finish_webhook(&j, &failure, now + 1).unwrap();
    let stable = j.id.clone();
    drop(s);
    let mut s = Store::open(dir.path()).unwrap();
    assert!(s.claim_webhook(&v, now + 2).unwrap().is_none());
    s.finish_webhook(
        &other,
        &Outcome {
            code: None,
            status: Some(204),
            retry_after: None,
            permanent: false,
        },
        now + 2,
    )
    .unwrap();
    let recovery = s.claim_webhook(&v, now + 3).unwrap().unwrap();
    assert_eq!(recovery.event.kind, "recovery");
    assert_eq!(recovery.endpoint.id, other.endpoint.id);
    s.finish_webhook(
        &recovery,
        &Outcome {
            code: None,
            status: Some(204),
            retry_after: None,
            permanent: false,
        },
        now + 3,
    )
    .unwrap();
    let retry = s.claim_webhook(&v, now + 122).unwrap().unwrap();
    assert_eq!(retry.id, stable);
    assert!(retry.endpoint.id == a || retry.endpoint.id == b);
    s.finish_webhook(
        &retry,
        &Outcome {
            code: Some("webhook_http_error"),
            status: Some(401),
            retry_after: None,
            permanent: true,
        },
        now + 122,
    )
    .unwrap();
    assert!(s
        .webhook_event_status(fault)
        .unwrap()
        .iter()
        .any(|v| v["permanent"] == true));
}
#[test]
fn acknowledgement_unknown_recovery_reset_and_device_delete_cancel_automatic_jobs() {
    let (_dir, mut s, v) = setup();
    let d = device();
    s.put(&d, &v.seal(&d.id, b"synthetic-password").unwrap())
        .unwrap();
    save(&mut s, &v, &input());
    let now = crate::now();
    s.apply(&d, &snapshot(Health::Critical), now).unwrap();
    let token: String =
        s.0.query_row(
            "SELECT token FROM alarm_control WHERE device='test' AND key='fan'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    s.acknowledge_alarm(
        &d.id,
        1,
        "fan",
        &token,
        true,
        "Investigating",
        "admin",
        now + 1,
    )
    .unwrap();
    assert!(s.claim_webhook(&v, now + 1).unwrap().is_none());
    s.apply(&d, &snapshot(Health::Unknown), now + 301).unwrap();
    s.apply(&d, &snapshot(Health::Critical), now + 601).unwrap();
    assert!(s.claim_webhook(&v, now + 601).unwrap().is_none());
    s.apply(&d, &snapshot(Health::Ok), now + 602).unwrap();
    assert!(s.claim_webhook(&v, now + 602).unwrap().is_none());
    s.apply(&d, &snapshot(Health::Critical), now + 603).unwrap();
    assert!(s.claim_webhook(&v, now + 603).unwrap().is_some());
    let token: String =
        s.0.query_row(
            "SELECT token FROM alarm_control WHERE device='test' AND key='fan'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    s.reset_alarm(&d.id, 1, "fan", &token, "admin", now + 604)
        .unwrap();
    assert!(s.claim_webhook(&v, now + 635).unwrap().is_none());
    s.apply(&d, &snapshot(Health::Critical), now + 636).unwrap();
    s.delete_admin(&d.id, 1, "admin").unwrap();
    assert!(s.claim_webhook(&v, now + 636).unwrap().is_none());
    assert!(!s.event_entries(-1).unwrap().is_empty());
}
#[test]
fn backup_roundtrip_rekeys_credentials_pauses_webhooks_and_preserves_history() {
    let (_dir, mut s, v) = setup();
    let id = save(&mut s, &v, &input());
    let now = crate::now();
    event(&mut s, "alarm", "fan", now);
    let archive = s.make_archive(&v).unwrap();
    let encrypted = crate::archive::encrypt(&archive, "synthetic-long-backup-password").unwrap();
    assert!(!encrypted.contains("synthetic-url-secret"));
    let decoded = crate::archive::decrypt(&encrypted, "synthetic-long-backup-password").unwrap();
    let (_target, mut target, v2) = setup();
    target.restore_archive(&decoded, &v2, "admin", 0).unwrap();
    let e = target.webhook_endpoint(&id, &v2).unwrap().unwrap();
    assert!(!e.settings.enabled);
    assert!(e.revision > 1);
    assert!(e.secrets.url.contains("synthetic-url-secret"));
    assert!(target.claim_webhook(&v2, now).unwrap().is_none());
    assert!(target.webhook_event_status(1).unwrap()[0]["cancelled"] == true);
}
#[test]
fn generic_provenance_is_preserved_and_chat_presets_suppress_mentions() {
    let mut e = Event::sample();
    e.message = "<@123> <!channel> @everyone".repeat(500);
    let s = Settings {
        name: "Chat".into(),
        format: Format::Discord,
        ..Default::default()
    };
    let rendered = render(&s, &e, "same-id", false).unwrap();
    let value: Value = serde_json::from_slice(&rendered.body).unwrap();
    assert_eq!(value["allowed_mentions"]["parse"], json!([]));
    assert!(value["content"].as_str().unwrap().chars().count() <= 2000);
    let s = Settings {
        format: Format::Generic,
        ..s
    };
    let body = render(&s, &e, "same-id", false).unwrap();
    let value: Value = serde_json::from_slice(&body.body).unwrap();
    assert_eq!(value["delivery_id"], "same-id");
    assert_eq!(value["verified"], true);
    assert_eq!(value["source"], "redfish");
}

#[test]
fn streaming_backups_rekey_webhooks_and_old_format_seven_defaults_to_no_targets() {
    let (dir, mut source, vault) = setup();
    let id = save(&mut source, &vault, &input());
    event(&mut source, "alarm", "fan", crate::now());
    let snapshot = dir.path().join("snapshot.db");
    let file = dir.path().join("webhook.hmbackup");
    crate::stream_archive::snapshot(
        &dir.path().join("monitor.db"),
        &snapshot,
        &mut |_, _| Ok(()),
    )
    .unwrap();
    crate::stream_archive::export(
        &snapshot,
        &file,
        &vault,
        "synthetic-backup-password",
        &mut |_, _| Ok(()),
    )
    .unwrap();
    let (_target_dir, mut target, target_vault) = setup();
    let stage = dir.path().join("stage");
    crate::stream_archive::inspect(
        &file,
        &stage,
        &target_vault,
        "synthetic-backup-password",
        &mut |_, _| Ok(()),
    )
    .unwrap();
    let staged = Store::open(&stage).unwrap();
    target
        .restore_staged(&staged.0, &target_vault, "admin", 0, &mut || Ok(()))
        .unwrap();
    let endpoint = target
        .webhook_endpoint(&id, &target_vault)
        .unwrap()
        .unwrap();
    assert!(!endpoint.settings.enabled);
    assert!(endpoint.secrets.url.contains("synthetic-url-secret"));
    assert!(target
        .claim_webhook(&target_vault, crate::now())
        .unwrap()
        .is_none());
    let mut legacy = serde_json::to_value(source.make_archive(&vault).unwrap()).unwrap();
    legacy["format"] = json!(7);
    for (table, _) in TABLES {
        legacy["tables"].as_object_mut().unwrap().remove(*table);
    }
    let legacy = serde_json::from_value(legacy).unwrap();
    let encrypted = crate::archive::encrypt(&legacy, "synthetic-backup-password").unwrap();
    let decoded = crate::archive::decrypt(&encrypted, "synthetic-backup-password").unwrap();
    let (_old_target, mut old_target, v) = setup();
    old_target
        .restore_archive(&decoded, &v, "admin", 0)
        .unwrap();
    assert!(old_target.webhook_views(&v).unwrap().is_empty());
}

#[test]
fn delivery_attempt_limit_expiry_retention_and_csv_do_not_lose_history() {
    let (_dir, mut store, vault) = setup();
    save(&mut store, &vault, &input());
    let now = crate::now();
    let old = event(&mut store, "alarm", "fan", now - MAX_AGE - 1);
    assert!(store.claim_webhook(&vault, now).unwrap().is_none());
    assert_eq!(
        store.webhook_event_status(old).unwrap()[0]["error"],
        "expired"
    );
    let id = event(&mut store, "alarm", "psu", now);
    let job = store.claim_webhook(&vault, now).unwrap().unwrap();
    store
        .0
        .execute("UPDATE webhook_jobs SET attempts=7 WHERE id=?1", [&job.id])
        .unwrap();
    store
        .finish_webhook(
            &job,
            &Outcome {
                code: Some("webhook_connection_failed"),
                status: None,
                retry_after: None,
                permanent: false,
            },
            now,
        )
        .unwrap();
    assert_eq!(store.webhook_event_status(id).unwrap()[0]["attempts"], 8);
    assert_eq!(
        store.webhook_event_status(id).unwrap()[0]["permanent"],
        true
    );
    let (csv, count) = store.events_csv(&Default::default()).unwrap();
    assert_eq!(count, 2);
    assert!(!csv.starts_with('\u{feff}'));
    assert!(csv.contains("Webhook-Versand") && csv.contains("webhook_connection_failed"));
    store.clear_events("admin").unwrap();
    assert!(store.webhook_event_status(id).unwrap().is_empty());
}

#[test]
fn chat_templates_customize_both_services_and_old_configs_keep_their_default_text() {
    let event = Event::sample();
    let legacy: Settings = serde_json::from_value(
        json!({"name":"Old Discord","format":"discord","template":"{{message}}"}),
    )
    .unwrap();
    let value: Value =
        serde_json::from_slice(&render(&legacy, &event, "delivery", false).unwrap().body).unwrap();
    assert_eq!(
        value["content"],
        format!("[{}] {}", event.health, event.message)
    );
    assert!(value.get("embeds").is_none());
    assert!(serde_json::to_value(&legacy)
        .unwrap()
        .get("chat_template")
        .is_none());
    for format in [Format::Discord, Format::Slack] {
        let settings = Settings {
            name: "Custom chat".into(),
            format,
            chat_template: Some("Alarm {{event_id}}: {{device}} / {{health}}\n{{message}}".into()),
            ..Default::default()
        };
        settings.validate().unwrap();
        let value: Value =
            serde_json::from_slice(&render(&settings, &event, "delivery", false).unwrap().body)
                .unwrap();
        let content = if format == Format::Discord {
            &value["content"]
        } else {
            &value["text"]
        };
        assert!(content.as_str().unwrap().starts_with("Alarm 123:"));
        if format == Format::Slack {
            assert_eq!(value["blocks"][0]["text"]["text"], value["text"]);
            assert_eq!(value["blocks"][0]["text"]["type"], "plain_text");
        }
    }
}
#[test]
fn discord_embeds_support_typed_placeholders_and_embed_only_messages_without_mentions() {
    let settings=Settings{name:"Embeds".into(),format:Format::Discord,chat_template:Some(String::new()),embeds_template:Some(r#"[{"title":"{{device}}","description":"{{message}}","color":"{{event_id}}","timestamp":"{{time}}","fields":[{"name":"Status","value":"{{health}}","inline":"{{verified}}"}],"footer":{"text":"Hardware Monitor"},"author":{"name":"Monitor","url":"https://example.invalid/"},"thumbnail":{"url":"https://example.invalid/icon.png"}}]"#.into()),..Default::default()};
    settings.validate().unwrap();
    let mut event = Event::sample();
    event.message = "Quotes \"\n{{uninterpreted}}".into();
    let value: Value =
        serde_json::from_slice(&render(&settings, &event, "delivery", false).unwrap().body)
            .unwrap();
    assert_eq!(value["content"], "");
    assert_eq!(value["embeds"][0]["description"], event.message);
    assert_eq!(value["embeds"][0]["color"], 123);
    assert_eq!(value["embeds"][0]["fields"][0]["inline"], true);
    assert_eq!(value["allowed_mentions"]["parse"], json!([]));
}
#[test]
fn discord_embeds_reject_provider_limits_and_unsupported_or_wrongly_typed_fields() {
    let invalid = vec![
        json!({"title":"object not array"}),
        json!([{}]),
        json!([{"title":"a","provider":{"name":"unsupported"}}]),
        json!([{"title":"a","color":16777216}]),
        json!([{"title":"a","timestamp":"invalid"}]),
        json!([{"title":"a","image":{"url":"file:///tmp/image"}}]),
        json!([{"title":"a","fields":[{"name":"n","value":"v","inline":"true"}]}]),
        json!([{"title":"a","fields":vec![json!({"name":"n","value":"v"});26]}]),
        json!(vec![json!({"title":"a"}); 11]),
        json!([{"title":"a".repeat(257)}]),
        json!([{"description":"a".repeat(4097)}]),
        json!([{"description":"a".repeat(4000)},{"description":"b".repeat(2001)}]),
    ];
    for value in invalid {
        let settings = Settings {
            name: "Invalid embeds".into(),
            format: Format::Discord,
            embeds_template: Some(value.to_string()),
            ..Default::default()
        };
        assert!(settings.validate().is_err(), "{value}");
    }
    let settings = Settings {
        name: "Empty chat".into(),
        format: Format::Discord,
        chat_template: Some(String::new()),
        ..Default::default()
    };
    assert!(settings.validate().is_err());
}
#[test]
fn chat_text_is_shortened_without_splitting_unicode_and_templates_roundtrip_in_storage() {
    let (_dir, mut store, vault) = setup();
    let mut input = input();
    input.settings.format = Format::Discord;
    input.settings.chat_template = Some("{{message}}".into());
    input.settings.embeds_template = Some("[{\"title\":\"{{device}}\"}]".into());
    let id = save(&mut store, &vault, &input);
    let endpoint = store.webhook_endpoint(&id, &vault).unwrap().unwrap();
    assert_eq!(
        endpoint.settings.chat_template,
        input.settings.chat_template
    );
    assert_eq!(
        endpoint.settings.embeds_template,
        input.settings.embeds_template
    );
    let mut event = Event::sample();
    event.message = "😀".repeat(4000);
    let value: Value = serde_json::from_slice(
        &render(&endpoint.settings, &event, "delivery", false)
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(
        value["content"].as_str().unwrap().encode_utf16().count(),
        2000
    );
    let slack = Settings {
        format: Format::Slack,
        ..endpoint.settings
    };
    let value: Value =
        serde_json::from_slice(&render(&slack, &event, "delivery", false).unwrap().body).unwrap();
    assert_eq!(
        value["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap()
            .encode_utf16()
            .count(),
        3000
    );
}

#[test]
fn discord_sender_overrides_are_optional_persisted_and_do_not_affect_slack_or_auth() {
    let (_dir, mut store, vault) = setup();
    let mut i = input();
    i.settings.format = Format::Discord;
    let original: Value = serde_json::from_slice(
        &render(&i.settings, &Event::sample(), "delivery", false)
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(original.get("username").is_none() && original.get("avatar_url").is_none());
    i.settings.discord_username = " Hardware Monitor ".into();
    i.settings.discord_avatar_url = "https://example.invalid/avatar.png?size=128".into();
    i.settings.username = "smtp-or-basic-user".into();
    let id = save(&mut store, &vault, &i);
    let endpoint = store.webhook_endpoint(&id, &vault).unwrap().unwrap();
    assert_eq!(
        endpoint.settings.discord_username,
        i.settings.discord_username
    );
    assert_eq!(
        endpoint.settings.discord_avatar_url,
        i.settings.discord_avatar_url
    );
    let value: Value = serde_json::from_slice(
        &render(&endpoint.settings, &Event::sample(), "delivery", false)
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(value["username"], "Hardware Monitor");
    assert_eq!(value["avatar_url"], i.settings.discord_avatar_url);
    assert_eq!(endpoint.settings.username, "smtp-or-basic-user");
    let slack = Settings {
        format: Format::Slack,
        ..endpoint.settings
    };
    slack.validate().unwrap();
    let value: Value = serde_json::from_slice(
        &render(&slack, &Event::sample(), "delivery", false)
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(
        value.get("username").is_none()
            && value.get("avatar_url").is_none()
            && value.get("icon_url").is_none()
    );
}
#[test]
fn discord_sender_validation_rejects_non_http_avatars_credentials_and_invalid_names() {
    let mut s = Settings {
        name: "Discord sender".into(),
        format: Format::Discord,
        ..Default::default()
    };
    for value in [
        "data:image/png;base64,AAAA",
        "file:///tmp/avatar.png",
        "ftp://example.invalid/avatar.png",
        "https://user:password@example.invalid/avatar.png",
        "not a URL",
    ] {
        s.discord_avatar_url = value.into();
        assert!(s.validate().is_err(), "{value}");
    }
    s.discord_avatar_url = "https://example.invalid/avatar.png".into();
    s.discord_username = "😀".repeat(40);
    s.validate().unwrap();
    s.discord_username.push('a');
    assert!(s.validate().is_err());
    s.discord_username = "Name\nInjected".into();
    assert!(s.validate().is_err());
}

#[test]
fn preview_sample_language_applies_to_every_body_format_without_changing_machine_fields() {
    for (language, device, message) in [
        (
            Language::De,
            "Beispielserver",
            "Beispielserver: Lüfter ausgefallen",
        ),
        (Language::En, "Sample server", "Sample server: Fan failed"),
    ] {
        let event = Event::sample_for(language);
        assert_eq!(event.device, device);
        assert_eq!(event.message, message);
        assert_eq!(event.id, 123);
        assert_eq!(event.kind, "alarm");
        assert_eq!(event.health, "critical");
        assert_eq!(event.resource, "fan:1");
        for format in [
            Format::Generic,
            Format::Text,
            Format::Json,
            Format::Form,
            Format::Multipart,
            Format::Discord,
            Format::Slack,
        ] {
            let settings = Settings {
                name: "Language regression".into(),
                language,
                format,
                template: if format == Format::Json {
                    r#"{"message":"{{message}}"}"#.into()
                } else {
                    "{{message}}".into()
                },
                fields: vec![field("message", "{{message}}", false)],
                chat_template: Some("{{message}}".into()),
                ..Default::default()
            };
            settings.validate().unwrap();
            let rendered = render(&settings, &event, "sample-id", false).unwrap();
            if format == Format::Form {
                assert_eq!(
                    url::form_urlencoded::parse(&rendered.body)
                        .into_owned()
                        .next()
                        .unwrap()
                        .1,
                    message
                );
            } else {
                assert!(
                    String::from_utf8(rendered.body).unwrap().contains(message),
                    "{format:?}"
                );
            }
        }
    }
}
#[test]
fn automatic_webhook_language_uses_each_saved_target_and_preserves_real_names_and_vendor_text() {
    let (_dir, mut store, vault) = setup();
    let now = crate::now();
    for language in [Language::De, Language::En] {
        let mut i = input();
        i.settings.language = language;
        save(&mut store, &vault, &i);
    }
    event(&mut store, "alarm", "fan", now);
    let mut seen = 0;
    while let Some(job) = store.claim_webhook(&vault, now).unwrap() {
        assert_eq!(job.event.device, "Synthetic server");
        assert_eq!(job.event.kind, "alarm");
        let prefix = match job.endpoint.settings.language {
            Language::De => "Synthetic server: Hardwarezustand kritisch",
            Language::En => "Synthetic server: Hardware state critical",
        };
        assert!(
            job.event.message.starts_with(prefix),
            "{}",
            job.event.message
        );
        seen += 1;
        store
            .finish_webhook(
                &job,
                &Outcome {
                    code: None,
                    status: Some(204),
                    retry_after: None,
                    permanent: false,
                },
                now,
            )
            .unwrap();
    }
    assert_eq!(seen, 2);
    let tx = store.0.transaction().unwrap();
    crate::store::event(
        &tx,
        &device(),
        "log:vendor",
        "hardware_log",
        Health::Critical,
        "Lüfter ausgefallen",
        now + 2,
    )
    .unwrap();
    tx.commit().unwrap();
    for _ in 0..2 {
        let job = store.claim_webhook(&vault, now + 2).unwrap().unwrap();
        assert_eq!(job.event.message, "Synthetic server: Lüfter ausgefallen");
        store
            .finish_webhook(
                &job,
                &Outcome {
                    code: None,
                    status: Some(204),
                    retry_after: None,
                    permanent: false,
                },
                now + 2,
            )
            .unwrap();
    }
}

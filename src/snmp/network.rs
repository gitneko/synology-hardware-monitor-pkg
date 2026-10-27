//! Bounded logical-interface discovery and persisted transition assessment.
//! Numeric contracts: IF-MIB (RFC 2863), EtherLike-MIB (RFC 3635).
//! Interface labels/MACs are logical identity context, never physical proof for traps.
use super::{
    config::Profile,
    profiles::{integer, rows, text, Data, Table},
};
use crate::model::{AssessmentExclusion, Device, Health, Observation, Snapshot};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const INTERFACES: &str = "1.3.6.1.2.1.2.2.1";
const EXTENDED: &str = "1.3.6.1.2.1.31.1.1.1";
const ETHERNET: &str = "1.3.6.1.2.1.10.7.2.1";
const LIMIT: usize = 128;
const HISTORY_LIMIT: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counter {
    pub value: u64,
    pub bits: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Interface {
    pub key: String,
    pub index: u32,
    pub name: String,
    pub alias: Option<String>,
    pub kind: Option<i32>,
    pub admin: Option<i32>,
    pub oper: Option<i32>,
    pub speed_bps: Option<u64>,
    pub duplex: Option<i32>,
    pub discontinuity: Option<u32>,
    pub counters: BTreeMap<String, Counter>,
    pub present: bool,
    pub seen_up: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub interfaces: Vec<Interface>,
    pub truncated: bool,
    pub base_complete: bool,
    pub revision: i64,
    pub observed_at: i64,
}
pub(super) fn is_network_table(name: &str) -> bool {
    matches!(name, "interfaces" | "interfaces_extended" | "ethernet")
}
pub(super) fn tables() -> Vec<Table> {
    [
        (
            "interfaces",
            INTERFACES,
            &[2, 3, 5, 6, 7, 8, 10, 13, 14, 16, 19, 20][..],
        ),
        ("interfaces_extended", EXTENDED, &[1, 6, 10, 15, 18, 19][..]),
        ("ethernet", ETHERNET, &[19][..]),
    ]
    .into_iter()
    .map(|(name, entry, columns)| Table {
        name,
        entry,
        columns,
        inventory: &[],
        status: 8,
        label: Some(2),
        identity: None,
        kind: "network_interface",
        hpe: false,
        reading: None,
    })
    .collect()
}
fn counter(value: Option<&async_snmp::Value>) -> Option<Counter> {
    match value? {
        async_snmp::Value::Counter32(v) => Some(Counter {
            value: (*v).into(),
            bits: 32,
        }),
        async_snmp::Value::Counter64(v) => Some(Counter {
            value: *v,
            bits: 64,
        }),
        _ => None,
    }
}
fn gauge(value: Option<&async_snmp::Value>) -> Option<u32> {
    match value? {
        async_snmp::Value::Gauge32(v) => Some(*v),
        _ => None,
    }
}
pub(super) fn discover(data: &Data, base_complete: bool, agent_scope: &str) -> Inventory {
    let specs = tables();
    let base = rows(&specs[0], data);
    let extended = rows(&specs[1], data);
    let ethernet = rows(&specs[2], data);
    let truncated = base.len() > LIMIT;
    let interfaces = base
        .into_iter()
        .take(LIMIT)
        .map(|(index, row)| {
            let ext = extended.get(&index);
            let extra = |col| ext.and_then(|r| r.get(&col));
            let identity_name =
                text(row.get(&2)).unwrap_or_else(|| format!("ifIndex {}", index[0]));
            let name = text(extra(1)).unwrap_or_else(|| identity_name.clone());
            let mac = match row.get(&6) {
                Some(async_snmp::Value::OctetString(b)) if b.len() <= 32 => b.to_vec(),
                _ => vec![],
            };
            let digest = Sha256::digest(
                format!(
                    "{agent_scope}:{}:{identity_name}:{:?}:{mac:?}",
                    index[0],
                    integer(row.get(&3))
                )
                .as_bytes(),
            );
            let key = format!(
                "snmp:interface:{}",
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let speed_bps = gauge(extra(15))
                .filter(|v| *v > 0)
                .map(|v| u64::from(v) * 1_000_000)
                .or_else(|| {
                    gauge(row.get(&5))
                        .filter(|v| *v > 0 && *v < u32::MAX)
                        .map(u64::from)
                });
            let mut counters = BTreeMap::new();
            for (name, normal, wide) in [
                ("in_octets", 10, Some(6)),
                ("out_octets", 16, Some(10)),
                ("in_errors", 14, None),
                ("out_errors", 20, None),
                ("in_discards", 13, None),
                ("out_discards", 19, None),
            ] {
                if let Some(v) = wide
                    .and_then(|c| counter(extra(c)))
                    .or_else(|| counter(row.get(&normal)))
                {
                    counters.insert(name.into(), v);
                }
            }
            let discontinuity = match extra(19) {
                Some(async_snmp::Value::TimeTicks(v)) => Some(*v),
                _ => None,
            };
            Interface {
                key,
                index: index[0],
                name,
                alias: text(extra(18)),
                kind: integer(row.get(&3)),
                admin: integer(row.get(&7)),
                oper: integer(row.get(&8)),
                speed_bps,
                duplex: ethernet.get(&index).and_then(|r| integer(r.get(&19))),
                discontinuity,
                counters,
                present: true,
                seen_up: false,
            }
        })
        .collect();
    Inventory {
        interfaces,
        truncated,
        base_complete,
        ..Default::default()
    }
}
fn observation(
    snapshot: &mut Snapshot,
    key: String,
    label: String,
    health: Health,
    reading: Option<f64>,
    unit: Option<&str>,
    neutral: Option<AssessmentExclusion>,
) {
    if let Some(reason) = neutral.filter(|_| health == Health::Unknown) {
        snapshot.assessment_exclusions.insert(key.clone(), reason);
    }
    snapshot.observations.push(Observation {
        key,
        label,
        health,
        reading,
        unit: unit.map(str::to_owned),
    });
}
fn same_agent(a: &super::polling::Metadata, b: &super::polling::Metadata) -> bool {
    a.profile == b.profile
        && a.target == b.target
        && a.sys_object_id == b.sys_object_id
        && a.engine_id == b.engine_id
}
fn rate(
    current: &Counter,
    previous: &Counter,
    seconds: i64,
    speed: Option<u64>,
    octets: bool,
) -> Option<f64> {
    if !(1..=900).contains(&seconds)
        || current.bits != previous.bits
        || current.value < previous.value
    {
        return None;
    }
    // A 32-bit counter may wrap repeatedly at high speed. Do not manufacture a
    // small rate when an unobservable wrap is possible (v1 has no Counter64).
    if current.bits == 32
        && octets
        && speed.is_none_or(|s| u128::from(s) * seconds as u128 / 8 >= u128::from(u32::MAX))
    {
        return None;
    }
    let value = (current.value - previous.value) as f64 / seconds as f64;
    if octets && speed.is_some_and(|s| value * 8.0 > s as f64 * 1.05) {
        return None;
    }
    Some(if octets { value * 8.0 } else { value })
}
/// Run inside apply_poll's transaction, after revision/epoch checks. The saved
/// snapshot is the baseline: restarting the daemon cannot forget an open link.
pub(crate) fn assess(
    conn: &Connection,
    device: &Device,
    snapshot: &mut Snapshot,
    revision: i64,
    now: i64,
) -> Result<()> {
    if !snapshot
        .snmp
        .as_ref()
        .is_some_and(|m| m.profile == Profile::NetworkGeneric)
    {
        return Ok(());
    }
    let raw: Option<String> = conn
        .query_row(
            "SELECT snapshot FROM devices WHERE id=?1",
            [&device.id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let previous = raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<Snapshot>(s).ok());
    assess_with_previous(snapshot, previous.as_ref(), revision, now);
    Ok(())
}
fn assess_with_previous(
    snapshot: &mut Snapshot,
    previous: Option<&Snapshot>,
    revision: i64,
    now: i64,
) {
    let current_meta = snapshot.snmp.as_ref().expect("network snapshot");
    let mut inventory = current_meta.network.clone().unwrap_or_default();
    let old_meta = previous
        .and_then(|s| s.snmp.as_ref())
        .filter(|old| same_agent(current_meta, old));
    let old_inventory = old_meta
        .and_then(|m| m.network.as_ref())
        .filter(|old| old.revision == revision);
    let old: BTreeMap<_, _> = old_inventory
        .into_iter()
        .flat_map(|i| &i.interfaces)
        .map(|i| (i.key.clone(), i))
        .collect();
    let seconds = old_inventory
        .map(|i| now.saturating_sub(i.observed_at))
        .unwrap_or(0);
    let counters_fresh = old_meta.is_some_and(|old| {
        let delta = current_meta.uptime_ticks.wrapping_sub(old.uptime_ticks) as u64;
        !current_meta.agent_restart
            && current_meta.engine_boots == old.engine_boots
            && seconds > 0
            && delta > 0
            && delta <= (seconds as u64 + 60) * 100
    });
    for port in &mut inventory.interfaces {
        let before = old.get(&port.key).copied();
        port.seen_up = before.is_some_and(|p| p.seen_up)
            || (inventory.base_complete
                && port.admin == Some(1)
                && port.oper == Some(1)
                && port.kind != Some(24));
        let label = format!(
            "SNMP · {}{}",
            port.name,
            port.alias
                .as_ref()
                .map(|a| format!(" ({a})"))
                .unwrap_or_default()
        );
        let (health, neutral) =
            if !inventory.base_complete || port.admin.is_none() || port.oper.is_none() {
                (Health::Unknown, None)
            } else if port.kind == Some(24) {
                (Health::Unknown, Some(AssessmentExclusion::Informational))
            } else if port.admin == Some(2) {
                (Health::Unknown, Some(AssessmentExclusion::Disabled))
            } else if port.admin != Some(1) {
                (Health::Unknown, None)
            } else if port.oper == Some(1) {
                (Health::Ok, None)
            } else if port.seen_up && matches!(port.oper, Some(2 | 6 | 7)) {
                (Health::Warning, None)
            } else if !port.seen_up && matches!(port.oper, Some(2 | 5 | 6 | 7)) {
                (Health::Unknown, Some(AssessmentExclusion::Informational))
            } else {
                (Health::Unknown, None)
            };
        observation(
            snapshot,
            port.key.clone(),
            format!("{label} · Link"),
            health,
            None,
            None,
            neutral,
        );
        if let Some(speed) = port.speed_bps {
            observation(
                snapshot,
                format!("{}:speed", port.key),
                format!("{label} · Geschwindigkeit"),
                Health::Unknown,
                Some(speed as f64),
                Some("bit/s"),
                Some(AssessmentExclusion::Informational),
            );
        }
        if let Some(duplex) = port.duplex.filter(|v| (1..=3).contains(v)) {
            let state = if port.admin == Some(1) && port.oper == Some(1) && inventory.base_complete
            {
                match duplex {
                    2 => Health::Warning,
                    3 => Health::Ok,
                    _ => Health::Unknown,
                }
            } else {
                Health::Unknown
            };
            observation(
                snapshot,
                format!("{}:duplex", port.key),
                format!("{label} · Duplex"),
                state,
                Some(duplex as f64),
                None,
                Some(AssessmentExclusion::Informational),
            );
        }
        for (name, counter) in &port.counters {
            let octets = name.ends_with("octets");
            let value = before
                .filter(|p| {
                    p.present
                        && port.present
                        && p.discontinuity == port.discontinuity
                        && counters_fresh
                })
                .and_then(|p| p.counters.get(name))
                .and_then(|old| rate(counter, old, seconds, port.speed_bps, octets));
            let title = match name.as_str() {
                "in_octets" => "Eingehender Verkehr",
                "out_octets" => "Ausgehender Verkehr",
                "in_errors" => "Eingehende Fehler",
                "out_errors" => "Ausgehende Fehler",
                "in_discards" => "Eingehende Verwerfungen",
                _ => "Ausgehende Verwerfungen",
            };
            observation(
                snapshot,
                format!("{}:{name}", port.key),
                format!("{label} · {title}"),
                Health::Unknown,
                value,
                Some(if octets { "bit/s" } else { "1/s" }),
                Some(AssessmentExclusion::Informational),
            );
        }
    }
    // Missing formerly active ports stay visible as unknown. Disappearance,
    // truncated walks, shutdown or reboot cannot create a recovery.
    for port in old.values().filter(|p| p.seen_up) {
        if !inventory.interfaces.iter().any(|i| i.key == port.key) {
            if inventory.interfaces.len() >= HISTORY_LIMIT {
                inventory.truncated = true;
                break;
            }
            let mut missing = (*port).clone();
            missing.present = false;
            missing.admin = None;
            missing.oper = None;
            missing.counters.clear();
            observation(
                snapshot,
                missing.key.clone(),
                format!("SNMP · {} · Link", missing.name),
                Health::Unknown,
                None,
                None,
                None,
            );
            inventory.interfaces.push(missing);
        }
    }
    if inventory.truncated {
        observation(
            snapshot,
            "coverage:network_limit".into(),
            "SNMP · Schnittstellenerkennung unvollständig".into(),
            Health::Warning,
            None,
            None,
            None,
        );
        // Keep a blocking assessment row as well: coverage keys are diagnostic.
        observation(
            snapshot,
            "snmp:network_coverage".into(),
            "SNMP · Schnittstellenerkennung unvollständig".into(),
            Health::Unknown,
            None,
            None,
            None,
        );
    }
    inventory.revision = revision;
    inventory.observed_at = now;
    snapshot.snmp.as_mut().unwrap().network = Some(inventory);
}

#[cfg(test)]
mod tests {
    use super::super::profiles;
    use super::*;
    use async_snmp::Value;
    use bytes::Bytes;
    use serde_json::json;
    fn data(oper: i32) -> Data {
        let mut d = Data::new();
        d.insert(
            profiles::oid("1.3.6.1.2.1.1.2.0"),
            Value::ObjectIdentifier(profiles::oid("1.3.6.1.4.1.8072.3.2.8")),
        );
        d.insert(profiles::oid("1.3.6.1.2.1.1.3.0"), Value::TimeTicks(10000));
        for (index, state) in [(7, oper), (19, 2)] {
            for (col, v) in [
                (2, Value::OctetString(Bytes::from(format!("igc{index}")))),
                (3, Value::Integer(6)),
                (5, Value::Gauge32(1_000_000_000)),
                (7, Value::Integer(1)),
                (8, Value::Integer(state)),
                (10, Value::Counter32(1000)),
            ] {
                d.insert(profiles::oid(&format!("{INTERFACES}.{col}.{index}")), v);
            }
        }
        d
    }
    fn snapshot(d: &Data) -> Snapshot {
        let (mut s, _) = profiles::normalize(Profile::NetworkGeneric, d, 1, Some(10000));
        s.capabilities = vec![
            crate::model::Capability {
                uri: "snmp:system".into(),
                outcome: "available".into(),
                optional: false,
                http_status: None,
                attempts: 1,
            },
            crate::model::Capability {
                uri: format!("snmp:interfaces:{INTERFACES}"),
                outcome: "available".into(),
                optional: false,
                http_status: None,
                attempts: 1,
            },
        ];
        let mut metadata:super::super::polling::Metadata=serde_json::from_value(json!({"version":"v2c","profile":"network_generic","target":"127.0.0.1:161","sys_object_id":"1.3.6.1.4.1.8072.3.2.8","sys_name":null,"sys_descr":null,"uptime_ticks":10000,"generation":1,"agent_restart":false,"engine_id":null,"engine_boots":null,"complete":true,"statistics":{"requests":1,"received_bytes":10,"varbinds":1,"rejected_datagrams":0},"identities":[]})).unwrap();
        metadata.network = Some(discover(d, true, "test-agent"));
        s.snmp = Some(metadata);
        s
    }
    fn link(s: &Snapshot, index: u32) -> &Observation {
        let p = s
            .snmp
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .interfaces
            .iter()
            .find(|i| i.index == index)
            .unwrap();
        s.observations.iter().find(|o| o.key == p.key).unwrap()
    }
    #[test]
    fn only_previously_active_ports_alarm_and_a_missing_port_never_recovers() {
        let mut first = snapshot(&data(2));
        assess_with_previous(&mut first, None, 1, 100);
        assert_eq!(link(&first, 7).health, Health::Unknown);
        assert!(first
            .assessment_exclusions
            .contains_key(&link(&first, 7).key));
        let mut up = snapshot(&data(1));
        assess_with_previous(&mut up, Some(&first), 1, 110);
        assert_eq!(link(&up, 7).health, Health::Ok);
        let mut down = snapshot(&data(2));
        assess_with_previous(&mut down, Some(&up), 1, 120);
        assert_eq!(link(&down, 7).health, Health::Warning);
        assert_eq!(link(&down, 19).health, Health::Unknown);
        let mut missing = snapshot(&Data::new());
        assess_with_previous(&mut missing, Some(&down), 1, 130);
        assert_eq!(link(&missing, 7).health, Health::Unknown);
        assert!(
            !missing
                .snmp
                .as_ref()
                .unwrap()
                .network
                .as_ref()
                .unwrap()
                .interfaces[0]
                .present
        );
        let mut still_down = snapshot(&data(2));
        assess_with_previous(&mut still_down, Some(&missing), 1, 140);
        assert_eq!(link(&still_down, 7).health, Health::Warning);
        let mut recovered = snapshot(&data(1));
        assess_with_previous(&mut recovered, Some(&still_down), 1, 150);
        assert_eq!(link(&recovered, 7).health, Health::Ok);
    }
    #[test]
    fn admin_shutdown_partial_data_reboot_and_changed_identity_cannot_clear_link_fault() {
        let mut up = snapshot(&data(1));
        assess_with_previous(&mut up, None, 1, 100);
        for condition in ["shutdown", "missing_status", "partial"] {
            let mut d = data(2);
            if condition == "shutdown" {
                d.insert(
                    profiles::oid(&format!("{INTERFACES}.7.7")),
                    Value::Integer(2),
                );
            }
            if condition == "missing_status" {
                d.remove(&profiles::oid(&format!("{INTERFACES}.8.7")));
            }
            let mut changed = snapshot(&d);
            if condition == "partial" {
                changed
                    .snmp
                    .as_mut()
                    .unwrap()
                    .network
                    .as_mut()
                    .unwrap()
                    .base_complete = false;
            }
            assess_with_previous(&mut changed, Some(&up), 1, 110);
            assert_eq!(link(&changed, 7).health, Health::Unknown);
            assert!(
                changed
                    .snmp
                    .as_ref()
                    .unwrap()
                    .network
                    .as_ref()
                    .unwrap()
                    .interfaces
                    .iter()
                    .find(|i| i.index == 7)
                    .unwrap()
                    .seen_up
            );
        }
        let mut restarted = snapshot(&data(2));
        restarted.snmp.as_mut().unwrap().agent_restart = true;
        assess_with_previous(&mut restarted, Some(&up), 1, 110);
        assert_eq!(link(&restarted, 7).health, Health::Warning);
        let d = data(1);
        assert_ne!(
            discover(&d, true, "old-agent").interfaces[0].key,
            discover(&d, true, "new-agent").interfaces[0].key
        );
        let mut changed = snapshot(&data(2));
        assess_with_previous(&mut changed, Some(&up), 2, 110);
        assert_eq!(link(&changed, 7).health, Health::Unknown); // config revision scope is explicit
    }
    #[test]
    fn counters_require_matching_width_valid_time_and_unambiguous_delta() {
        let c = |value, bits| Counter { value, bits };
        assert_eq!(
            rate(&c(1500, 64), &c(500, 64), 10, Some(1_000_000), true),
            Some(800.0)
        );
        assert_eq!(rate(&c(20, 32), &c(0, 32), 10, None, false), Some(2.0));
        for (a, b, seconds, speed) in [
            (c(1, 64), c(2, 64), 10, Some(1000)),
            (c(1000, 64), c(0, 32), 10, Some(1000)),
            (c(1000, 64), c(0, 64), 0, Some(1000)),
            (c(1000, 64), c(0, 64), 901, Some(1000)),
            (c(1000, 32), c(0, 32), 60, Some(1_000_000_000)),
            (c(1000, 32), c(0, 32), 1, None),
        ] {
            assert_eq!(rate(&a, &b, seconds, speed, true), None);
        }
    }
    #[test]
    fn typed_rows_optional_extensions_and_inventory_limit_are_explicit() {
        let mut d = data(1);
        d.insert(
            profiles::oid(&format!("{INTERFACES}.8.0")),
            Value::Integer(1),
        );
        d.insert(
            profiles::oid(&format!("{EXTENDED}.6.7")),
            Value::Counter64(u64::MAX - 1),
        );
        d.insert(
            profiles::oid(&format!("{INTERFACES}.8.7")),
            Value::Gauge32(1),
        );
        d.insert(
            profiles::oid(&format!("{INTERFACES}.8.7.1")),
            Value::Integer(1),
        );
        let inventory = discover(&d, true, "scope");
        assert_eq!(inventory.interfaces.len(), 2);
        assert_eq!(inventory.interfaces[0].oper, None);
        assert_eq!(inventory.interfaces[0].counters["in_octets"].bits, 64);
        assert_eq!(
            inventory.interfaces[0].counters["in_octets"].value,
            u64::MAX - 1
        );
        let mut optional = data(1);
        optional.insert(
            profiles::oid(&format!("{EXTENDED}.1.7")),
            Value::OctetString(Bytes::from_static(b"Optional display name")),
        );
        let with_optional = discover(&optional, true, "scope");
        optional.remove(&profiles::oid(&format!("{EXTENDED}.1.7")));
        let without_optional = discover(&optional, true, "scope");
        assert_eq!(
            with_optional.interfaces[0].key,
            without_optional.interfaces[0].key
        );
        assert_ne!(
            with_optional.interfaces[0].name,
            without_optional.interfaces[0].name
        );
        for index in 30..170 {
            d.insert(
                profiles::oid(&format!("{INTERFACES}.8.{index}")),
                Value::Integer(1),
            );
        }
        let inventory = discover(&d, true, "scope");
        assert_eq!(inventory.interfaces.len(), LIMIT);
        assert!(inventory.truncated);
    }
    #[test]
    fn persisted_snapshot_survives_process_restart_and_only_fresh_up_creates_recovery() {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 30;
        let temp = tempfile::tempdir().unwrap();
        let mut store = crate::store::Store::open(temp.path()).unwrap();
        let mut device:Device=serde_json::from_value(json!({"id":"network-test","name":"Synthetic","endpoint":"https://example.invalid/","username":"reader","interval_seconds":60,"repeat_seconds":null,"alerts_enabled":false})).unwrap();
        store.put(&device, b"synthetic-sealed").unwrap();
        device.primary_protocol = crate::model::PrimaryProtocol::Snmp;
        device.snmp_poll=Some(serde_json::from_value(json!({"host":"127.0.0.1","profile":"network_generic","security":{"version":"v2c"}})).unwrap());
        store
            .0
            .execute(
                "UPDATE devices SET config=?1",
                [serde_json::to_string(&device).unwrap()],
            )
            .unwrap();
        store.apply(&device, &snapshot(&data(1)), at).unwrap();
        assert_eq!(
            store.dashboard().unwrap()["devices"][0]["overall_status"],
            "ok"
        );
        drop(store);
        let mut store = crate::store::Store::open(temp.path()).unwrap();
        store.apply(&device, &snapshot(&data(2)), at + 10).unwrap();
        assert_eq!(
            store.dashboard().unwrap()["devices"][0]["overall_status"],
            "warning"
        );
        let mut d = data(2);
        d.insert(
            profiles::oid(&format!("{INTERFACES}.7.7")),
            Value::Integer(2),
        );
        store.apply(&device, &snapshot(&d), at + 20).unwrap();
        assert_eq!(
            store.dashboard().unwrap()["devices"][0]["overall_status"],
            "warning"
        );
        store.apply(&device, &snapshot(&data(1)), at + 30).unwrap();
        assert_eq!(
            store.dashboard().unwrap()["devices"][0]["overall_status"],
            "ok"
        );
        let recoveries: i64 = store
            .0
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind='recovery' AND key LIKE 'snmp:interface:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(recoveries, 1);
    }
}

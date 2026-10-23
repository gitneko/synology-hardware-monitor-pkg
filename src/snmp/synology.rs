//! DSM SYSTEM/DISK/RAID numeric allowlist. See docs/SNMP-SYNOLOGY-SOURCES.json.
//! No DSM Enterprise raidSummary, Counter64 capacity or guessed trap mapping.
use super::profiles::{component_key, integer, oid, rows, text, Data, Identity, Table};
use crate::model::{AssessmentExclusion, Health, Observation, Snapshot};
use async_snmp::Value;

const SYSTEM: &str = "1.3.6.1.4.1.6574.1";
const DISKS: &str = "1.3.6.1.4.1.6574.2.1.1";
const RAID: &str = "1.3.6.1.4.1.6574.3.1.1";
const STATES: &[(&str, &str, &str)] = &[
    ("system_partition", "1", "DSM · Systempartition"),
    ("power", "3", "DSM · Stromversorgung"),
    ("system_fan", "4.1", "DSM · Systemlüfter"),
    ("cpu_fan", "4.2", "DSM · CPU-Lüfter"),
    ("thermal", "8", "DSM · Übertemperaturstatus"),
];

pub(super) fn scalars() -> Vec<&'static str> {
    vec![
        "1.3.6.1.4.1.6574.1.1.0",
        "1.3.6.1.4.1.6574.1.2.0",
        "1.3.6.1.4.1.6574.1.3.0",
        "1.3.6.1.4.1.6574.1.4.1.0",
        "1.3.6.1.4.1.6574.1.4.2.0",
        "1.3.6.1.4.1.6574.1.8.0",
    ]
}
pub(super) fn tables() -> Vec<Table> {
    vec![
        Table {
            name: "synology_disks",
            entry: DISKS,
            // diskHealthStatus is optional before DSM 7.1; serial is optional
            // (documented for DSM Enterprise). Never infer it from diskName/ID.
            columns: &[2, 3, 5, 6, 12, 13, 14],
            inventory: &[], // Names/serials are reread; no stale slot inventory.
            status: 5,
            label: Some(12),
            identity: Some(14),
            kind: "physical_disk",
            hpe: false,
            reading: Some((6, 1.0, "°C")),
        },
        Table {
            name: "synology_raid",
            entry: RAID,
            columns: &[2, 3],
            inventory: &[],
            status: 3,
            label: Some(2),
            identity: None,
            kind: "volume",
            hpe: false,
            reading: None,
        },
    ]
}
fn binary_status(v: Option<&Value>) -> Health {
    match integer(v) {
        Some(1) => Health::Ok,
        Some(2) => Health::Critical,
        _ => Health::Unknown,
    }
}
fn disk_status(deployment: Option<&Value>, health: Option<&Value>) -> Health {
    // Initialized/uninitialized are allocation states, not hardware failures.
    let deployed = match integer(deployment) {
        Some(1..=3) => Health::Ok,
        Some(4 | 5) => Health::Critical,
        _ => Health::Unknown,
    };
    let physical = match integer(health) {
        Some(1) => Health::Ok,
        Some(2) => Health::Warning,
        Some(3 | 4) => Health::Critical,
        _ => Health::Unknown,
    };
    match (deployed, physical) {
        (Health::Critical, _) | (_, Health::Critical) => Health::Critical,
        (_, Health::Warning) => Health::Warning,
        // Missing optional health on older DSM uses deployment status. A
        // present malformed/new enum must not silently fall back to healthy.
        (Health::Ok, Health::Ok) => Health::Ok,
        (h, _) if health.is_none() => h,
        _ => Health::Unknown,
    }
}
fn raid_status(v: Option<&Value>) -> Health {
    match integer(v) {
        Some(1) => Health::Ok,
        Some(11) => Health::Warning,
        Some(12) => Health::Critical,
        // Maintenance is visible, cannot confirm recovery, and does not create
        // a hardware fault notification just because a scrub is running.
        _ => Health::Unknown,
    }
}
fn raid_state(v: Option<&Value>) -> &'static str {
    match integer(v) {
        Some(1) => "normal",
        Some(2) => "repairing",
        Some(3) => "migrating",
        Some(4) => "expanding",
        Some(5) => "deleting",
        Some(6) => "creating",
        Some(7) => "syncing",
        Some(8) => "parity checking",
        Some(9) => "assembling",
        Some(10) => "canceling",
        Some(11) => "degraded",
        Some(12) => "crashed / read-only",
        Some(13) => "data scrubbing",
        Some(14) => "deploying",
        Some(15) => "undeploying",
        Some(16) => "mounting cache",
        Some(17) => "unmounting cache",
        Some(18) => "unfinished SHR expansion",
        Some(19) => "converting SHR to pool",
        Some(20) => "migrating SHR-1 to SHR-2",
        _ => "unknown",
    }
}
fn temperature(v: Option<&Value>) -> Option<f64> {
    // Zero/negative/sentinel values are not credible NAS operating readings.
    integer(v).filter(|v| (1..=150).contains(v)).map(f64::from)
}
pub(super) fn normalize(data: &Data, generation: i64) -> (Snapshot, Vec<Identity>) {
    let mut snapshot = Snapshot::default();
    let mut identities = Vec::new();
    for (name, suffix, label) in STATES {
        let value = data.get(&oid(&format!("{SYSTEM}.{suffix}.0")));
        // thermalStatus is a newer, optional extension; do not invent success
        // on older firmware or claim that a temperature is an alarm threshold.
        if *name == "thermal" && value.is_none() {
            continue;
        }
        snapshot.observations.push(Observation {
            key: format!("snmp:synology:{name}"),
            label: (*label).into(),
            health: binary_status(value),
            reading: None,
            unit: None,
        });
    }
    let reading = temperature(data.get(&oid(&format!("{SYSTEM}.2.0"))));
    let key = "snmp:synology:temperature".to_owned();
    if reading.is_some() {
        snapshot
            .assessment_exclusions
            .insert(key.clone(), AssessmentExclusion::Informational);
    }
    snapshot.observations.push(Observation {
        key,
        label: "DSM · Systemtemperatur".into(),
        health: Health::Unknown,
        reading,
        unit: Some("°C".into()),
    });
    for table in tables() {
        let entries = rows(&table, data);
        let keys: Vec<_> = entries
            .iter()
            .map(|(i, r)| component_key(&table, r, i, generation))
            .collect();
        for ((index, row), candidate) in entries.into_iter().zip(keys.iter()) {
            // A duplicate serial cannot authorize merging physical components.
            let key = if keys.iter().filter(|k| *k == candidate).count() > 1 {
                format!("snmp:{}:g{generation}:{}", table.name, index[0])
            } else {
                candidate.clone()
            };
            let disk = table.entry == DISKS;
            let name = table
                .label
                .and_then(|c| text(row.get(&c)))
                .or_else(|| disk.then(|| text(row.get(&2))).flatten())
                .unwrap_or_else(|| index[0].to_string());
            let (health, label, reading) = if disk {
                let state = match integer(row.get(&5)) {
                    Some(2) => " · initialized",
                    Some(3) => " · uninitialized",
                    _ => "",
                };
                (
                    disk_status(row.get(&5), row.get(&13)),
                    format!("DSM · Disk {name}{state}"),
                    temperature(row.get(&6)),
                )
            } else {
                (
                    raid_status(row.get(&3)),
                    format!("DSM · RAID {name} · {}", raid_state(row.get(&3))),
                    None,
                )
            };
            snapshot.resources.insert(
                key.clone(),
                crate::correlation::Resource {
                    kind: table.kind.into(),
                    own_health: Some(health),
                    ..Default::default()
                },
            );
            snapshot.observations.push(Observation {
                key: key.clone(),
                label,
                health,
                reading,
                unit: reading.map(|_| "°C".into()),
            });
            identities.push(Identity {
                key,
                locator: format!("{}.{}", table.entry, index[0]),
                // Actual unique serials only; generation-scoped rows have no alias.
                aliases: if keys.iter().filter(|k| *k == candidate).count() == 1
                    && candidate.contains(":id:")
                {
                    text(row.get(&14)).into_iter().collect()
                } else {
                    vec![]
                },
            });
        }
    }
    (snapshot, identities)
}

#[cfg(test)]
mod tests {
    use super::super::{config::Profile, profiles};
    use super::*;
    use bytes::Bytes;
    fn string(s: &'static str) -> Value {
        Value::OctetString(Bytes::from_static(s.as_bytes()))
    }
    #[test]
    fn dsm_statuses_are_typed_and_faults_dominate_partial_coverage() {
        for value in [
            None,
            Some(Value::Gauge32(1)),
            Some(Value::Integer(0)),
            Some(Value::Integer(3)),
        ] {
            assert_eq!(binary_status(value.as_ref()), Health::Unknown);
        }
        assert_eq!(binary_status(Some(&Value::Integer(2))), Health::Critical);
        for status in 1..=5 {
            assert_eq!(
                disk_status(Some(&Value::Integer(status)), None),
                if status <= 3 {
                    Health::Ok
                } else {
                    Health::Critical
                }
            );
        }
        assert_eq!(
            disk_status(None, Some(&Value::Integer(3))),
            Health::Critical
        );
        assert_eq!(disk_status(None, Some(&Value::Integer(1))), Health::Unknown);
        assert_eq!(
            disk_status(Some(&Value::Integer(1)), Some(&Value::Integer(5))),
            Health::Unknown
        );
        assert_eq!(
            disk_status(Some(&Value::Integer(5)), Some(&Value::Integer(1))),
            Health::Critical
        );
        assert_eq!(
            disk_status(Some(&Value::Integer(1)), Some(&Value::Integer(2))),
            Health::Warning
        );
        assert_eq!(raid_status(Some(&Value::Integer(11))), Health::Warning);
        assert_eq!(raid_status(Some(&Value::Integer(12))), Health::Critical);
        for status in (2..=10).chain(13..=22) {
            assert_eq!(raid_status(Some(&Value::Integer(status))), Health::Unknown);
        }
    }
    #[test]
    fn sparse_indices_optional_health_unique_serials_and_no_name_identity() {
        let mut data = Data::new();
        for index in [0, 17] {
            data.insert(oid(&format!("{DISKS}.5.{index}")), Value::Integer(1));
            data.insert(oid(&format!("{DISKS}.12.{index}")), string("Same name"));
        }
        data.insert(oid(&format!("{DISKS}.13.17")), Value::Integer(3));
        data.insert(oid(&format!("{DISKS}.6.0")), Value::Integer(35));
        data.insert(oid(&format!("{DISKS}.6.17")), Value::Integer(-99));
        data.insert(oid(&format!("{DISKS}.5.0.1")), Value::Integer(1)); // malformed full index
        let (a, ids) = profiles::normalize(Profile::SynologyDsm, &data, 10, None);
        let disks: Vec<_> = a
            .observations
            .iter()
            .filter(|o| o.key.contains("synology_disks"))
            .collect();
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].health, Health::Ok);
        assert_eq!(disks[0].reading, Some(35.0));
        assert_eq!(disks[1].health, Health::Critical);
        assert_eq!(disks[1].reading, None);
        assert!(ids.iter().all(|id| id.aliases.is_empty()));
        let (_, later) = normalize(&data, 11);
        assert_ne!(ids[0].key, later[0].key);
        for index in [0, 17] {
            data.insert(oid(&format!("{DISKS}.14.{index}")), string("duplicate"));
        }
        let (_, duplicate) = normalize(&data, 10);
        assert_ne!(duplicate[0].key, duplicate[1].key);
        assert!(duplicate.iter().all(|id| id.aliases.is_empty()));
        data.insert(oid(&format!("{DISKS}.14.17")), string("unique"));
        let (_, unique) = normalize(&data, 10);
        let (_, later) = normalize(&data, 11);
        assert_eq!(unique[0].key, later[0].key);
        assert_eq!(unique[1].aliases, vec!["unique"]);
    }
    #[test]
    fn bounded_temperatures_and_missing_scalars_never_assert_overall_health() {
        for value in [-99, -1, 0, 151, i32::MAX] {
            assert_eq!(temperature(Some(&Value::Integer(value))), None);
        }
        assert_eq!(temperature(Some(&Value::Gauge32(35))), None);
        let (empty, _) = normalize(&Data::new(), 1);
        assert!(empty
            .observations
            .iter()
            .all(|o| o.health == Health::Unknown));
        let mut data = Data::new();
        data.insert(oid(&format!("{SYSTEM}.1.0")), Value::Integer(1));
        data.insert(oid(&format!("{SYSTEM}.2.0")), Value::Integer(42));
        data.insert(oid(&format!("{SYSTEM}.8.0")), Value::Integer(2));
        let (snapshot, _) = normalize(&data, 1);
        assert_eq!(
            snapshot
                .observations
                .iter()
                .find(|o| o.key.ends_with(":thermal"))
                .unwrap()
                .health,
            Health::Critical
        );
        assert_eq!(
            snapshot
                .assessment_exclusions
                .get("snmp:synology:temperature"),
            Some(&AssessmentExclusion::Informational)
        );
        assert!(!snapshot.observations.iter().any(|o| o.key == "snmp:system"));
    }
}

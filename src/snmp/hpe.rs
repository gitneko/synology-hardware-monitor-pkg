//! HPE CPQ-MIB contracts, explicit population and firmware-dependent fan units.
//! Keep the saved hpe_ilo5 profile identifier compatible with iLO 5/6 configs.
use super::{
    config::Profile,
    profiles::{self, integer, oid, rows, text, Data, Table},
};
use crate::model::{Device, Health, Observation, Snapshot};
use anyhow::Result;
use async_snmp::Value;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const POWER: &str = "1.3.6.1.4.1.232.9.2.2.32.0";
const STORAGE: &str = "1.3.6.1.4.1.232.3.1.3.0";
const PSU_SUMMARY: &str = "1.3.6.1.4.1.232.6.2.9.1.0";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub slots: BTreeMap<String, Slot>,
    pub revision: i64,
    pub power_state: Option<i32>,
    pub storage_assessable: bool,
    #[serde(default)]
    pub power_redundant: Option<bool>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slot {
    pub label: String,
    pub present: Option<bool>,
    pub seen_present: bool,
}
pub(super) fn population(table: &Table, row: &BTreeMap<u32, Value>) -> Option<bool> {
    match table.name {
        "power_supplies" => match integer(row.get(&3)) {
            Some(2) => Some(false),
            Some(3) => Some(true),
            _ => None,
        },
        "fans" => match integer(row.get(&4)) {
            Some(2) => Some(false),
            Some(3) => Some(true),
            _ => None,
        },
        "hpe_memory_modules" => match integer(row.get(&19)) {
            // notPresent can also mean uninitialized. Require empty-size and
            // other condition before treating a DIMM slot as optional/empty.
            Some(2) if integer(row.get(&6)) == Some(0) && integer(row.get(&20)) == Some(1) => {
                Some(false)
            }
            Some(3..=6 | 11..=13) => Some(true),
            _ => None,
        },
        _ => None,
    }
}
fn percentage_fans(data: &Data) -> bool {
    let Some(description) = text(data.get(&oid("1.3.6.1.2.1.1.1.0"))) else {
        return false;
    };
    let Some(rest) = description
        .strip_prefix("Integrated Lights-Out ")
        .or_else(|| description.strip_prefix("HPE Integrated Lights-Out "))
    else {
        return false;
    };
    let mut words = rest.split_whitespace();
    let Some(generation) = words.next().and_then(|s| s.parse::<u32>().ok()) else {
        return false;
    };
    let Some(version) = words.next() else {
        return false;
    };
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    if major.is_empty()
        || minor.is_empty()
        || major.len() > 2
        || minor.len() > 2
        || !major.bytes().all(|b| b.is_ascii_digit())
        || !minor.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let version = (major.parse::<u32>().unwrap(), minor.parse::<u32>().unwrap());
    match generation {
        5 => version >= (3, 6),
        6 => version >= (1, 61),
        _ => false,
    }
}
pub(super) struct RowState {
    pub health: Health,
    pub reading: Option<f64>,
    pub unit: Option<&'static str>,
    pub absent: bool,
}
pub(super) fn row(table: &Table, row: &BTreeMap<u32, Value>, data: &Data) -> RowState {
    let mut health = profiles::health(row.get(&table.status), true);
    if table.name == "hpe_memory_modules" {
        // Module Condition=4 is degradedModuleIndexUnknown, NOT failed.
        health = match integer(row.get(&20)) {
            Some(2) => Health::Ok,
            Some(3 | 4) => Health::Warning,
            _ => Health::Unknown,
        };
        health = match integer(row.get(&19)) {
            Some(7..=10 | 14 | 15) => Health::Critical,
            Some(11 | 13) => Health::Warning,
            _ => health,
        };
    } else if table.name == "power_supplies" && matches!(integer(row.get(&5)), Some(2..=17)) {
        // PowerSupplyStatus has its own enum; noError(1) cannot prove Condition.
        health = Health::Critical;
    }
    let absent = population(table, row) == Some(false)
        && !matches!(health, Health::Warning | Health::Critical);
    let mut result = RowState {
        health,
        reading: None,
        unit: None,
        absent,
    };
    if absent {
        result.health = Health::Unknown;
        return result;
    }
    let measurement = match table.kind {
        "fan" if percentage_fans(data) => integer(row.get(&6))
            .filter(|v| (0..=100).contains(v))
            .map(|v| (v, "%")),
        "fan" => integer(row.get(&12))
            .filter(|v| (1..=200_000).contains(v))
            .map(|v| (v, "rpm")),
        "temperature" => integer(row.get(&4))
            .filter(|v| *v != -99 && (-1000..=2500).contains(v))
            .map(|v| (v, "°C")),
        "memory" => integer(row.get(&6)).filter(|v| *v > 0).map(|v| (v, "MiB")),
        _ => None,
    };
    if let Some((value, unit)) = measurement {
        result.reading = Some(if table.name == "hpe_memory_modules" {
            f64::from(value) / 1024.0
        } else {
            f64::from(value)
        });
        result.unit = Some(unit);
    }
    result
}
pub(super) fn summaries(data: &Data, snapshot: &mut Snapshot) {
    if data.contains_key(&oid(PSU_SUMMARY)) {
        snapshot.observations.push(Observation {
            key: "snmp:hpe:power_supplies".into(),
            label: "SNMP · Stromversorgung gesamt".into(),
            health: profiles::health(data.get(&oid(PSU_SUMMARY)), true),
            reading: None,
            unit: None,
        });
    }
    if integer(data.get(&oid(POWER))) == Some(4) {
        snapshot.observations.push(Observation {
            key: "snmp:hpe:power_denied".into(),
            label: "SNMP · Einschalten verweigert oder unzureichende Stromversorgung".into(),
            health: Health::Warning,
            reading: None,
            unit: None,
        });
    } else if matches!(integer(data.get(&oid(POWER))), Some(2 | 3)) {
        snapshot.observations.push(Observation {
            key: "snmp:hpe:power_denied".into(),
            label: "SNMP · Keine verweigerte Einschaltung gemeldet".into(),
            health: Health::Ok,
            reading: None,
            unit: None,
        });
    }
    // Redundancy is configuration, not component health. notRedundant(2)
    // alone must not manufacture a hardware fault or prove redundant power.
}
pub(super) fn inventory(data: &Data) -> Inventory {
    let mut slots = BTreeMap::new();
    for table in profiles::tables(Profile::HpeIlo5)
        .into_iter()
        .filter(|t| matches!(t.name, "power_supplies" | "fans" | "hpe_memory_modules"))
    {
        for (index, row) in rows(&table, data) {
            let index = index
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(".");
            slots.insert(
                format!("{}.{index}", table.entry),
                Slot {
                    label: format!("{} {index}", table.name),
                    present: population(&table, &row),
                    seen_present: false,
                },
            );
        }
    }
    let psu = profiles::tables(Profile::HpeIlo5)
        .into_iter()
        .find(|t| t.name == "power_supplies")
        .unwrap();
    let redundancy: Vec<_> = rows(&psu, data)
        .values()
        .filter(|r| population(&psu, r) == Some(true))
        .map(|r| integer(r.get(&9)))
        .collect();
    let power_redundant = if redundancy.contains(&Some(2)) {
        Some(false)
    } else if !redundancy.is_empty() && redundancy.iter().all(|v| *v == Some(3)) {
        Some(true)
    } else {
        None
    };
    Inventory {
        slots,
        power_redundant,
        power_state: integer(data.get(&oid(POWER))),
        storage_assessable: matches!(integer(data.get(&oid(STORAGE))), Some(2..=4)),
        ..Default::default()
    }
}
/// Persist population history with the accepted snapshot, in the same revision/
/// epoch-guarded transaction as alarms. A daemon restart cannot forget removal.
pub(crate) fn assess(
    conn: &Connection,
    device: &Device,
    snapshot: &mut Snapshot,
    revision: i64,
) -> Result<()> {
    if !snapshot
        .snmp
        .as_ref()
        .is_some_and(|m| m.profile == Profile::HpeIlo5 && m.hpe.is_some())
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
    assess_previous(snapshot, previous.as_ref(), revision);
    Ok(())
}
fn assess_previous(snapshot: &mut Snapshot, previous: Option<&Snapshot>, revision: i64) {
    let meta = snapshot.snmp.as_ref().unwrap();
    let old = previous
        .and_then(|s| s.snmp.as_ref())
        .filter(|m| {
            m.profile == meta.profile
                && m.target == meta.target
                && m.engine_id == meta.engine_id
                && m.sys_object_id == meta.sys_object_id
        })
        .and_then(|m| m.hpe.as_ref())
        .filter(|i| i.revision == revision);
    let mut inventory = meta.hpe.clone().unwrap();
    inventory.revision = revision;
    if let Some(old) = old {
        for (locator, slot) in &old.slots {
            if inventory.slots.len() >= 4096 {
                break;
            }
            inventory
                .slots
                .entry(locator.clone())
                .or_insert_with(|| Slot {
                    label: slot.label.clone(),
                    present: None,
                    seen_present: slot.seen_present,
                });
        }
    }
    for (locator, slot) in &mut inventory.slots {
        slot.seen_present = slot.present == Some(true)
            || old
                .and_then(|i| i.slots.get(locator))
                .is_some_and(|s| s.seen_present);
        if !slot.seen_present {
            continue; // The ordinary component row already explains an empty slot.
        }
        let previous = old.and_then(|i| i.slots.get(locator));
        if slot.present == Some(true)
            && !previous.is_some_and(|s| s.seen_present && s.present != Some(true))
        {
            continue; // Avoid duplicate healthy population rows.
        }
        let key = format!("snmp:hpe:presence:{locator}");
        let health = match slot.present {
            Some(false) => Health::Warning,
            Some(true) => Health::Ok,
            None => Health::Unknown,
        };
        snapshot.observations.push(Observation {
            key,
            label: format!("SNMP · Bestückung {}", slot.label),
            health,
            reading: None,
            unit: None,
        });
    }
    snapshot.snmp.as_mut().unwrap().hpe = Some(inventory);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AssessmentExclusion;
    use bytes::Bytes;
    fn fixture() -> Data {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/snmp-hpe-ilo6.json")).unwrap();
        fixture["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let value = match row["type"].as_str().unwrap() {
                    "Integer" => Value::Integer(row["value"].as_i64().unwrap() as i32),
                    "TimeTicks" => Value::TimeTicks(row["value"].as_u64().unwrap() as u32),
                    "OID" => Value::ObjectIdentifier(oid(row["value"].as_str().unwrap())),
                    "OctetString" => Value::OctetString(Bytes::copy_from_slice(
                        row["text"].as_str().unwrap().as_bytes(),
                    )),
                    _ => panic!("Unexpected sanitized fixture type"),
                };
                (oid(row["oid"].as_str().unwrap()), value)
            })
            .collect()
    }
    fn observed<'a>(snapshot: &'a Snapshot, fragment: &str) -> &'a Observation {
        snapshot
            .observations
            .iter()
            .find(|o| o.key.contains(fragment))
            .unwrap()
    }
    fn snapshot(data: &Data) -> Snapshot {
        let (mut snapshot, _) = profiles::normalize(Profile::HpeIlo5, data, 1, None);
        snapshot.snmp = Some(super::super::polling::Metadata {
            system_information: Default::default(),
            network: None,
            hpe: Some(inventory(data)),
            version: "v2c".into(),
            profile: Profile::HpeIlo5,
            target: "127.0.0.1:161".parse().unwrap(),
            sys_object_id: "1.3.6.1.4.1.232.9.4.12".into(),
            sys_name: None,
            sys_descr: None,
            uptime_ticks: 1,
            generation: 1,
            agent_restart: false,
            engine_id: None,
            engine_boots: None,
            complete: true,
            statistics: Default::default(),
            identities: vec![],
        });
        snapshot
    }
    #[test]
    fn population_history_survives_missing_rows_but_is_scoped_to_revision_and_agent() {
        let mut data = fixture();
        let mut first = snapshot(&data);
        assess_previous(&mut first, None, 1);
        let key = "snmp:hpe:presence:1.3.6.1.4.1.232.6.2.9.3.1.0.1";
        assert!(!first.observations.iter().any(|o| o.key == key));
        data.insert(oid("1.3.6.1.4.1.232.6.2.9.3.1.3.0.1"), Value::Integer(2));
        data.insert(oid("1.3.6.1.4.1.232.6.2.9.3.1.4.0.1"), Value::Integer(1));
        let mut removed = snapshot(&data);
        assess_previous(&mut removed, Some(&first), 1);
        assert_eq!(observed(&removed, key).health, Health::Warning);
        let mut missing = snapshot(&Data::new());
        assess_previous(&mut missing, Some(&removed), 1);
        assert_eq!(observed(&missing, key).health, Health::Unknown);
        let mut still_removed = snapshot(&data);
        assess_previous(&mut still_removed, Some(&missing), 1);
        assert_eq!(observed(&still_removed, key).health, Health::Warning);
        let mut changed = snapshot(&data);
        assess_previous(&mut changed, Some(&first), 2);
        assert!(!changed.observations.iter().any(|o| o.key == key));
        let mut other = snapshot(&data);
        other.snmp.as_mut().unwrap().target = "127.0.0.2:161".parse().unwrap();
        assess_previous(&mut other, Some(&first), 1);
        assert!(!other.observations.iter().any(|o| o.key == key));
        data.insert(oid("1.3.6.1.4.1.232.6.2.9.3.1.3.0.1"), Value::Integer(3));
        data.insert(oid("1.3.6.1.4.1.232.6.2.9.3.1.4.0.1"), Value::Integer(2));
        let mut reinserted = snapshot(&data);
        assess_previous(&mut reinserted, Some(&missing), 1);
        assert_eq!(observed(&reinserted, key).health, Health::Ok);
        assert!(profiles::optional_group(
            Profile::HpeIlo5,
            "hpe_memory_modules"
        ));
    }
    #[test]
    fn captured_ilo6_empty_population_is_excluded_but_storage_remains_unknown() {
        let data = fixture();
        let (snapshot, _) = profiles::normalize(Profile::HpeIlo5, &data, 1, None);
        let psu = observed(&snapshot, "power_supplies:g1:0.2");
        assert_eq!(psu.health, Health::Unknown);
        assert_eq!(
            snapshot.assessment_exclusions[&psu.key],
            AssessmentExclusion::Absent
        );
        let dims: Vec<_> = snapshot
            .observations
            .iter()
            .filter(|o| o.key.starts_with("snmp:hpe_memory_modules:"))
            .collect();
        assert_eq!(dims.len(), 3);
        assert!(dims
            .iter()
            .all(|o| snapshot.assessment_exclusions.get(&o.key)
                == Some(&AssessmentExclusion::Absent)));
        let populated = snapshot
            .observations
            .iter()
            .find(|o| o.key.starts_with("snmp:memory:id:"))
            .unwrap();
        assert_eq!(populated.health, Health::Ok);
        assert_eq!(populated.reading, Some(32768.0));
        assert_eq!(observed(&snapshot, "snmp:storage").health, Health::Unknown);
        assert!(!snapshot.assessment_exclusions.contains_key("snmp:storage"));
        let fans: Vec<_> = snapshot
            .observations
            .iter()
            .filter(|o| o.key.starts_with("snmp:fans:"))
            .collect();
        assert_eq!(
            fans.iter()
                .map(|o| o.reading.unwrap() as i32)
                .collect::<Vec<_>>(),
            [7, 7, 41]
        );
        assert!(fans
            .iter()
            .all(|o| o.health == Health::Ok && o.unit.as_deref() == Some("%")));
        assert_eq!(inventory(&data).power_state, Some(2));
        assert!(!inventory(&data).storage_assessable);
        assert_eq!(inventory(&data).power_redundant, Some(false));
    }
    #[test]
    fn firmware_boundaries_determine_units_even_for_values_one_to_three() {
        let mut data = fixture();
        let table = profiles::tables(Profile::HpeIlo5)
            .into_iter()
            .find(|t| t.name == "fans")
            .unwrap();
        let mut values = BTreeMap::from([
            (4, Value::Integer(3)),
            (6, Value::Integer(2)),
            (9, Value::Integer(2)),
        ]);
        for (description, percentage) in [
            ("Integrated Lights-Out 5 3.05", false),
            ("Integrated Lights-Out 5 3.06", true),
            ("Integrated Lights-Out 6 1.60", false),
            ("Integrated Lights-Out 6 1.61", true),
            ("Integrated Lights-Out 6 1.79", true),
            ("Integrated Lights-Out 6 1.61garbage", false),
            ("Unknown 6 1.79", false),
            ("Integrated Lights-Out 7 1.79", false),
        ] {
            data.insert(
                oid("1.3.6.1.2.1.1.1.0"),
                Value::OctetString(Bytes::copy_from_slice(description.as_bytes())),
            );
            let result = row(&table, &values, &data);
            assert_eq!(result.reading, percentage.then_some(2.0), "{description}");
            assert_eq!(result.unit, percentage.then_some("%"));
            assert_eq!(result.health, Health::Ok);
        }
        data.remove(&oid("1.3.6.1.2.1.1.1.0"));
        values.insert(12, Value::Integer(1200));
        assert_eq!(row(&table, &values, &data).unit, Some("rpm"));
        data = fixture();
        values.insert(6, Value::Integer(101));
        assert_eq!(row(&table, &values, &data).reading, None);
    }
    #[test]
    fn absence_never_hides_a_reported_fault_and_malformed_presence_is_not_absence() {
        let data = fixture();
        let table = profiles::tables(Profile::HpeIlo5)
            .into_iter()
            .find(|t| t.name == "power_supplies")
            .unwrap();
        for presence in [
            Value::Integer(1),
            Value::Integer(4),
            Value::OctetString(Bytes::from_static(b"2")),
        ] {
            let values = BTreeMap::from([(3, presence), (4, Value::Integer(1))]);
            assert!(!row(&table, &values, &data).absent);
        }
        for status in [2, 17] {
            let values = BTreeMap::from([
                (3, Value::Integer(2)),
                (4, Value::Integer(1)),
                (5, Value::Integer(status)),
            ]);
            let state = row(&table, &values, &data);
            assert_eq!(state.health, Health::Critical);
            assert!(!state.absent);
        }
        let values = BTreeMap::from([
            (3, Value::Integer(2)),
            (4, Value::Integer(3)),
            (5, Value::Integer(1)),
        ]);
        assert_eq!(row(&table, &values, &data).health, Health::Warning);
        assert!(!row(&table, &values, &data).absent);
    }
    #[test]
    fn memory_uses_its_own_condition_enum_and_does_not_guess_from_size_alone() {
        let table = profiles::tables(Profile::HpeIlo5)
            .into_iter()
            .find(|t| t.name == "hpe_memory_modules")
            .unwrap();
        let data = Data::new();
        for (status, condition, expected) in [
            (4, 2, Health::Ok),
            (4, 4, Health::Warning),
            (7, 1, Health::Critical),
            (11, 2, Health::Warning),
            (15, 1, Health::Critical),
            (1, 1, Health::Unknown),
        ] {
            let values = BTreeMap::from([
                (6, Value::Integer(0)),
                (19, Value::Integer(status)),
                (20, Value::Integer(condition)),
            ]);
            let state = row(&table, &values, &data);
            assert_eq!(state.health, expected);
            assert!(!state.absent);
        }
        let values = BTreeMap::from([
            (6, Value::Integer(32768)),
            (19, Value::Integer(2)),
            (20, Value::Integer(1)),
        ]);
        assert!(!row(&table, &values, &data).absent);
        assert_eq!(population(&table, &values), None);
        assert!(table.valid_index(&[0]));
        assert!(!table.valid_index(&[0, 1]));
    }
}

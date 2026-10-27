//! Numeric allowlist and typed normalization. Provenance: docs/SNMP-SERVER-SOURCES.json.
use super::config::Profile;
use crate::model::{AssessmentExclusion, Health, Observation, Snapshot};
use async_snmp::{Oid, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Data = BTreeMap<Oid, Value>;
#[derive(Clone)]
pub struct Table {
    pub name: &'static str,
    pub entry: &'static str,
    pub columns: &'static [u32],
    pub inventory: &'static [u32],
    pub status: u32,
    pub label: Option<u32>,
    pub identity: Option<u32>,
    pub kind: &'static str,
    pub hpe: bool,
    pub reading: Option<(u32, f64, &'static str)>,
}
impl Table {
    pub fn valid_index(&self, index: &[u32]) -> bool {
        let count = if self.entry.starts_with("1.3.6.1.2.1.")
            || self.entry.starts_with("1.3.6.1.4.1.6574.")
            || self.kind == "ups"
            || self.name == "controllers"
            || self.name == "hpe_memory_modules"
            || (!self.hpe && matches!(self.name, "physical_disks" | "virtual_disks"))
        {
            1
        } else {
            2
        };
        index.len() == count
            && index.iter().all(|x| *x <= i32::MAX as u32)
            && (!super::network::is_network_table(self.name) || index[0] > 0)
    }
    pub fn roots(&self) -> Vec<Oid> {
        self.columns
            .iter()
            .map(|c| oid(&format!("{}.{c}", self.entry)))
            .collect()
    }
}
pub fn oid(s: &str) -> Oid {
    Oid::parse(s).expect("static numeric OID")
}
pub fn scalar_oids(profile: Profile) -> Vec<Oid> {
    let mut v = vec![
        oid("1.3.6.1.2.1.1.2.0"),
        oid("1.3.6.1.2.1.1.1.0"),
        oid("1.3.6.1.2.1.1.5.0"),
        oid("1.3.6.1.2.1.1.3.0"),
    ];
    for s in match profile {
        Profile::Generic | Profile::NetworkGeneric => vec![
            "1.3.6.1.2.1.1.4.0",    // sysContact
            "1.3.6.1.2.1.1.6.0",    // sysLocation
            "1.3.6.1.2.1.25.1.1.0", // optional host uptime, not SNMP uptime
        ],
        Profile::UpsGeneric | Profile::ApcUps | Profile::EatonUps => super::ups::scalars(profile),
        Profile::SynologyDsm => super::synology::scalars(),
        Profile::DellIdrac => vec!["1.3.6.1.4.1.674.10892.5.2.1.0"],
        Profile::HpeIlo5 => vec![
            "1.3.6.1.4.1.232.6.1.3.0",
            "1.3.6.1.4.1.232.9.1.3.0",
            "1.3.6.1.4.1.232.3.1.3.0",
            "1.3.6.1.4.1.232.6.2.14.4.0",
            "1.3.6.1.4.1.232.6.2.9.1.0",
            "1.3.6.1.4.1.232.9.2.2.32.0",
        ],
    } {
        v.push(oid(s));
    }
    v
}
pub fn tables(profile: Profile) -> Vec<Table> {
    let generic = || {
        vec![
            Table {
                name: "entity",
                entry: "1.3.6.1.2.1.47.1.1.1.1",
                columns: &[2, 5, 7, 11],
                inventory: &[2, 5, 7, 11],
                status: 0,
                label: Some(7),
                identity: Some(11),
                kind: "entity",
                hpe: false,
                reading: None,
            },
            Table {
                name: "sensors",
                entry: "1.3.6.1.2.1.99.1.1.1",
                columns: &[1, 2, 3, 4, 5, 7, 8],
                inventory: &[],
                status: 5,
                label: None,
                identity: None,
                kind: "sensor",
                hpe: false,
                reading: None,
            },
        ]
    };
    match profile {
        Profile::Generic => generic(),
        Profile::NetworkGeneric => {
            let mut tables = generic();
            tables.extend(super::network::tables());
            tables
        }
        Profile::UpsGeneric | Profile::ApcUps | Profile::EatonUps => super::ups::tables(profile),
        Profile::SynologyDsm => super::synology::tables(),
        Profile::DellIdrac => vec![
            Table {
                name: "power_supplies",
                entry: "1.3.6.1.4.1.674.10892.5.4.600.12.1",
                columns: &[5, 6, 8, 15],
                inventory: &[8, 15],
                status: 5,
                label: Some(8),
                identity: Some(15),
                kind: "power_supply",
                hpe: false,
                reading: Some((6, 0.1, "W (rated)")),
            },
            Table {
                name: "fans",
                entry: "1.3.6.1.4.1.674.10892.5.4.700.12.1",
                columns: &[5, 6, 8, 16, 19],
                inventory: &[8, 16, 19],
                status: 5,
                label: Some(8),
                identity: Some(19),
                kind: "fan",
                hpe: false,
                reading: Some((6, 1.0, "rpm")),
            },
            Table {
                name: "temperatures",
                entry: "1.3.6.1.4.1.674.10892.5.4.700.20.1",
                columns: &[5, 6, 7, 8],
                inventory: &[7, 8],
                status: 5,
                label: Some(8),
                identity: None,
                kind: "temperature",
                hpe: false,
                reading: Some((6, 0.1, "°C")),
            },
            Table {
                name: "memory",
                entry: "1.3.6.1.4.1.674.10892.5.4.1100.50.1",
                columns: &[5, 8, 26],
                inventory: &[8, 26],
                status: 5,
                label: Some(8),
                identity: Some(26),
                kind: "memory",
                hpe: false,
                reading: None,
            },
            Table {
                name: "controllers",
                entry: "1.3.6.1.4.1.674.10892.5.5.1.20.130.1.1",
                columns: &[2, 37, 38, 78],
                inventory: &[2, 78],
                status: 38,
                label: Some(2),
                identity: Some(78),
                kind: "controller",
                hpe: false,
                reading: None,
            },
            Table {
                name: "physical_disks",
                entry: "1.3.6.1.4.1.674.10892.5.5.1.20.130.4.1",
                columns: &[2, 7, 24, 54],
                inventory: &[2, 7, 54],
                status: 24,
                label: Some(2),
                identity: Some(54),
                kind: "drive",
                hpe: false,
                reading: None,
            },
            Table {
                name: "virtual_disks",
                entry: "1.3.6.1.4.1.674.10892.5.5.1.20.140.1.1",
                columns: &[2, 20, 35],
                inventory: &[2, 35],
                status: 20,
                label: Some(2),
                identity: Some(35),
                kind: "volume",
                hpe: false,
                reading: None,
            },
        ],
        Profile::HpeIlo5 => vec![
            Table {
                name: "hpe_memory_modules",
                entry: "1.3.6.1.4.1.232.6.2.14.13.1",
                columns: &[6, 12, 13, 19, 20],
                inventory: &[],
                status: 20,
                label: Some(13),
                identity: Some(12),
                kind: "memory",
                hpe: true,
                reading: None,
            },
            Table {
                name: "power_supplies",
                entry: "1.3.6.1.4.1.232.6.2.9.3.1",
                columns: &[3, 4, 5, 9, 11, 15],
                inventory: &[],
                status: 4,
                label: Some(15),
                identity: Some(11),
                kind: "power_supply",
                hpe: true,
                reading: None,
            },
            Table {
                name: "fans",
                entry: "1.3.6.1.4.1.232.6.2.6.7.1",
                columns: &[4, 6, 9, 11, 12],
                inventory: &[],
                status: 9,
                label: Some(11),
                identity: None,
                kind: "fan",
                hpe: true,
                reading: Some((12, 1.0, "rpm")),
            },
            Table {
                name: "temperatures",
                entry: "1.3.6.1.4.1.232.6.2.6.8.1",
                columns: &[4, 6, 8],
                inventory: &[8],
                status: 6,
                label: Some(8),
                identity: None,
                kind: "temperature",
                hpe: true,
                reading: Some((4, 1.0, "°C")),
            },
            Table {
                name: "controllers",
                entry: "1.3.6.1.4.1.232.3.2.2.1.1",
                columns: &[6],
                inventory: &[],
                status: 6,
                label: None,
                identity: None,
                kind: "controller",
                hpe: true,
                reading: None,
            },
            Table {
                name: "physical_disks",
                entry: "1.3.6.1.4.1.232.3.2.5.1.1",
                columns: &[37, 51],
                inventory: &[51],
                status: 37,
                label: None,
                identity: Some(51),
                kind: "drive",
                hpe: true,
                reading: None,
            },
            Table {
                name: "virtual_disks",
                entry: "1.3.6.1.4.1.232.3.2.3.1.1",
                columns: &[11],
                inventory: &[],
                status: 11,
                label: None,
                identity: None,
                kind: "volume",
                hpe: true,
                reading: None,
            },
        ],
    }
}
pub fn integer(v: Option<&Value>) -> Option<i32> {
    if let Some(Value::Integer(x)) = v {
        Some(*x)
    } else {
        None
    }
}
pub fn text(v: Option<&Value>) -> Option<String> {
    let Value::OctetString(b) = v? else {
        return None;
    };
    if b.len() > 256 {
        return None;
    }
    let s = std::str::from_utf8(b).ok()?.trim().to_owned();
    (!s.is_empty() && !s.chars().any(char::is_control)).then_some(s)
}
pub fn probe_health(v: Option<&Value>) -> Health {
    match integer(v) {
        Some(3) => Health::Ok,
        Some(4 | 7) => Health::Warning,
        Some(5 | 6 | 8 | 9 | 10) => Health::Critical,
        _ => Health::Unknown,
    }
}
pub fn health(v: Option<&Value>, hpe: bool) -> Health {
    match (hpe, integer(v)) {
        (true, Some(2)) | (false, Some(3)) => Health::Ok,
        (true, Some(3)) | (false, Some(4)) => Health::Warning,
        (true, Some(4)) | (false, Some(5 | 6)) => Health::Critical,
        _ => Health::Unknown,
    }
}
/// Never join rows by position or by the last index arc alone.
pub fn rows(table: &Table, data: &Data) -> BTreeMap<Vec<u32>, BTreeMap<u32, Value>> {
    let base = oid(table.entry);
    let mut rows = BTreeMap::<Vec<u32>, BTreeMap<u32, Value>>::new();
    for (o, v) in data {
        let Some(tail) = o.arcs().strip_prefix(base.arcs()) else {
            continue;
        };
        if tail.len() < 2 || !table.valid_index(&tail[1..]) || !table.columns.contains(&tail[0]) {
            continue;
        }
        rows.entry(tail[1..].to_vec())
            .or_default()
            .insert(tail[0], v.clone());
    }
    rows
}
fn digest(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn stable_id(v: Option<&Value>) -> Option<String> {
    text(v).filter(|s| {
        !matches!(
            s.to_ascii_lowercase().as_str(),
            "unknown" | "n/a" | "none" | "not available" | "not specified" | "not present" | "0"
        )
    })
}
pub(super) fn component_key(
    table: &Table,
    row: &BTreeMap<u32, Value>,
    index: &[u32],
    generation: i64,
) -> String {
    let absent = table.hpe && super::hpe::population(table, row) == Some(false);
    if let Some(id) = table
        .identity
        .filter(|_| !absent)
        .and_then(|c| stable_id(row.get(&c)))
    {
        format!(
            "snmp:{}:id:{}",
            table.kind,
            digest(&format!("{}:{id}", table.entry))
        )
    } else {
        format!(
            "snmp:{}:g{generation}:{}",
            table.name,
            index
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(".")
        )
    }
}
pub type Identity = crate::identity::Component;
pub fn optional_group(profile: Profile, name: &str) -> bool {
    (profile == Profile::HpeIlo5 && name == "hpe_memory_modules")
        || (super::ups::is_ups(profile) && matches!(name, "ups_input" | "ups_output"))
        || matches!(profile, Profile::Generic | Profile::NetworkGeneric)
            && matches!(
                name,
                "entity" | "sensors" | "interfaces_extended" | "ethernet"
            )
}
/// Normalize only typed, validated values. Unsupported groups produce no Ok.
pub fn normalize(
    profile: Profile,
    data: &Data,
    generation: i64,
    uptime: Option<u32>,
) -> (Snapshot, Vec<Identity>) {
    if super::ups::is_ups(profile) {
        return super::ups::normalize(profile, data);
    }
    if profile == Profile::SynologyDsm {
        return super::synology::normalize(data, generation);
    }
    let mut s = Snapshot::default();
    let mut identities = Vec::new();
    for (name, root) in match profile {
        Profile::Generic | Profile::NetworkGeneric => vec![],
        Profile::UpsGeneric | Profile::ApcUps | Profile::EatonUps => {
            unreachable!("dedicated UPS normalization")
        }
        Profile::SynologyDsm => unreachable!("dedicated DSM normalization"),
        Profile::DellIdrac => vec![("system", "1.3.6.1.4.1.674.10892.5.2.1.0")],
        Profile::HpeIlo5 => vec![
            ("system", "1.3.6.1.4.1.232.6.1.3.0"),
            ("management", "1.3.6.1.4.1.232.9.1.3.0"),
            ("storage", "1.3.6.1.4.1.232.3.1.3.0"),
            ("memory", "1.3.6.1.4.1.232.6.2.14.4.0"),
        ],
    } {
        s.observations.push(Observation {
            key: format!("snmp:{name}"),
            label: format!("SNMP · {name}"),
            health: if name == "memory" && integer(data.get(&oid(root))) == Some(4) {
                Health::Unknown
            } else {
                health(data.get(&oid(root)), profile == Profile::HpeIlo5)
            },
            reading: None,
            unit: None,
        });
    }
    let specs = tables(profile);
    let entities = specs
        .iter()
        .find(|t| t.name == "entity")
        .map(|t| rows(t, data))
        .unwrap_or_default();
    for table in &specs {
        if table.name == "entity" || super::network::is_network_table(table.name) {
            continue;
        }
        let entries = rows(table, data);
        let keys: Vec<_> = entries
            .iter()
            .map(|(i, r)| component_key(table, r, i, generation))
            .collect();
        for ((index, row), mut key) in entries.into_iter().zip(keys.iter().cloned()) {
            // Duplicated alleged physical identities are ambiguous, never merge.
            if keys.iter().filter(|k| **k == key).count() > 1 {
                key = format!(
                    "snmp:{}:g{generation}:{}",
                    table.name,
                    index
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(".")
                );
            }
            let mut label = table
                .label
                .and_then(|c| text(row.get(&c)))
                .unwrap_or_else(|| {
                    format!(
                        "{} {}",
                        table.name,
                        index
                            .iter()
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join(".")
                    )
                });
            let mut h = if !table.hpe && matches!(table.kind, "fan" | "temperature") {
                probe_health(row.get(&table.status))
            } else {
                health(row.get(&table.status), table.hpe)
            };
            let mut reading = None;
            let mut unit = None;
            if table.name == "sensors" {
                if let Some(entity) = entities.get(&index) {
                    label = text(entity.get(&7))
                        .or_else(|| text(entity.get(&2)))
                        .unwrap_or(label);
                    if let Some(serial) = stable_id(entity.get(&11)).filter(|serial| {
                        entities
                            .values()
                            .filter(|row| stable_id(row.get(&11)).as_ref() == Some(serial))
                            .count()
                            == 1
                    }) {
                        key = format!(
                            "snmp:sensor:id:{}",
                            digest(&format!(
                                "{}:{serial}",
                                integer(entity.get(&5)).unwrap_or(0)
                            ))
                        );
                    }
                }
                // operStatus describes the sensor's availability, not hardware
                // thresholds. No generic sensor may assert overall hardware Ok.
                h = if integer(row.get(&5)) == Some(3) {
                    Health::Warning
                } else {
                    Health::Unknown
                };
                if h == Health::Unknown {
                    s.assessment_exclusions
                        .insert(key.clone(), AssessmentExclusion::Informational);
                }
                let fresh = match (row.get(&7), row.get(&8), uptime) {
                    (Some(Value::TimeTicks(timestamp)), Some(Value::Gauge32(rate)), Some(now))
                        if *rate > 0 =>
                    {
                        (now.wrapping_sub(*timestamp) as u64) * 10
                            <= (*rate as u64).saturating_mul(2).max(60000)
                    }
                    (Some(Value::TimeTicks(_)), Some(Value::Gauge32(0)), _) => true,
                    _ => false,
                };
                if integer(row.get(&5)) == Some(1) && fresh {
                    if let (Some(kind), Some(scale), Some(precision), Some(value)) = (
                        integer(row.get(&1)),
                        integer(row.get(&2)),
                        integer(row.get(&3)),
                        integer(row.get(&4)),
                    ) {
                        let units = match kind {
                            3 | 4 => Some("V"),
                            5 => Some("A"),
                            6 => Some("W"),
                            7 => Some("Hz"),
                            8 => Some("°C"),
                            9 => Some("%RH"),
                            10 => Some("rpm"),
                            11 => Some("m³/min"),
                            _ => None,
                        };
                        if (1..=17).contains(&scale)
                            && (-8..=9).contains(&precision)
                            && (-1_000_000_000..=1_000_000_000).contains(&value)
                        {
                            if let Some(u) = units {
                                reading =
                                    Some(value as f64 * 10f64.powi((scale - 9) * 3 - precision));
                                unit = Some(u.into());
                            }
                        }
                    }
                }
            } else if let Some((column, factor, u)) = table.reading {
                if let Some(raw) = integer(row.get(&column)) {
                    let valid = if table.kind == "temperature" {
                        (raw != -99 || !table.hpe)
                            && raw != i32::MIN
                            && (table.hpe || integer(row.get(&7)) == Some(3))
                            && (-1000.0..=2500.0).contains(&(raw as f64 * factor))
                    } else {
                        raw >= 0
                            && (table.hpe
                                || table.kind != "fan"
                                || matches!(integer(row.get(&16)), Some(3 | 5)))
                    };
                    if valid {
                        reading = Some(raw as f64 * factor);
                        unit = Some(u.into());
                    }
                }
            }
            if table.hpe {
                let state = super::hpe::row(table, &row, data);
                h = state.health;
                reading = state.reading;
                unit = state.unit.map(str::to_owned);
                if state.absent {
                    s.assessment_exclusions
                        .insert(key.clone(), AssessmentExclusion::Absent);
                }
            }
            let locator = format!(
                "{}.{}",
                table.entry,
                index
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(".")
            );
            identities.push(Identity {
                key: key.clone(),
                locator,
                aliases: table
                    .identity
                    .filter(|_| !table.hpe || super::hpe::population(table, &row) != Some(false))
                    .and_then(|c| stable_id(row.get(&c)))
                    .into_iter()
                    .collect(),
            });
            s.observations.push(Observation {
                key: key.clone(),
                label: format!("SNMP · {label}"),
                health: h,
                reading,
                unit,
            });
            let mut resource = crate::correlation::Resource {
                kind: table.kind.into(),
                own_health: Some(h),
                ..Default::default()
            };
            if table.name == "controllers" && !table.hpe {
                resource.rollup = Some(health(row.get(&37), false));
            }
            s.resources.insert(key, resource);
        }
    }
    if profile == Profile::HpeIlo5 {
        super::hpe::summaries(data, &mut s);
    }
    if matches!(profile, Profile::Generic | Profile::NetworkGeneric) {
        s.observations.push(Observation {
            key: "snmp:availability".into(),
            label: "SNMP · Erreichbarkeit und Systemidentität".into(),
            health: if matches!(
                data.get(&oid("1.3.6.1.2.1.1.2.0")),
                Some(Value::ObjectIdentifier(_))
            ) && matches!(
                data.get(&oid("1.3.6.1.2.1.1.3.0")),
                Some(Value::TimeTicks(_))
            ) {
                Health::Ok
            } else {
                Health::Unknown
            },
            reading: None,
            unit: None,
        });
        for (key, root, label) in [
            (
                "agent_uptime",
                "1.3.6.1.2.1.1.3.0",
                "SNMP · Laufzeit des SNMP-Dienstes",
            ),
            (
                "host_uptime",
                "1.3.6.1.2.1.25.1.1.0",
                "SNMP · Systemlaufzeit",
            ),
        ] {
            if let Some(Value::TimeTicks(ticks)) = data.get(&oid(root)) {
                let key = format!("snmp:{key}");
                s.assessment_exclusions
                    .insert(key.clone(), AssessmentExclusion::Informational);
                s.observations.push(Observation {
                    key,
                    label: label.into(),
                    health: Health::Unknown,
                    reading: Some(*ticks as f64 / 100.0),
                    unit: Some("s".into()),
                });
            }
        }
    }
    (s, identities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    #[test]
    fn dell_probe_enums_and_subtypes_are_distinct_from_object_status() {
        let mut data = Data::new();
        let temp = "1.3.6.1.4.1.674.10892.5.4.700.20.1";
        let fan = "1.3.6.1.4.1.674.10892.5.4.700.12.1";
        for (root, column, index, value) in [
            (temp, 5, "1.1", Value::Integer(8)),
            (temp, 6, "1.1", Value::Integer(-99)),
            (temp, 7, "1.1", Value::Integer(3)),
            (fan, 5, "1.1", Value::Integer(7)),
            (fan, 6, "1.1", Value::Integer(1)),
            (fan, 16, "1.1", Value::Integer(4)),
            (
                fan,
                19,
                "1.1",
                Value::OctetString(Bytes::from_static(b"Fan.Test")),
            ),
        ] {
            data.insert(oid(&format!("{root}.{column}.{index}")), value);
        }
        let (s, _) = normalize(Profile::DellIdrac, &data, 10, None);
        assert!(s.observations.iter().any(|o| o.health == Health::Critical
            && o.reading == Some(-9.9)
            && o.unit.as_deref() == Some("°C")));
        assert!(s
            .observations
            .iter()
            .any(|o| o.key.starts_with("snmp:fan:id:")
                && o.health == Health::Warning
                && o.reading.is_none()));
        data.insert(oid(&format!("{temp}.7.1.1")), Value::Integer(16));
        let (s, _) = normalize(Profile::DellIdrac, &data, 10, None);
        assert!(s
            .observations
            .iter()
            .filter(|o| o.key.starts_with("snmp:temperatures:"))
            .all(|o| o.reading.is_none()));
    }
    #[test]
    fn hpe_unknown_sentinel_sparse_rows_and_typed_status_preserve_evidence() {
        let mut data = Data::new();
        let root = "1.3.6.1.4.1.232.6.2.6.8.1";
        for (c, index, v) in [
            (4, "0.1", Value::Integer(-99)),
            (6, "0.1", Value::Integer(4)),
            (4, "1.1", Value::Integer(30)),
            (6, "1.1", Value::OctetString(Bytes::from_static(b"2"))),
        ] {
            data.insert(oid(&format!("{root}.{c}.{index}")), v);
        }
        let (s, _) = normalize(Profile::HpeIlo5, &data, 10, None);
        assert!(s
            .observations
            .iter()
            .any(|o| o.health == Health::Critical && o.reading.is_none()));
        assert!(s
            .observations
            .iter()
            .any(|o| o.health == Health::Unknown && o.reading == Some(30.0)));
        let table = tables(Profile::HpeIlo5)
            .into_iter()
            .find(|t| t.name == "temperatures")
            .unwrap();
        assert_eq!(rows(&table, &data).len(), 2);
        data.insert(oid(&format!("{root}.6.1")), Value::Integer(2));
        assert_eq!(rows(&table, &data).len(), 2);
    }
    #[test]
    fn duplicate_serials_never_merge_and_index_keys_are_generation_scoped() {
        let mut data = Data::new();
        let root = "1.3.6.1.4.1.232.3.2.5.1.1";
        for (index, status) in [("1.1", 4), ("2.1", 2)] {
            data.insert(oid(&format!("{root}.37.{index}")), Value::Integer(status));
            data.insert(
                oid(&format!("{root}.51.{index}")),
                Value::OctetString(Bytes::from_static(b"duplicate")),
            );
        }
        let (a, _) = normalize(Profile::HpeIlo5, &data, 10, None);
        let (b, _) = normalize(Profile::HpeIlo5, &data, 11, None);
        let keys = |s: Snapshot| {
            s.observations
                .into_iter()
                .filter(|o| o.key.starts_with("snmp:physical_disks:"))
                .map(|o| o.key)
                .collect::<Vec<_>>()
        };
        let a = keys(a);
        let b = keys(b);
        assert_eq!(a.len(), 2);
        assert_ne!(a[0], a[1]);
        assert!(a.iter().all(|key| !b.contains(key)));
    }
    #[test]
    fn stale_generic_readings_and_invalid_scale_never_become_zero_or_healthy() {
        let root = "1.3.6.1.2.1.99.1.1.1";
        let mut data = Data::new();
        for (c, v) in [
            (1, Value::Integer(8)),
            (2, Value::Integer(9)),
            (3, Value::Integer(0)),
            (4, Value::Integer(30)),
            (5, Value::Integer(1)),
            (7, Value::TimeTicks(1)),
            (8, Value::Gauge32(1000)),
        ] {
            data.insert(oid(&format!("{root}.{c}.1")), v);
        }
        let (s, _) = normalize(Profile::Generic, &data, 10, Some(10000));
        assert!(s
            .observations
            .iter()
            .all(|o| o.reading.is_none() && o.health == Health::Unknown));
        data.insert(oid(&format!("{root}.2.1")), Value::Integer(18));
        let (s, _) = normalize(Profile::Generic, &data, 10, Some(1));
        assert!(s.observations.iter().all(|o| o.reading.is_none()));
    }
}

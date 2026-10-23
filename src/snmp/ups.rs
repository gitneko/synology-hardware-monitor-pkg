//! Read-only UPS-MIB (RFC 1628), APC PowerNet and Eaton xUPS profiles.
//! Numeric contracts and provenance: docs/SNMP-UPS-SOURCES.json.
use super::{
    config::Profile,
    profiles::{integer, oid, rows, text, Data, Identity, Table},
};
use crate::model::{AssessmentExclusion, Capability, Health, Observation, Snapshot};
use async_snmp::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn is_ups(profile: Profile) -> bool {
    matches!(
        profile,
        Profile::UpsGeneric | Profile::ApcUps | Profile::EatonUps
    )
}
fn prefix(profile: Profile) -> &'static str {
    match profile {
        Profile::UpsGeneric => "rfc1628",
        Profile::ApcUps => "apc",
        Profile::EatonUps => "eaton",
        _ => unreachable!(),
    }
}
fn key(profile: Profile, suffix: &str) -> String {
    format!("snmp:ups:{}:{suffix}", prefix(profile))
}
#[allow(clippy::too_many_arguments)]
fn add(
    snapshot: &mut Snapshot,
    profile: Profile,
    suffix: &str,
    label: String,
    health: Health,
    reading: Option<f64>,
    unit: Option<&str>,
    informational: bool,
) {
    let key = key(profile, suffix);
    if informational && health == Health::Unknown {
        snapshot
            .assessment_exclusions
            .insert(key.clone(), AssessmentExclusion::Informational);
    }
    snapshot.observations.push(Observation {
        key,
        label,
        health,
        reading,
        unit: unit.map(str::to_owned),
    });
}
#[derive(Clone, Copy)]
enum Number {
    Integer,
    Gauge,
    Ticks,
}
struct Metric {
    name: &'static str,
    oid: &'static str,
    label: &'static str,
    unit: &'static str,
    factor: f64,
    min: i64,
    max: i64,
    kind: Number,
}
fn metrics(profile: Profile) -> Vec<Metric> {
    use Number::*;
    let specs = match profile {
        Profile::UpsGeneric => vec![
            (
                "charge",
                "1.3.6.1.2.1.33.1.2.4.0",
                "Batterieladung",
                "%",
                1.0,
                0,
                100,
                Integer,
            ),
            (
                "runtime",
                "1.3.6.1.2.1.33.1.2.3.0",
                "Restlaufzeit",
                "min",
                1.0,
                1,
                i32::MAX as i64,
                Integer,
            ),
            (
                "battery_voltage",
                "1.3.6.1.2.1.33.1.2.5.0",
                "Batteriespannung",
                "V",
                0.1,
                0,
                i32::MAX as i64,
                Integer,
            ),
            (
                "battery_current",
                "1.3.6.1.2.1.33.1.2.6.0",
                "Batteriestrom",
                "A",
                0.1,
                i32::MIN as i64 + 1,
                i32::MAX as i64,
                Integer,
            ),
            (
                "temperature",
                "1.3.6.1.2.1.33.1.2.7.0",
                "Batterietemperatur",
                "°C",
                1.0,
                0,
                200,
                Integer,
            ),
            (
                "on_battery_seconds",
                "1.3.6.1.2.1.33.1.2.2.0",
                "Zeit im Batteriebetrieb",
                "s",
                1.0,
                0,
                i32::MAX as i64,
                Integer,
            ),
            (
                "output_frequency",
                "1.3.6.1.2.1.33.1.4.2.0",
                "Ausgangsfrequenz",
                "Hz",
                0.1,
                0,
                i32::MAX as i64,
                Integer,
            ),
        ],
        Profile::ApcUps => vec![
            (
                "charge",
                "1.3.6.1.4.1.318.1.1.1.2.2.1.0",
                "Batterieladung",
                "%",
                1.0,
                0,
                100,
                Gauge,
            ),
            (
                "runtime",
                "1.3.6.1.4.1.318.1.1.1.2.2.3.0",
                "Restlaufzeit",
                "s",
                0.01,
                0,
                u32::MAX as i64 - 1,
                Ticks,
            ),
            (
                "temperature",
                "1.3.6.1.4.1.318.1.1.1.2.2.2.0",
                "Batterietemperatur",
                "°C",
                1.0,
                0,
                200,
                Gauge,
            ),
            (
                "load",
                "1.3.6.1.4.1.318.1.1.1.4.2.3.0",
                "Auslastung",
                "%",
                1.0,
                0,
                1000,
                Gauge,
            ),
            (
                "input_voltage",
                "1.3.6.1.4.1.318.1.1.1.3.2.1.0",
                "Eingangsspannung",
                "V",
                1.0,
                0,
                i32::MAX as i64,
                Gauge,
            ),
            (
                "output_voltage",
                "1.3.6.1.4.1.318.1.1.1.4.2.1.0",
                "Ausgangsspannung",
                "V",
                1.0,
                0,
                i32::MAX as i64,
                Gauge,
            ),
            (
                "output_current",
                "1.3.6.1.4.1.318.1.1.1.4.2.4.0",
                "Ausgangsstrom",
                "A",
                1.0,
                0,
                i32::MAX as i64,
                Gauge,
            ),
            (
                "output_frequency",
                "1.3.6.1.4.1.318.1.1.1.4.2.2.0",
                "Ausgangsfrequenz",
                "Hz",
                1.0,
                0,
                i32::MAX as i64,
                Gauge,
            ),
            (
                "battery_voltage",
                "1.3.6.1.4.1.318.1.1.1.2.3.4.0",
                "Batteriespannung",
                "V",
                0.1,
                0,
                i32::MAX as i64,
                Integer,
            ),
        ],
        Profile::EatonUps => vec![
            (
                "charge",
                "1.3.6.1.4.1.534.1.2.4.0",
                "Batterieladung",
                "%",
                1.0,
                0,
                100,
                Integer,
            ),
            (
                "runtime",
                "1.3.6.1.4.1.534.1.2.1.0",
                "Restlaufzeit",
                "s",
                1.0,
                0,
                i32::MAX as i64,
                Integer,
            ),
            (
                "battery_voltage",
                "1.3.6.1.4.1.534.1.2.2.0",
                "Batteriespannung",
                "V",
                1.0,
                0,
                i32::MAX as i64,
                Integer,
            ),
            (
                "battery_current",
                "1.3.6.1.4.1.534.1.2.3.0",
                "Batteriestrom",
                "A",
                1.0,
                i32::MIN as i64 + 1,
                i32::MAX as i64,
                Integer,
            ),
            (
                "load",
                "1.3.6.1.4.1.534.1.4.1.0",
                "Auslastung",
                "%",
                1.0,
                0,
                200,
                Integer,
            ),
            (
                "input_frequency",
                "1.3.6.1.4.1.534.1.3.1.0",
                "Eingangsfrequenz",
                "Hz",
                0.1,
                0,
                i32::MAX as i64,
                Integer,
            ),
            (
                "output_frequency",
                "1.3.6.1.4.1.534.1.4.2.0",
                "Ausgangsfrequenz",
                "Hz",
                0.1,
                0,
                i32::MAX as i64,
                Integer,
            ),
            (
                "temperature",
                "1.3.6.1.4.1.534.1.6.1.0",
                "Umgebungstemperatur",
                "°C",
                1.0,
                -100,
                200,
                Integer,
            ),
        ],
        _ => vec![],
    };
    specs
        .into_iter()
        .map(|(name, oid, label, unit, factor, min, max, kind)| Metric {
            name,
            oid,
            label,
            unit,
            factor,
            min,
            max,
            kind,
        })
        .collect()
}
fn status_oids(profile: Profile) -> Vec<&'static str> {
    match profile {
        Profile::UpsGeneric => vec![
            "1.3.6.1.2.1.33.1.2.1.0",
            "1.3.6.1.2.1.33.1.4.1.0",
            "1.3.6.1.2.1.33.1.7.3.0",
        ],
        Profile::ApcUps => vec![
            "1.3.6.1.4.1.318.1.1.1.2.1.1.0",
            "1.3.6.1.4.1.318.1.1.1.4.1.1.0",
            "1.3.6.1.4.1.318.1.1.1.2.2.4.0",
            "1.3.6.1.4.1.318.1.1.1.7.2.3.0",
            "1.3.6.1.4.1.318.1.1.1.11.1.1.0",
        ],
        Profile::EatonUps => vec![
            "1.3.6.1.4.1.534.1.4.5.0",
            "1.3.6.1.4.1.534.1.2.5.0",
            "1.3.6.1.4.1.534.1.8.2.0",
            "1.3.6.1.4.1.534.1.2.7.0",
            "1.3.6.1.4.1.534.1.2.8.0",
            "1.3.6.1.4.1.534.1.2.9.0",
            "1.3.6.1.4.1.534.1.2.10.0",
        ],
        _ => vec![],
    }
}
pub(super) fn alarm_count_oid(profile: Profile) -> Option<&'static str> {
    match profile {
        Profile::UpsGeneric => Some("1.3.6.1.2.1.33.1.6.1.0"),
        Profile::EatonUps => Some("1.3.6.1.4.1.534.1.7.1.0"),
        _ => None,
    }
}
pub(super) fn scalars(profile: Profile) -> Vec<&'static str> {
    let mut v = status_oids(profile);
    v.extend(metrics(profile).iter().map(|m| m.oid));
    v.extend(alarm_count_oid(profile));
    v.extend(match profile {
        Profile::UpsGeneric => vec!["1.3.6.1.2.1.33.1.1.1.0", "1.3.6.1.2.1.33.1.1.2.0"],
        Profile::ApcUps => vec!["1.3.6.1.4.1.318.1.1.1.1.1.1.0"],
        Profile::EatonUps => vec!["1.3.6.1.4.1.534.1.1.1.0", "1.3.6.1.4.1.534.1.1.2.0"],
        _ => vec![],
    });
    v
}
fn table(name: &'static str, entry: &'static str, columns: &'static [u32]) -> Table {
    Table {
        name,
        entry,
        columns,
        inventory: &[],
        status: 0,
        label: None,
        identity: None,
        kind: "ups",
        hpe: false,
        reading: None,
    }
}
pub(super) fn tables(profile: Profile) -> Vec<Table> {
    match profile {
        Profile::UpsGeneric => vec![
            table("ups_alarms", "1.3.6.1.2.1.33.1.6.2.1", &[2]),
            table("ups_input", "1.3.6.1.2.1.33.1.3.3.1", &[2, 3, 4, 5]),
            table("ups_output", "1.3.6.1.2.1.33.1.4.4.1", &[2, 3, 4, 5]),
        ],
        Profile::EatonUps => vec![
            table("ups_alarms", "1.3.6.1.4.1.534.1.7.2.1", &[2]),
            table("ups_input", "1.3.6.1.4.1.534.1.3.4.1", &[2, 3, 4]),
            table("ups_output", "1.3.6.1.4.1.534.1.4.4.1", &[2, 3, 4]),
        ],
        _ => vec![],
    }
}
fn enum_status(
    profile: Profile,
    name: &str,
    value: Option<&Value>,
) -> (Health, &'static str, bool) {
    use Health::*;
    let v = integer(value);
    match (profile, name, v) {
        (Profile::UpsGeneric | Profile::ApcUps, "battery", Some(2)) => {
            (Ok, "Batterie normal", false)
        }
        (Profile::UpsGeneric | Profile::ApcUps, "battery", Some(3)) => {
            (Critical, "Batterie schwach", false)
        }
        (Profile::UpsGeneric, "battery", Some(4)) => (Critical, "Batterie erschöpft", false),
        (Profile::ApcUps, "battery", Some(4)) => (Critical, "Batteriefehler", false),
        (Profile::ApcUps, "battery", Some(5)) => (Critical, "Batterie fehlt", false),
        (Profile::ApcUps, "replace", Some(1)) => (Ok, "Kein Batteriewechsel erforderlich", false),
        (Profile::ApcUps, "replace", Some(2)) => (Warning, "Batteriewechsel erforderlich", false),
        (Profile::EatonUps, "abm", Some(1)) => (Ok, "Batterie wird geladen", false),
        (Profile::EatonUps, "abm", Some(2)) => (Warning, "Batterie wird entladen", false),
        (Profile::EatonUps, "abm", Some(3 | 4)) => (Ok, "Batterie geladen", false),
        (Profile::EatonUps, "abm", Some(6)) => (Critical, "Batterie getrennt", false),
        (Profile::EatonUps, "abm", Some(7)) => (Unknown, "Test läuft", true),
        (Profile::EatonUps, "abm", Some(8)) => (Warning, "Batterie prüfen", false),
        (Profile::EatonUps, "failure" | "not_present" | "low_capacity", Some(1)) => {
            (Critical, "Batteriestörung gemeldet", false)
        }
        (Profile::EatonUps, "aged", Some(1)) => (Warning, "Batteriewechsel erforderlich", false),
        (Profile::EatonUps, "failure" | "not_present" | "low_capacity" | "aged", Some(2)) => {
            (Ok, "Keine Störung gemeldet", false)
        }
        (Profile::UpsGeneric | Profile::ApcUps, "test", Some(1))
        | (Profile::EatonUps, "test", Some(2)) => (Ok, "Test erfolgreich", false),
        (Profile::UpsGeneric, "test", Some(2)) => (Warning, "Test mit Warnung", false),
        (Profile::UpsGeneric | Profile::EatonUps, "test", Some(3))
        | (Profile::ApcUps, "test", Some(2)) => (Critical, "Test fehlgeschlagen", false),
        (Profile::UpsGeneric, "test", Some(4..=6))
        | (Profile::ApcUps, "test", Some(3 | 4))
        | (Profile::EatonUps, "test", Some(1 | 4..=7)) => {
            (Unknown, "Kein abgeschlossenes Testergebnis", true)
        }
        (Profile::ApcUps, "output", Some(2 | 4 | 12 | 13 | 20)) => (Ok, "Netzbetrieb", false),
        (Profile::ApcUps, "output", Some(3)) => (Warning, "Batteriebetrieb", false),
        (Profile::ApcUps, "output", Some(6 | 9 | 16 | 17)) => (Warning, "Bypassbetrieb", false),
        (Profile::ApcUps, "output", Some(5 | 7 | 8 | 10 | 11)) => {
            (Critical, "Ausgang aus oder gestört", false)
        }
        (Profile::ApcUps, "output", Some(15 | 28)) => (Unknown, "Test läuft", true),
        (Profile::UpsGeneric | Profile::EatonUps, "output", Some(3 | 6 | 7))
        | (Profile::EatonUps, "output", Some(8..=10 | 12)) => (Ok, "Netzbetrieb", false),
        (Profile::UpsGeneric | Profile::EatonUps, "output", Some(2)) => {
            (Critical, "Ausgang aus oder gestört", false)
        }
        (Profile::UpsGeneric | Profile::EatonUps, "output", Some(4))
        | (Profile::EatonUps, "output", Some(11)) => (Warning, "Bypassbetrieb", false),
        (Profile::UpsGeneric | Profile::EatonUps, "output", Some(5)) => {
            (Warning, "Batteriebetrieb", false)
        }
        _ => (Unknown, "Zustand unbekannt", false),
    }
}
pub(super) fn normalize(profile: Profile, data: &Data) -> (Snapshot, Vec<Identity>) {
    let mut s = Snapshot::default();
    let states = match profile {
        Profile::UpsGeneric => vec![
            ("battery", "Batteriezustand", true),
            ("output", "Ausgangsversorgung", true),
            ("test", "Selbsttest", false),
        ],
        Profile::ApcUps => vec![
            ("battery", "Batteriezustand", true),
            ("output", "Ausgangsversorgung", true),
            ("replace", "Batteriewechsel", false),
            ("test", "Selbsttest", false),
        ],
        Profile::EatonUps => vec![
            ("output", "Ausgangsversorgung", true),
            ("abm", "Batteriemanagement", false),
            ("test", "Selbsttest", false),
            ("failure", "Batteriefehler", false),
            ("not_present", "Batterie fehlt", false),
            ("aged", "Batteriealterung", false),
            ("low_capacity", "Batteriekapazität niedrig", false),
        ],
        _ => vec![],
    };
    for ((name, label, required), root) in states.into_iter().zip(status_oids(profile)) {
        let value = data.get(&oid(root));
        if !required && value.is_none() {
            continue;
        }
        let (health, state, info) = enum_status(profile, name, value);
        let condition = matches!(health, Health::Warning | Health::Critical).then(|| {
            serde_json::json!([
                format!("{root}:{}", integer(value).unwrap()),
                null,
                key(profile, name),
                if health == Health::Critical {
                    "Critical"
                } else {
                    "Warning"
                }
            ])
            .to_string()
        });
        s.resources.insert(
            key(profile, name),
            crate::correlation::Resource {
                kind: "ups".into(),
                own_health: Some(health),
                independent_condition: true,
                condition_fingerprint: serde_json::json!([
                    null,
                    null,
                    condition.into_iter().collect::<Vec<_>>()
                ])
                .to_string(),
                ..Default::default()
            },
        );
        add(
            &mut s,
            profile,
            name,
            format!("USV · {label} · {state}"),
            health,
            None,
            None,
            info,
        );
    }
    if profile == Profile::ApcUps {
        apc_flags(&mut s, data);
    }
    for m in metrics(profile) {
        let Some(value) = data.get(&oid(m.oid)) else {
            continue;
        };
        let raw = match (m.kind, value) {
            (Number::Integer, Value::Integer(v)) => Some(i64::from(*v)),
            (Number::Gauge, Value::Gauge32(v)) | (Number::Ticks, Value::TimeTicks(v)) => {
                Some(i64::from(*v))
            }
            _ => None,
        };
        let reading = raw
            .filter(|v| (m.min..=m.max).contains(v))
            .map(|v| v as f64 * m.factor);
        add(
            &mut s,
            profile,
            m.name,
            format!("USV · {}", m.label),
            Health::Unknown,
            reading,
            Some(m.unit),
            true,
        );
    }
    for t in tables(profile)
        .into_iter()
        .filter(|t| t.name != "ups_alarms")
    {
        for (index, row) in rows(&t, data) {
            let input = t.name == "ups_input";
            for (column, value) in row {
                let (label, factor, unit, max) = match (profile, input, column) {
                    (Profile::UpsGeneric, true, 2) => ("Frequenz", 0.1, "Hz", i32::MAX),
                    (Profile::UpsGeneric, true, 3)
                    | (_, false, 2)
                    | (Profile::EatonUps, true, 2) => ("Spannung", 1.0, "V", i32::MAX),
                    (Profile::UpsGeneric, true, 4) | (Profile::UpsGeneric, false, 3) => {
                        ("Strom", 0.1, "A", i32::MAX)
                    }
                    (Profile::EatonUps, _, 3) => ("Strom", 1.0, "A", i32::MAX),
                    (Profile::UpsGeneric, true, 5)
                    | (_, false, 4)
                    | (Profile::EatonUps, true, 4) => ("Wirkleistung", 1.0, "W", i32::MAX),
                    (Profile::UpsGeneric, false, 5) => ("Auslastung", 1.0, "%", 200),
                    _ => continue,
                };
                let reading = integer(Some(&value))
                    .filter(|v| (0..=max).contains(v))
                    .map(|v| v as f64 * factor);
                let direction = if input { "Eingang" } else { "Ausgang" };
                add(
                    &mut s,
                    profile,
                    &format!("{}:{}:{column}", t.name, index[0]),
                    format!("USV · {direction} · L{} · {label}", index[0]),
                    Health::Unknown,
                    reading,
                    Some(unit),
                    true,
                );
            }
        }
    }
    (s, vec![])
}

fn alarm(profile: Profile, number: u32) -> Option<(Health, &'static str)> {
    use Health::*;
    if profile == Profile::UpsGeneric {
        Some(match number {
            1 => (Warning, "Batteriewechsel erforderlich"),
            2 => (Warning, "Batteriebetrieb"),
            3 => (Critical, "Batterie schwach"),
            4 => (Critical, "Batterie erschöpft"),
            5 => (Critical, "Temperatur außerhalb des Bereichs"),
            6 => (Warning, "Eingang gestört"),
            7 => (Critical, "Ausgang gestört"),
            8 => (Critical, "Überlast"),
            9 => (Warning, "Bypassbetrieb"),
            10 => (Warning, "Bypass gestört"),
            11 | 12 => (Warning, "Abschaltung angefordert"),
            13 => (Critical, "Ladegerät ausgefallen"),
            14 | 15 => (Critical, "Ausgang aus oder gestört"),
            16 => (Critical, "Lüfter ausgefallen"),
            17 => (Critical, "Sicherung ausgefallen"),
            18 => (Critical, "Interner Fehler"),
            19 => (Warning, "Test fehlgeschlagen"),
            20 => (Critical, "USV-Kommunikation unterbrochen"),
            21 => (Critical, "Wartet auf Netzversorgung"),
            22 => (Warning, "Abschaltung ausstehend"),
            23 => (Critical, "Abschaltung unmittelbar bevorstehend"),
            24 => (Unknown, "Test läuft"),
            _ => return None,
        })
    } else {
        Some(match number {
            3 => (Warning, "Batteriebetrieb"),
            4 => (Critical, "Batterie schwach"),
            5 | 6 | 17 => (Unknown, "Zustandsmeldung"),
            7 => (Critical, "Überlast"),
            8 | 10 | 35 | 36 => (Critical, "Interner Fehler"),
            9 => (Critical, "Batterie erschöpft"),
            11 | 44 => (Warning, "Bypassbetrieb"),
            12 => (Warning, "Bypass gestört"),
            13 | 20 | 43 => (Critical, "Ausgang aus oder gestört"),
            14 => (Warning, "Eingang gestört"),
            15 | 39 => (Warning, "Weitere Alarmbedingung"),
            16 => (Critical, "Abschaltung unmittelbar bevorstehend"),
            21 | 22 | 24 => (Warning, "Abschaltung angefordert"),
            23 => (Warning, "Batteriewechsel erforderlich"),
            25 => (Warning, "Test fehlgeschlagen"),
            26 => (Critical, "USV-Kommunikation unterbrochen"),
            27 => (Warning, "Abschaltung ausstehend"),
            28 => (Unknown, "Test läuft"),
            29 | 31 | 40 | 41 => (Critical, "Temperatur oder Feuchte außerhalb des Bereichs"),
            30 => (Warning, "Redundanz verloren"),
            32 => (Critical, "Ladegerät ausgefallen"),
            33 => (Critical, "Lüfter ausgefallen"),
            34 => (Critical, "Sicherung ausgefallen"),
            37 => (Warning, "Alternative Stromquelle aktiv"),
            38 => (Warning, "Alternative Stromquelle gestört"),
            42 => (Critical, "Ausgang gestört"),
            _ => return None,
        })
    }
}
fn aggregate(
    snapshot: &mut Snapshot,
    profile: Profile,
    name: &str,
    active: Vec<(String, Health, String)>,
    proven: bool,
) {
    let critical = active.iter().any(|(_, h, _)| *h == Health::Critical);
    let warning = active.iter().any(|(_, h, _)| *h == Health::Warning);
    let health = if critical {
        Health::Critical
    } else if !proven {
        Health::Unknown
    } else if warning {
        Health::Warning
    } else if !active.is_empty() {
        Health::Unknown
    } else {
        Health::Ok
    };
    let mut label = format!("USV · {name}");
    for (_, _, message) in &active {
        label.push_str(" · ");
        label.push_str(message);
    }
    let conditions: Vec<_> = active
        .iter()
        .filter(|(_, h, _)| matches!(h, Health::Critical | Health::Warning))
        .map(|(id, h, _)| {
            serde_json::json!([
                id,
                null,
                key(profile, "alarms"),
                if *h == Health::Critical {
                    "Critical"
                } else {
                    "Warning"
                }
            ])
            .to_string()
        })
        .collect();
    let resource = crate::correlation::Resource {
        kind: "ups".into(),
        own_health: Some(health),
        independent_condition: true,
        condition_fingerprint: serde_json::json!([null, null, conditions]).to_string(),
        ..Default::default()
    };
    snapshot.resources.insert(key(profile, "alarms"), resource);
    let count = active.len() as f64;
    add(
        snapshot,
        profile,
        "alarms",
        label,
        health,
        Some(count),
        None,
        proven && !warning && !critical && !active.is_empty(),
    );
}
fn apc_flags(snapshot: &mut Snapshot, data: &Data) {
    let Some(raw) = data.get(&oid("1.3.6.1.4.1.318.1.1.1.11.1.1.0")) else {
        return;
    };
    let flags =
        text(Some(raw)).filter(|s| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0' | b'1')));
    let Some(flags) = flags else {
        aggregate(snapshot, Profile::ApcUps, "Alarmstatus", vec![], false);
        return;
    };
    let mut active = vec![];
    let mut proven = flags.bytes().any(|b| b == b'1');
    for (i, _) in flags.bytes().enumerate().filter(|(_, b)| *b == b'1') {
        let n = i + 1;
        let (h, label) = match n {
            2 => (Health::Warning, "Batteriebetrieb"),
            3 | 30 => (Health::Critical, "Batterie schwach"),
            5 => (Health::Warning, "Batteriewechsel erforderlich"),
            9 | 54 => (Health::Critical, "Überlast"),
            11 | 40 => (Health::Critical, "Batterie erschöpft"),
            12 | 13 | 44 => (Health::Warning, "Bypassbetrieb"),
            14..=16 | 23 | 37..=39 | 42 | 43 | 48..=50 | 55 => {
                (Health::Critical, "Interner Fehler")
            }
            17 | 18 | 20 | 58 => (Health::Critical, "Ausgang aus oder gestört"),
            21 | 56 => (Health::Critical, "USV-Kommunikation unterbrochen"),
            22 | 31 | 32 => (Health::Warning, "Abschaltung ausstehend"),
            24 => (Health::Critical, "Ausgang gestört"),
            25 => (Health::Critical, "Ladegerät ausgefallen"),
            26 | 28 | 45 => (Health::Critical, "Temperatur außerhalb des Bereichs"),
            27 | 46 => (Health::Warning, "Temperaturwarnung"),
            33 => (Health::Critical, "Batterie fehlt"),
            41 => (Health::Critical, "Lüfter ausgefallen"),
            47 => (Health::Warning, "Bypass gestört"),
            53 => (Health::Critical, "Notabschaltung aktiv"),
            60 => (Health::Warning, "Weitere Alarmbedingung"),
            10 | 29 | 34..=36 => (Health::Unknown, "Test oder Steuerbefehl läuft"),
            1 | 4 | 6..=8 | 19 | 51 | 52 | 57 | 59 => continue,
            _ => {
                proven = false;
                continue;
            }
        };
        active.push((format!("apc:flag:{n}"), h, label.into()));
    }
    // The generic abnormal flag must not become a healthy aggregate even if no
    // specific documented fault bit accompanies it.
    if flags.as_bytes()[0] == b'1'
        && !active
            .iter()
            .any(|(_, h, _)| matches!(h, Health::Warning | Health::Critical))
    {
        active.push((
            "apc:abnormal".into(),
            Health::Warning,
            "Weitere Alarmbedingung".into(),
        ));
    }
    aggregate(snapshot, Profile::ApcUps, "Alarmstatus", active, proven);
}
/// Positive evidence of an empty table requires a completed walk and matching
/// typed counts read on both sides. Count/row/type mismatch cannot clear faults.
pub(super) fn finish_alarms(
    profile: Profile,
    data: &Data,
    after: Option<&Value>,
    snapshot: &mut Snapshot,
    capabilities: &mut [Capability],
) -> bool {
    if !matches!(profile, Profile::UpsGeneric | Profile::EatonUps) {
        return true;
    }
    let spec = tables(profile).remove(0);
    let count = |value: Option<&Value>| match value {
        Some(Value::Gauge32(n)) if *n <= 512 => Some(*n as usize),
        _ => None,
    };
    let before = count(data.get(&oid(alarm_count_oid(profile).unwrap())));
    let after = count(after);
    let entries = rows(&spec, data);
    let mut proven = capabilities.iter().any(|c| {
        c.uri.starts_with("snmp:ups_alarms:")
            && matches!(c.outcome.as_str(), "available" | "unsupported")
    }) && before.is_some()
        && before == after
        && before == Some(entries.len());
    let alarm_base = oid(if profile == Profile::UpsGeneric {
        "1.3.6.1.2.1.33.1.6.3"
    } else {
        "1.3.6.1.4.1.534.1.7"
    });
    let mut seen = BTreeSet::new();
    let mut active = vec![];
    for (index, row) in entries {
        if index[0] == 0 {
            proven = false;
        }
        let Some(Value::ObjectIdentifier(id)) = row.get(&2) else {
            proven = false;
            continue;
        };
        if !seen.insert(id.clone()) {
            proven = false;
            continue;
        }
        let number = id
            .arcs()
            .strip_prefix(alarm_base.arcs())
            .filter(|tail| tail.len() == 1)
            .map(|tail| tail[0]);
        let (health, label) = number
            .and_then(|n| alarm(profile, n))
            .map(|(h, s)| (h, s.to_owned()))
            .unwrap_or((Health::Warning, format!("Unbekannte Alarmbedingung · {id}")));
        active.push((id.to_string(), health, label));
    }
    active.sort_by(|a, b| a.0.cmp(&b.0));
    for c in capabilities
        .iter_mut()
        .filter(|c| c.uri.starts_with("snmp:ups_alarms:"))
    {
        if proven {
            c.outcome = "available".into();
        } else if matches!(c.outcome.as_str(), "available" | "unsupported") {
            c.outcome = if before.is_none() {
                "unsupported"
            } else {
                "snmp_invalid_response"
            }
            .into();
        }
    }
    aggregate(snapshot, profile, "Aktive Alarmbedingungen", active, proven);
    proven
}
pub(super) fn system_information(profile: Profile, data: &Data) -> BTreeMap<String, String> {
    let roots = match profile {
        Profile::UpsGeneric => vec![
            ("ups_manufacturer", "1.3.6.1.2.1.33.1.1.1.0"),
            ("ups_model", "1.3.6.1.2.1.33.1.1.2.0"),
        ],
        Profile::ApcUps => vec![("ups_model", "1.3.6.1.4.1.318.1.1.1.1.1.1.0")],
        Profile::EatonUps => vec![
            ("ups_manufacturer", "1.3.6.1.4.1.534.1.1.1.0"),
            ("ups_model", "1.3.6.1.4.1.534.1.1.2.0"),
        ],
        _ => vec![],
    };
    roots
        .into_iter()
        .filter_map(|(name, root)| text(data.get(&oid(root))).map(|v| (name.into(), v)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    fn string(s: &str) -> Value {
        Value::OctetString(Bytes::copy_from_slice(s.as_bytes()))
    }
    fn observation<'a>(s: &'a Snapshot, suffix: &str) -> &'a Observation {
        s.observations
            .iter()
            .find(|o| o.key.ends_with(&format!(":{suffix}")))
            .unwrap()
    }
    fn scan(
        profile: Profile,
        data: &Data,
        after: Option<&Value>,
        outcome: &str,
    ) -> (Snapshot, Vec<Capability>, bool) {
        let (mut s, _) = normalize(profile, data);
        let mut caps = vec![Capability {
            uri: format!("snmp:ups_alarms:{}", tables(profile)[0].entry),
            outcome: outcome.into(),
            optional: false,
            http_status: None,
            attempts: 1,
        }];
        let proof = finish_alarms(profile, data, after, &mut s, &mut caps);
        (s, caps, proof)
    }
    #[test]
    fn enum_values_are_profile_specific_and_wrong_types_never_assert_health() {
        for p in [Profile::UpsGeneric, Profile::ApcUps, Profile::EatonUps] {
            for value in [
                None,
                Some(Value::Gauge32(3)),
                Some(Value::Integer(0)),
                Some(Value::Integer(99)),
            ] {
                assert_eq!(enum_status(p, "output", value.as_ref()).0, Health::Unknown);
            }
        }
        let state = |p, n, v| enum_status(p, n, Some(&Value::Integer(v))).0;
        assert_eq!(state(Profile::ApcUps, "output", 2), Health::Ok);
        assert_eq!(state(Profile::UpsGeneric, "output", 2), Health::Critical);
        for p in [Profile::UpsGeneric, Profile::EatonUps] {
            assert_eq!(state(p, "output", 3), Health::Ok);
            assert_eq!(state(p, "output", 5), Health::Warning);
            assert_eq!(state(p, "output", 4), Health::Warning);
        }
        assert_eq!(state(Profile::UpsGeneric, "output", 12), Health::Unknown);
        assert_eq!(state(Profile::EatonUps, "output", 12), Health::Ok);
        for v in [3, 4, 5] {
            assert_eq!(state(Profile::ApcUps, "battery", v), Health::Critical);
        }
        assert_eq!(state(Profile::EatonUps, "abm", 4), Health::Ok);
        assert_eq!(state(Profile::EatonUps, "abm", 6), Health::Critical);
        assert_eq!(state(Profile::EatonUps, "abm", 7), Health::Unknown);
        assert_eq!(state(Profile::EatonUps, "abm", 8), Health::Warning);
        for p in [Profile::UpsGeneric, Profile::ApcUps, Profile::EatonUps] {
            let (s, _) = normalize(p, &Data::new());
            assert!(s.observations.iter().all(|o| o.health == Health::Unknown));
            assert!(s.assessment_exclusions.is_empty());
        }
    }
    #[test]
    fn measurement_types_units_and_vendor_sentinels_are_preserved() {
        let mut d = Data::new();
        d.insert(
            oid("1.3.6.1.4.1.318.1.1.1.2.2.3.0"),
            Value::TimeTicks(12345),
        );
        d.insert(oid("1.3.6.1.4.1.318.1.1.1.2.2.2.0"), Value::Gauge32(255));
        d.insert(oid("1.3.6.1.4.1.318.1.1.1.2.2.1.0"), Value::Gauge32(101));
        let (s, _) = normalize(Profile::ApcUps, &d);
        assert_eq!(observation(&s, "runtime").reading, Some(123.45));
        assert_eq!(observation(&s, "runtime").unit.as_deref(), Some("s"));
        assert_eq!(observation(&s, "temperature").reading, None);
        assert_eq!(observation(&s, "charge").reading, None);
        d.insert(
            oid("1.3.6.1.4.1.318.1.1.1.2.2.3.0"),
            Value::TimeTicks(u32::MAX),
        );
        let (s, _) = normalize(Profile::ApcUps, &d);
        assert_eq!(observation(&s, "runtime").reading, None);
        d.clear();
        d.insert(oid("1.3.6.1.2.1.33.1.2.5.0"), Value::Integer(133));
        d.insert(oid("1.3.6.1.2.1.33.1.2.6.0"), Value::Integer(-42));
        d.insert(oid("1.3.6.1.2.1.33.1.2.3.0"), Value::Integer(12));
        let (s, _) = normalize(Profile::UpsGeneric, &d);
        assert_eq!(observation(&s, "battery_voltage").reading, Some(13.3));
        assert_eq!(observation(&s, "battery_current").reading, Some(-4.2));
        assert_eq!(observation(&s, "runtime").unit.as_deref(), Some("min"));
        d.clear();
        d.insert(oid("1.3.6.1.4.1.534.1.2.2.0"), Value::Integer(48));
        d.insert(oid("1.3.6.1.4.1.534.1.2.3.0"), Value::Integer(-2));
        let (s, _) = normalize(Profile::EatonUps, &d);
        assert_eq!(observation(&s, "battery_voltage").reading, Some(48.0));
        assert_eq!(observation(&s, "battery_current").reading, Some(-2.0));
    }
    #[test]
    fn empty_alarm_table_requires_completed_walk_and_consistent_gauge_counts() {
        for p in [Profile::UpsGeneric, Profile::EatonUps] {
            let mut d = Data::new();
            let root = oid(alarm_count_oid(p).unwrap());
            for before in [
                None,
                Some(Value::Integer(0)),
                Some(Value::Gauge32(1)),
                Some(Value::Gauge32(513)),
            ] {
                d.clear();
                if let Some(v) = before {
                    d.insert(root.clone(), v);
                }
                let (s, _, proof) = scan(p, &d, Some(&Value::Gauge32(0)), "unsupported");
                assert!(!proof);
                assert_eq!(observation(&s, "alarms").health, Health::Unknown);
            }
            d.insert(root, Value::Gauge32(0));
            for (after, outcome) in [
                (None, "unsupported"),
                (Some(Value::Gauge32(1)), "unsupported"),
                (Some(Value::Gauge32(0)), "snmp_deadline"),
            ] {
                let (s, _, proof) = scan(p, &d, after.as_ref(), outcome);
                assert!(!proof);
                assert_eq!(observation(&s, "alarms").health, Health::Unknown);
            }
            let (s, caps, proof) = scan(p, &d, Some(&Value::Gauge32(0)), "unsupported");
            assert!(proof);
            assert_eq!(observation(&s, "alarms").health, Health::Ok);
            assert_eq!(caps[0].outcome, "available");
        }
    }
    #[test]
    fn sparse_alarm_rows_use_condition_oids_not_recycled_indices() {
        for p in [Profile::UpsGeneric, Profile::EatonUps] {
            let mut d = Data::new();
            let count_root = oid(alarm_count_oid(p).unwrap());
            d.insert(count_root.clone(), Value::Gauge32(1));
            let table = tables(p).remove(0);
            let condition = if p == Profile::UpsGeneric {
                "1.3.6.1.2.1.33.1.6.3.8"
            } else {
                "1.3.6.1.4.1.534.1.7.7"
            };
            d.insert(
                oid(&format!("{}.2.17", table.entry)),
                Value::ObjectIdentifier(oid(condition)),
            );
            let (a, _, proof) = scan(p, &d, Some(&Value::Gauge32(1)), "available");
            assert!(proof);
            assert_eq!(observation(&a, "alarms").health, Health::Critical);
            d.remove(&oid(&format!("{}.2.17", table.entry)));
            d.insert(
                oid(&format!("{}.2.29", table.entry)),
                Value::ObjectIdentifier(oid(condition)),
            );
            let (b, _, _) = scan(p, &d, Some(&Value::Gauge32(1)), "available");
            assert_eq!(
                a.resources[&key(p, "alarms")].condition_fingerprint,
                b.resources[&key(p, "alarms")].condition_fingerprint
            );
            // Duplicate descriptors, type errors, truncated walks and count races
            // never turn a partial table into a healthy/recovered summary.
            d.insert(
                oid(&format!("{}.2.30", table.entry)),
                Value::ObjectIdentifier(oid(condition)),
            );
            d.insert(count_root.clone(), Value::Gauge32(2));
            let (s, _, proof) = scan(p, &d, Some(&Value::Gauge32(2)), "available");
            assert!(!proof);
            assert_eq!(observation(&s, "alarms").health, Health::Critical);
            d.clear();
            d.insert(count_root.clone(), Value::Gauge32(1));
            d.insert(oid(&format!("{}.2.17", table.entry)), Value::Integer(8));
            let (s, _, proof) = scan(p, &d, Some(&Value::Gauge32(1)), "available");
            assert!(!proof);
            assert_eq!(observation(&s, "alarms").health, Health::Unknown);
            d.insert(
                oid(&format!("{}.2.17", table.entry)),
                Value::ObjectIdentifier(oid("1.3.6.1.4.1.999.42")),
            );
            let (s, _, proof) = scan(p, &d, Some(&Value::Gauge32(1)), "available");
            assert!(proof);
            assert_eq!(observation(&s, "alarms").health, Health::Warning);
            let (s, _, proof) = scan(p, &d, Some(&Value::Gauge32(2)), "available");
            assert!(!proof);
            assert_eq!(observation(&s, "alarms").health, Health::Unknown);
            d.clear();
            d.insert(count_root, Value::Gauge32(0));
            let (s, _, proof) = scan(p, &d, Some(&Value::Gauge32(0)), "unsupported");
            assert!(proof);
            assert_eq!(observation(&s, "alarms").health, Health::Ok);
        }
    }
    #[test]
    fn apc_ascii_flags_are_left_to_right_and_unknown_or_reserved_flags_cannot_clear() {
        let root = oid("1.3.6.1.4.1.318.1.1.1.11.1.1.0");
        let mut d = Data::new();
        for value in [
            string("UNKNOWN"),
            string(&"0".repeat(64)),
            string(&"1".repeat(63)),
            Value::Integer(0),
        ] {
            d.insert(root.clone(), value);
            let (s, _) = normalize(Profile::ApcUps, &d);
            assert_eq!(observation(&s, "alarms").health, Health::Unknown);
        }
        let mut flags = [b'0'; 64];
        flags[3] = b'1';
        flags[5] = b'1';
        d.insert(root.clone(), string(std::str::from_utf8(&flags).unwrap()));
        let (s, _) = normalize(Profile::ApcUps, &d);
        assert_eq!(observation(&s, "alarms").health, Health::Ok);
        flags[8] = b'1';
        d.insert(root.clone(), string(std::str::from_utf8(&flags).unwrap()));
        let (s, _) = normalize(Profile::ApcUps, &d);
        assert_eq!(observation(&s, "alarms").health, Health::Critical);
        assert!(observation(&s, "alarms").label.contains("Überlast"));
        flags[8] = b'0';
        flags[60] = b'1';
        d.insert(root.clone(), string(std::str::from_utf8(&flags).unwrap()));
        let (s, _) = normalize(Profile::ApcUps, &d);
        assert_eq!(observation(&s, "alarms").health, Health::Unknown);
        flags[60] = b'0';
        flags[0] = b'1';
        d.insert(root, string(std::str::from_utf8(&flags).unwrap()));
        let (s, _) = normalize(Profile::ApcUps, &d);
        assert_eq!(observation(&s, "alarms").health, Health::Warning);
    }
    #[test]
    fn phase_measurements_join_full_sparse_indices_and_remain_informational() {
        let mut d = Data::new();
        for (col, index, value) in [(2, 1, 230), (3, 1, 125), (2, 3, 231), (3, 3, 80)] {
            d.insert(
                oid(&format!("1.3.6.1.2.1.33.1.4.4.1.{col}.{index}")),
                Value::Integer(value),
            );
        }
        d.insert(oid("1.3.6.1.2.1.33.1.4.4.1.2.1.1"), Value::Integer(999));
        let (s, _) = normalize(Profile::UpsGeneric, &d);
        let values: Vec<_> = s
            .observations
            .iter()
            .filter(|o| o.key.contains(":ups_output:"))
            .collect();
        assert_eq!(values.len(), 4);
        assert_eq!(observation(&s, "ups_output:1:3").reading, Some(12.5));
        assert_eq!(observation(&s, "ups_output:3:3").reading, Some(8.0));
        assert!(values
            .iter()
            .all(|o| s.assessment_exclusions.contains_key(&o.key)));
    }
    #[test]
    fn stored_alarm_acknowledgement_tracks_conditions_and_only_proven_empty_recovers() {
        use crate::{model::Device, store::Store};
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(directory.path()).unwrap();
        let device:Device=serde_json::from_value(serde_json::json!({"id":"ups-test","name":"UPS test","endpoint":"https://example.invalid/","username":"monitor","interval_seconds":60,"alerts_enabled":true})).unwrap();
        store.put(&device, b"synthetic-sealed").unwrap();
        let profile = Profile::UpsGeneric;
        let k = key(profile, "alarms");
        let now = crate::now();
        let mut data = Data::new();
        data.insert(oid(alarm_count_oid(profile).unwrap()), Value::Gauge32(1));
        let entry = oid("1.3.6.1.2.1.33.1.6.2.1.2.17");
        data.insert(
            entry.clone(),
            Value::ObjectIdentifier(oid("1.3.6.1.2.1.33.1.6.3.8")),
        );
        let (a, _, _) = scan(profile, &data, Some(&Value::Gauge32(1)), "available");
        store.apply(&device, &a, now).unwrap();
        let evaluation = crate::acknowledgement::evaluate(&store.0, &device.id, Some(&a)).unwrap();
        let token = &evaluation.statuses[&k].token;
        store
            .acknowledge_alarm(&device.id, 1, &k, token, true, "reviewed", "admin", now)
            .unwrap();
        assert_eq!(
            crate::acknowledgement::evaluate(&store.0, &device.id, Some(&a))
                .unwrap()
                .statuses[&k]
                .status,
            "acknowledged"
        );
        data.insert(
            entry.clone(),
            Value::ObjectIdentifier(oid("1.3.6.1.2.1.33.1.6.3.13")),
        );
        let (b, _, _) = scan(profile, &data, Some(&Value::Gauge32(1)), "available");
        store.apply(&device, &b, now + 1).unwrap();
        assert_eq!(
            crate::acknowledgement::evaluate(&store.0, &device.id, Some(&b))
                .unwrap()
                .statuses[&k]
                .status,
            "critical"
        );
        data.remove(&entry);
        let (partial, _, _) = scan(profile, &data, None, "unsupported");
        store.apply(&device, &partial, now + 2).unwrap();
        assert_eq!(
            crate::acknowledgement::evaluate(&store.0, &device.id, Some(&partial))
                .unwrap()
                .statuses[&k]
                .status,
            "critical"
        );
        data.insert(oid(alarm_count_oid(profile).unwrap()), Value::Gauge32(0));
        let (clear, _, _) = scan(profile, &data, Some(&Value::Gauge32(0)), "unsupported");
        store.apply(&device, &clear, now + 3).unwrap();
        assert!(
            !crate::acknowledgement::evaluate(&store.0, &device.id, Some(&clear))
                .unwrap()
                .statuses
                .contains_key(&k)
        );
        let recovered: i64 = store
            .0
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind='recovery' AND key=?1",
                [&k],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recovered, 1);
        assert_eq!(
            crate::i18n::label(
                "USV · Batteriefehler · Batterie schwach",
                crate::i18n::Language::En
            ),
            "UPS · Battery fault · Low battery"
        );
    }
}

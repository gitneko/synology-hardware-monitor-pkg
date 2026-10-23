//! Small numeric notification allowlist, checked against the P2 vendor sources.
//! Message IDs identify conditions, never unique event occurrences.
use super::config::Profile;
use crate::model::Health;
use async_snmp::{Oid, Value, VarBind};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Fault,
    Recovery,
    Test,
    Unknown,
    UnsupportedPet,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Fqdd {
        value: String,
    },
    Serial {
        value: String,
        chassis: u32,
        locator: String,
    },
    Index {
        locator: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub class: Class,
    pub health: Health,
    pub component_kind: String,
    pub identity: Option<Identity>,
    pub condition: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<crate::model::Occurrence>,
}

fn text(v: &Value) -> Option<String> {
    let Value::OctetString(bytes) = v else {
        return None;
    };
    let raw = std::str::from_utf8(bytes).ok()?;
    (raw.len() <= 1024).then(|| raw.to_owned())
}
fn number(v: &Value) -> Option<u32> {
    match v {
        Value::Integer(n) if *n >= 0 => Some(*n as u32),
        _ => None,
    }
}
fn exact<'a>(vars: &'a [VarBind], root: &str) -> Option<&'a Value> {
    let oid: Oid = root.parse().ok()?;
    let mut matches = vars.iter().filter(|v| v.oid == oid);
    let v = &matches.next()?.value;
    if matches.next().is_some() {
        None
    } else {
        Some(v)
    }
}
fn column_number(vars: &[VarBind], root: &str) -> Option<u32> {
    let oid: Oid = root.parse().ok()?;
    let mut values = vars.iter().filter(|v| v.oid.arcs().starts_with(oid.arcs()));
    let n = number(&values.next()?.value)?;
    if values.next().is_some() {
        None
    } else {
        Some(n)
    }
}
fn column_text(vars: &[VarBind], root: &str) -> Option<String> {
    let oid: Oid = root.parse().ok()?;
    let mut values = vars.iter().filter(|v| v.oid.arcs().starts_with(oid.arcs()));
    let s = text(&values.next()?.value)?;
    if values.next().is_some() {
        None
    } else {
        Some(s)
    }
}
pub fn normalize(profile: Profile, oid: &Oid, vars: &[VarBind]) -> Event {
    let mut event = Event {
        class: Class::Unknown,
        health: Health::Unknown,
        component_kind: String::new(),
        identity: None,
        condition: {
            let text = oid.to_string();
            if text.len() <= 256 {
                text
            } else {
                use sha2::{Digest, Sha256};
                format!(
                    "oid:{}",
                    super::notifications::hex(&Sha256::digest(text.as_bytes()))
                )
            }
        },
        message: format!("SNMP · {oid}").chars().take(256).collect(),
        occurrence: None,
    };
    if oid.arcs().starts_with(&[1, 3, 6, 1, 4, 1, 3183, 1, 1]) {
        event.class = Class::UnsupportedPet;
        return event;
    }
    if oid.to_string() == "1.3.6.1.6.3.1.1.5.1" {
        return event;
    }
    if profile == Profile::DellIdrac {
        if oid.to_string() == "1.3.6.1.4.1.674.10892.5.3.2.5.0.10395" {
            event.class = Class::Test;
            return event;
        }
        let arcs = oid.arcs();
        let prefix = [1, 3, 6, 1, 4, 1, 674, 10892, 5, 3, 2, 1, 0];
        if arcs.len() != prefix.len() + 1 || !arcs.starts_with(&prefix) {
            return event;
        }
        let (kind, health, class) = match arcs[prefix.len()] {
            2153 => ("fan", Health::Critical, Class::Fault),
            2154 => ("fan", Health::Warning, Class::Fault),
            2155 => ("fan", Health::Unknown, Class::Recovery),
            2161 => ("temperature", Health::Critical, Class::Fault),
            2162 => ("temperature", Health::Warning, Class::Fault),
            2163 => ("temperature", Health::Unknown, Class::Recovery),
            2185 => ("power_supply", Health::Critical, Class::Fault),
            2186 => ("power_supply", Health::Warning, Class::Fault),
            2187 => ("power_supply", Health::Unknown, Class::Recovery),
            2265 => ("memory", Health::Critical, Class::Fault),
            2266 => ("memory", Health::Warning, Class::Fault),
            2267 => ("memory", Health::Unknown, Class::Recovery),
            2297 => ("physical_disk", Health::Critical, Class::Fault),
            2298 => ("physical_disk", Health::Warning, Class::Fault),
            2299 => ("physical_disk", Health::Unknown, Class::Recovery),
            _ => return event,
        };
        event.class = class;
        event.health = health;
        event.component_kind = kind.into();
        event.condition = format!("dell:{kind}");
        if let Some(id) = exact(vars, "1.3.6.1.4.1.674.10892.5.3.1.1.0")
            .and_then(text)
            .filter(|s| {
                !s.is_empty() && s.len() <= 8 && s.bytes().all(|c| c.is_ascii_alphanumeric())
            })
        {
            event.condition = format!("dell:{id}");
        }
        event.identity = exact(vars, "1.3.6.1.4.1.674.10892.5.3.1.6.0")
            .and_then(text)
            .filter(|s| crate::identity::valid_reported_identifier(s))
            .map(|value| Identity::Fqdd { value });
        if let Some(message) = exact(vars, "1.3.6.1.4.1.674.10892.5.3.1.2.0")
            .and_then(text)
            .filter(|s| !s.is_empty())
        {
            let sanitized: String = message
                .chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect();
            if !sanitized.is_empty() {
                event.message = sanitized;
            }
        }
    } else if profile == Profile::HpeIlo5 {
        let arcs = oid.arcs();
        let prefix = [1, 3, 6, 1, 4, 1, 232, 0];
        if arcs.len() != prefix.len() + 1 || !arcs.starts_with(&prefix) {
            return event;
        }
        let (kind, health, class, root) = match arcs[prefix.len()] {
            6035 | 6036 => (
                "fan",
                Health::Critical,
                Class::Fault,
                "1.3.6.1.4.1.232.6.2.6.7.1",
            ),
            6038 => (
                "fan",
                Health::Unknown,
                Class::Recovery,
                "1.3.6.1.4.1.232.6.2.6.7.1",
            ),
            6049 | 6050 => (
                "power_supply",
                Health::Critical,
                Class::Fault,
                "1.3.6.1.4.1.232.6.2.9.3.1",
            ),
            6048 => (
                "power_supply",
                Health::Unknown,
                Class::Recovery,
                "1.3.6.1.4.1.232.6.2.9.3.1",
            ),
            _ => return event,
        };
        event.class = class;
        event.health = health;
        event.component_kind = kind.into();
        event.condition = format!("hpe:{kind}");
        if let (Some(chassis), Some(index)) = (
            column_number(vars, &format!("{root}.1")),
            column_number(vars, &format!("{root}.2")),
        ) {
            let locator = format!("{root}.{chassis}.{index}");
            event.identity = if kind == "power_supply" {
                column_text(vars, &format!("{root}.11"))
                    .filter(|s| crate::identity::valid_reported_identifier(s))
                    .map(|value| Identity::Serial {
                        value,
                        chassis,
                        locator: locator.clone(),
                    })
            } else {
                None
            }
            .or(Some(Identity::Index { locator }));
        }
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    fn strvar(oid: &str, value: &str) -> VarBind {
        VarBind::new(
            oid.parse().unwrap(),
            Value::OctetString(bytes::Bytes::copy_from_slice(value.as_bytes())),
        )
    }
    fn intvar(oid: &str, value: i32) -> VarBind {
        VarBind::new(oid.parse().unwrap(), Value::Integer(value))
    }
    #[test]
    fn dell_exact_subtree_fqdd_condition_and_test_are_not_guessed() {
        let oid: Oid = "1.3.6.1.4.1.674.10892.5.3.2.1.0.2153".parse().unwrap();
        let vars = vec![
            strvar("1.3.6.1.4.1.674.10892.5.3.1.6.0", "Fan.Embedded.1"),
            strvar("1.3.6.1.4.1.674.10892.5.3.1.1.0", "FAN0001"),
        ];
        let event = normalize(Profile::DellIdrac, &oid, &vars);
        assert_eq!(event.class, Class::Fault);
        assert_eq!(event.health, Health::Critical);
        assert_eq!(event.condition, "dell:FAN0001");
        assert!(event.occurrence.is_none());
        assert_eq!(
            normalize(Profile::Generic, &oid, &vars).class,
            Class::Unknown
        );
        for wrong in [
            "1.3.6.1.4.1.674.10892.5.3.2.0.2153",
            "1.3.6.1.4.1.674.10892.5.3.2.5.0.2153",
        ] {
            assert_eq!(
                normalize(Profile::DellIdrac, &wrong.parse().unwrap(), &vars).class,
                Class::Unknown
            );
        }
        assert_eq!(
            normalize(
                Profile::DellIdrac,
                &"1.3.6.1.4.1.674.10892.5.3.2.5.0.10395".parse().unwrap(),
                &vars
            )
            .class,
            Class::Test
        );
        let mut duplicate = vars.clone();
        duplicate.push(vars[0].clone());
        assert!(normalize(Profile::DellIdrac, &oid, &duplicate)
            .identity
            .is_none());
        assert!(normalize(
            Profile::DellIdrac,
            &oid,
            &[strvar(
                "1.3.6.1.4.1.674.10892.5.3.1.6.0",
                "Fan.\nEmbedded.1"
            )]
        )
        .identity
        .is_none());
    }
    #[test]
    fn hpe_fan_indices_and_psu_serial_are_distinct_scoped_inputs() {
        let vars = [
            intvar("1.3.6.1.4.1.232.6.2.6.7.1.1.1.2", 1),
            intvar("1.3.6.1.4.1.232.6.2.6.7.1.2.1.2", 2),
        ];
        let fan = normalize(
            Profile::HpeIlo5,
            &"1.3.6.1.4.1.232.0.6035".parse().unwrap(),
            &vars,
        );
        assert_eq!(fan.health, Health::Critical);
        assert_eq!(
            fan.identity,
            Some(Identity::Index {
                locator: "1.3.6.1.4.1.232.6.2.6.7.1.1.2".into()
            })
        );
        let vars = [
            intvar("1.3.6.1.4.1.232.6.2.9.3.1.1.1.2", 1),
            intvar("1.3.6.1.4.1.232.6.2.9.3.1.2.1.2", 2),
            strvar("1.3.6.1.4.1.232.6.2.9.3.1.11.1.2", "Synthetic-serial"),
        ];
        let psu = normalize(
            Profile::HpeIlo5,
            &"1.3.6.1.4.1.232.0.6049".parse().unwrap(),
            &vars,
        );
        assert!(matches!(
            psu.identity,
            Some(Identity::Serial { chassis: 1, .. })
        ));
        assert_eq!(
            normalize(
                Profile::HpeIlo5,
                &"1.3.6.1.4.1.232.0.6048".parse().unwrap(),
                &vars
            )
            .class,
            Class::Recovery
        );
    }
    #[test]
    fn pet_is_unsupported_and_normal_state_never_means_direct_recovery() {
        assert_eq!(
            normalize(
                Profile::DellIdrac,
                &"1.3.6.1.4.1.3183.1.1.0.1".parse().unwrap(),
                &[]
            )
            .class,
            Class::UnsupportedPet
        );
        let normal = normalize(
            Profile::DellIdrac,
            &"1.3.6.1.4.1.674.10892.5.3.2.1.0.2187".parse().unwrap(),
            &[],
        );
        assert_eq!(normal.class, Class::Recovery);
        assert_eq!(normal.health, Health::Unknown);
    }

    #[test]
    fn seeded_profile_corpus_cannot_invent_identity_or_unbounded_event_text() {
        use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
        let dell = "1.3.6.1.4.1.674.10892.5.3.2.1.0.2153".parse().unwrap();
        let hpe = "1.3.6.1.4.1.232.0.6049".parse().unwrap();
        let mut rng = StdRng::seed_from_u64(0x9050);
        for index in 0..1000 {
            let mut bytes = vec![0; rng.gen_range(0..1500)];
            rng.fill_bytes(&mut bytes);
            if index % 3 == 0 {
                bytes = "Synthetic\0\n<fan>測"
                    .repeat(rng.gen_range(0..100))
                    .into_bytes();
            }
            let value = if index % 3 == 1 {
                Value::Integer(rng.gen())
            } else {
                Value::OctetString(bytes.into())
            };
            let duplicate = strvar("1.3.6.1.4.1.674.10892.5.3.1.6.0", "Fan.Embedded.1");
            let vars = vec![
                duplicate.clone(),
                duplicate,
                VarBind::new(
                    "1.3.6.1.4.1.674.10892.5.3.1.2.0".parse().unwrap(),
                    value.clone(),
                ),
                VarBind::new("1.3.6.1.4.1.674.10892.5.3.1.1.0".parse().unwrap(), value),
                intvar("1.3.6.1.4.1.232.6.2.9.3.1.1.0", 1),
                intvar("1.3.6.1.4.1.232.6.2.9.3.1.1.0", 1),
                intvar("1.3.6.1.4.1.232.6.2.9.3.1.2.0", rng.gen()),
            ];
            for (profile, oid) in [(Profile::DellIdrac, &dell), (Profile::HpeIlo5, &hpe)] {
                let event = normalize(profile, oid, &vars);
                assert!(
                    event.identity.is_none(),
                    "duplicate aliases are not identity proof"
                );
                assert!(event.occurrence.is_none());
                assert!(!event.message.is_empty() && event.message.chars().count() <= 256);
                assert!(!event.message.chars().any(char::is_control));
                assert!(event.condition.len() <= 256);
                assert!(serde_json::to_vec(&event).unwrap().len() <= 4096);
            }
            let generic = normalize(Profile::Generic, &dell, &vars);
            assert_eq!(generic.class, Class::Unknown);
            assert_eq!(generic.health, Health::Unknown);
        }
    }
}

/// Bounded transport deduplication. A known fault/recovery/fault sequence must
/// survive even when a sender reuses uptime and the original wire payload.
#[derive(Default)]
pub(crate) struct Duplicates {
    entries: std::collections::HashMap<String, (std::time::Instant, Option<String>)>,
    phases: std::collections::HashMap<String, (Class, std::time::Instant)>,
}
impl Duplicates {
    fn flow(device: &str, r: &super::records::Receipt) -> Option<(String, Class)> {
        use sha2::{Digest, Sha256};
        let e = r.event.as_ref()?;
        if !matches!(e.class, Class::Fault | Class::Recovery) {
            return None;
        }
        let identity = e.identity.as_ref()?;
        let bytes = serde_json::to_vec(&(
            device,
            &r.version,
            &r.engine_id,
            r.engine_boots,
            &e.component_kind,
            identity,
        ))
        .ok()?;
        Some((
            super::notifications::hex(&Sha256::digest(bytes)),
            e.class.clone(),
        ))
    }
    pub fn contains(&self, device: &str, r: &super::records::Receipt) -> bool {
        if let Some((flow, class)) = Self::flow(device, r) {
            if self.phases.get(&flow).is_some_and(|(old, _)| *old != class) {
                return false;
            }
        }
        self.entries
            .get(&r.fingerprint)
            .is_some_and(|(at, _)| at.elapsed() < std::time::Duration::from_secs(30))
    }
    pub fn insert(&mut self, device: &str, r: &super::records::Receipt) {
        self.prune();
        let now = std::time::Instant::now();
        let phase = Self::flow(device, r);
        if let Some((flow, class)) = &phase {
            if self.phases.get(flow).is_some_and(|(old, _)| old != class) {
                self.entries.retain(|_, (_, id)| id.as_ref() != Some(flow));
            }
            if self.phases.len() >= 4096 {
                if let Some(key) = self
                    .phases
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(k, _)| k.clone())
                {
                    self.phases.remove(&key);
                }
            }
            self.phases.insert(flow.clone(), (class.clone(), now));
        }
        if self.entries.len() >= 4096 {
            if let Some(key) = self
                .entries
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&key);
            }
        }
        self.entries
            .insert(r.fingerprint.clone(), (now, phase.map(|(flow, _)| flow)));
    }
    pub fn prune(&mut self) {
        self.entries
            .retain(|_, (at, _)| at.elapsed() < std::time::Duration::from_secs(30));
        self.phases
            .retain(|_, (_, at)| at.elapsed() < std::time::Duration::from_secs(30));
    }
    pub fn clear(&mut self) {
        self.entries.clear();
        self.phases.clear();
    }
}

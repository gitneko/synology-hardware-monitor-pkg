//! Correlate legacy/modern power supply representations by chassis and serial.
//! Names, array positions, models and part numbers are never identity evidence.
use crate::model::{Health, Observation};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn valid_reported_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && value
            .chars()
            .any(|c| c != '0' && c != '-' && !c.is_whitespace())
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "n/a"
                | "na"
                | "none"
                | "unknown"
                | "not available"
                | "not specified"
                | "unspecified"
                | "not present"
        )
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Component {
    pub key: String,
    pub locator: String,
    pub aliases: Vec<String>,
}
/// Only explicit Dell FQDD fields are aliases; MemberId/name/array indices
/// are never promoted to a cross-protocol physical identity.
#[derive(Default)]
pub(crate) struct TrapIdentities(BTreeMap<String, Component>);
impl TrapIdentities {
    pub fn observe(&mut self, fallback: &str, value: &Value) {
        if value.get("Message").is_some() {
            return;
        }
        let key = value
            .get("@odata.id")
            .and_then(Value::as_str)
            .unwrap_or(fallback);
        fn fqdds(v: &Value, out: &mut Vec<String>, depth: u8) {
            if depth > 8 {
                return;
            }
            if let Some(m) = v.as_object() {
                for (k, v) in m {
                    if k == "FQDD" {
                        if let Some(s) = v.as_str().filter(|s| valid_reported_identifier(s)) {
                            out.push(s.into());
                        }
                    } else {
                        fqdds(v, out, depth + 1);
                    }
                }
            }
        }
        let mut aliases = Vec::new();
        if let Some(oem) = value.pointer("/Oem/Dell") {
            fqdds(oem, &mut aliases, 0);
        }
        aliases.sort();
        aliases.dedup();
        aliases.truncate(4);
        if !aliases.is_empty()
            && key.starts_with("/redfish/v1/")
            && key.len() <= 1024
            && self.0.len() < 4096
        {
            self.0.insert(
                key.into(),
                Component {
                    key: key.into(),
                    locator: key.into(),
                    aliases,
                },
            );
        }
        for name in [
            "PowerSupplies",
            "Fans",
            "Temperatures",
            "Memory",
            "Drives",
            "StorageControllers",
            "Members",
        ] {
            if let Some(items) = value.get(name).and_then(Value::as_array) {
                for (i, item) in items.iter().enumerate() {
                    self.observe(&crate::correlation::embedded_uri(key, name, item, i), item);
                }
            }
        }
    }
    pub fn finish(self, canonical: &BTreeMap<String, String>) -> Vec<Component> {
        self.0
            .into_values()
            .map(|mut c| {
                if let Some(key) = canonical.get(&c.key) {
                    c.key = key.clone();
                }
                c
            })
            .collect()
    }
}

#[derive(Default)]
pub struct PsuIdentities(BTreeMap<(String, String), BTreeMap<String, bool>>);
pub(crate) fn severity(health: Health) -> u8 {
    match health {
        Health::Critical => 3,
        Health::Warning => 2,
        Health::Ok => 1,
        Health::Unknown => 0,
    }
}
impl PsuIdentities {
    pub fn observe(&mut self, fallback: &str, value: &Value) {
        let key = value
            .get("@odata.id")
            .and_then(Value::as_str)
            .unwrap_or(fallback);
        let kind = value
            .get("@odata.type")
            .and_then(Value::as_str)
            .unwrap_or("");
        let modern = kind.starts_with("#PowerSupply.");
        let legacy = kind.starts_with("#Power.") && kind.ends_with(".PowerSupply");
        if modern || legacy {
            let base = key.split('#').next().unwrap_or(key);
            let parts: Vec<_> = base.trim_start_matches('/').split('/').collect();
            let serial = value
                .get("SerialNumber")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let lower = serial.to_ascii_lowercase();
            let valid = !serial.is_empty()
                && serial.len() <= 256
                && !serial.chars().any(char::is_control)
                && ![
                    "n/a",
                    "na",
                    "none",
                    "unknown",
                    "not available",
                    "not specified",
                    "unspecified",
                ]
                .contains(&lower.as_str())
                && serial.chars().any(|c| c != '0' && !c.is_whitespace());
            if valid
                && parts.len() >= 5
                && parts[..3] == ["redfish", "v1", "Chassis"]
                && matches!(parts[4], "Power" | "PowerSubsystem")
            {
                self.0
                    .entry((parts[..4].join("/"), serial.into()))
                    .or_default()
                    .insert(key.into(), modern);
            }
        }
        for name in ["PowerSupplies", "Members"] {
            if let Some(array) = value.get(name).and_then(Value::as_array) {
                for (index, item) in array.iter().enumerate() {
                    let member = item
                        .get("MemberId")
                        .or_else(|| item.get("Id"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| index.to_string());
                    self.observe(&format!("{fallback}#{name}:{member}"), item);
                }
            }
        }
    }
    pub fn merge(
        self,
        observations: &mut BTreeMap<String, Observation>,
    ) -> BTreeMap<String, String> {
        let mut aliases = BTreeMap::new();
        for candidates in self.0.into_values() {
            let modern: Vec<_> = candidates
                .iter()
                .filter(|(_, modern)| **modern)
                .map(|(key, _)| key)
                .collect();
            let legacy: Vec<_> = candidates
                .iter()
                .filter(|(_, modern)| !**modern)
                .map(|(key, _)| key)
                .collect();
            // Reject ambiguous serials, even if names/status happen to match.
            if modern.len() != 1 || legacy.len() != 1 {
                continue;
            }
            let canonical = modern[0];
            let alias = legacy[0];
            if !observations.contains_key(canonical) || !observations.contains_key(alias) {
                continue;
            }
            let old = observations.remove(alias).expect("checked alias");
            let current = observations.get_mut(canonical).expect("checked canonical");
            if severity(old.health) > severity(current.health) {
                current.health = old.health;
                current.reading = old.reading;
                current.unit = old.unit;
            } else if current.health == old.health && current.reading.is_none() {
                current.reading = old.reading;
                current.unit = old.unit;
            }
            aliases.insert(alias.clone(), canonical.clone());
        }
        aliases
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn source(modern: bool, slot: &str, serial: &str) -> (String, Value) {
        let path = if modern {
            format!("/redfish/v1/Chassis/Test/PowerSubsystem/PowerSupplies/{slot}")
        } else {
            format!("/redfish/v1/Chassis/Test/Power#/PowerSupplies/{slot}")
        };
        let kind = if modern {
            "#PowerSupply.v1_5_0.PowerSupply"
        } else {
            "#Power.v1_7_1.PowerSupply"
        };
        (
            path.clone(),
            json!({"@odata.id":path,"@odata.type":kind,"SerialNumber":serial,"Name":"Same name"}),
        )
    }
    fn observation(key: &str, h: Health) -> Observation {
        Observation {
            key: key.into(),
            label: "Same name".into(),
            health: h,
            reading: None,
            unit: None,
        }
    }
    #[test]
    fn proven_psu_aliases_merge_and_preserve_faults_in_either_direction() {
        for (legacy, modern) in [
            (Health::Critical, Health::Ok),
            (Health::Ok, Health::Critical),
            (Health::Warning, Health::Unknown),
        ] {
            let (old, a) = source(false, "0", "synthetic-serial-1");
            let (new, b) = source(true, "Slot.1", "synthetic-serial-1");
            let mut identities = PsuIdentities::default();
            identities.observe(&old, &a);
            identities.observe(&new, &b);
            let mut observations = BTreeMap::from([
                (old.clone(), observation(&old, legacy)),
                (new.clone(), observation(&new, modern)),
            ]);
            let aliases = identities.merge(&mut observations);
            assert_eq!(aliases.get(&old), Some(&new));
            assert_eq!(observations.len(), 1);
            assert_eq!(
                severity(observations[&new].health),
                severity(legacy).max(severity(modern))
            );
        }
    }
    #[test]
    fn equal_names_missing_different_or_ambiguous_serials_never_merge() {
        for (a_serial, b_serial) in [
            ("first", "second"),
            ("", ""),
            ("UNKNOWN", "UNKNOWN"),
            ("0000000", "0000000"),
        ] {
            let (old, a) = source(false, "0", a_serial);
            let (new, b) = source(true, "Slot.1", b_serial);
            let mut identities = PsuIdentities::default();
            identities.observe(&old, &a);
            identities.observe(&new, &b);
            let mut observations = BTreeMap::from([
                (old.clone(), observation(&old, Health::Critical)),
                (new.clone(), observation(&new, Health::Critical)),
            ]);
            assert!(identities.merge(&mut observations).is_empty());
            assert_eq!(observations.len(), 2);
        }
        let (a, av) = source(false, "0", "duplicate");
        let (b, bv) = source(false, "1", "duplicate");
        let (c, cv) = source(true, "Slot.1", "duplicate");
        let mut identities = PsuIdentities::default();
        for (key, v) in [(&a, &av), (&b, &bv), (&c, &cv)] {
            identities.observe(key, v);
        }
        let mut observations = BTreeMap::from([
            (a.clone(), observation(&a, Health::Critical)),
            (b.clone(), observation(&b, Health::Critical)),
            (c.clone(), observation(&c, Health::Critical)),
        ]);
        assert!(identities.merge(&mut observations).is_empty());
        assert_eq!(observations.len(), 3);
    }
}

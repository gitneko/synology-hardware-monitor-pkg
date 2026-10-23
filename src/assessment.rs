//! Applicability is separate from health: an excluded unknown is not an OK
//! observation and must never clear an earlier component fault.
use crate::model::{AssessmentExclusion, Health, Observation};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Facts {
    disabled: bool,
    other_state: bool,
    absent: bool,
    other_presence: bool,
    unavailable: bool,
    reported_fault: bool,
    informational: bool,
    has_status: bool,
    empty_simple: bool,
    populated: bool,
    empty_collection: bool,
    complete_members: bool,
    incomplete_members: bool,
    sata_only: bool,
    other_protocols: bool,
    uncertain_inventory: bool,
    members: BTreeSet<String>,
    storage: Option<Storage>,
}

struct Storage {
    empty_drives: bool,
    volumes: Option<String>,
    empty_volumes: bool,
    controllers: Vec<String>,
    controller_collection: Option<String>,
    sata_without_volumes: bool,
}

#[derive(Default)]
pub(crate) struct Applicability(BTreeMap<String, Facts>);

fn empty_array(value: &Value, name: &str) -> bool {
    value
        .get(name)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        && value
            .get(format!("{name}@odata.count"))
            .is_none_or(|count| count.as_u64() == Some(0))
        && value.get(format!("{name}@odata.nextLink")).is_none()
}

fn child_key(parent: &str, name: &str, item: &Value, index: usize) -> String {
    item.get("@odata.id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| crate::correlation::embedded_uri(parent, name, item, index))
}

// iLO 6 reports Warning for an empty PSU bay in both Power and PowerSubsystem.
// iLO 6 v1.79 omits Oem in its modern view. In that case require both the
// standard PowerSupply schema and HPE's exact supply name. Never use a name
// alone or override a conflicting OEM payload. Inventory can remain populated
// while the host is off; only independent fault evidence blocks neutral absence.
pub(crate) fn hpe_absent_power_supply_warning(value: &Value) -> bool {
    let typed_oem = value
        .pointer("/Oem/Hpe/@odata.type")
        .and_then(Value::as_str)
        .is_some_and(|kind| {
            kind.starts_with("#HpeServerPowerSupply.") && kind.ends_with(".HpeServerPowerSupply")
        });
    let standard_hpe = value
        .get("@odata.type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.starts_with("#PowerSupply.") && kind.ends_with(".PowerSupply"))
        && value.get("Name").and_then(Value::as_str) == Some("HpeServerPowerSupply")
        && value
            .get("Oem")
            .is_none_or(|v| v.as_object().is_some_and(|oem| oem.is_empty()));
    (typed_oem || standard_hpe)
        && value.pointer("/Status/State").and_then(Value::as_str) == Some("Absent")
        && value.pointer("/Status/Health").and_then(Value::as_str) == Some("Warning")
        && value
            .pointer("/Status/HealthRollup")
            .is_none_or(|v| v.is_null() || v.as_str() == Some("OK"))
        && value.pointer("/Status/Conditions").is_none_or(|v| {
            v.as_array().is_some_and(|conditions| {
                conditions
                    .iter()
                    .all(|c| c.get("Severity").and_then(Value::as_str) == Some("OK"))
            })
        })
        && value
            .pointer("/Oem/Hpe/Mismatched")
            .is_none_or(|v| v.as_bool() == Some(false))
        && value.pointer("/Oem/Hpe/PowerSupplyStatus").is_none_or(|v| {
            v.as_object().is_some_and(|status| {
                status.is_empty()
                    || (status.len() == 1
                        && matches!(
                            status.get("State").and_then(Value::as_str),
                            Some("Ok" | "GoodInStandby")
                        ))
            })
        })
}

impl Applicability {
    pub(crate) fn observe(&mut self, fallback: &str, value: &Value) {
        self.observe_context(fallback, value, None);
    }

    fn observe_context(&mut self, fallback: &str, value: &Value, embedded: Option<&str>) {
        if value.get("Message").is_some() {
            return;
        }
        let key = value
            .get("@odata.id")
            .and_then(Value::as_str)
            .unwrap_or(fallback);
        let facts = self.0.entry(key.into()).or_default();
        let kind = value
            .get("@odata.type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .rsplit('.')
            .next()
            .unwrap_or("");
        if let Some(state) = value.pointer("/Status/State").and_then(Value::as_str) {
            facts.disabled |= state == "Disabled";
            facts.other_state |= state != "Disabled";
            facts.absent |= state == "Absent";
            facts.other_presence |= state != "Absent";
            facts.unavailable |= !matches!(state, "Disabled" | "Enabled");
        }
        facts.has_status |= value.get("Status").is_some();
        facts.reported_fault |= !hpe_absent_power_supply_warning(value)
            && ["/Status/Health", "/Status/HealthRollup"]
                .iter()
                .any(|path| {
                    matches!(
                        value.pointer(path).and_then(Value::as_str),
                        Some("Warning" | "Critical")
                    )
                });
        facts.reported_fault |= value
            .pointer("/Status/Conditions")
            .and_then(Value::as_array)
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|c| c.get("Severity").and_then(Value::as_str) != Some("OK"))
            });
        facts.informational |= (kind == "PowerControl"
            || (kind.is_empty() && embedded == Some("PowerControl")))
            && value
                .get("PowerConsumedWatts")
                .and_then(Value::as_f64)
                .is_some_and(f64::is_finite);
        facts.populated |= ["Drives", "Devices", "Volumes", "Members"]
            .iter()
            .any(|name| {
                value
                    .get(*name)
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty())
                    || value
                        .get(format!("{name}@odata.count"))
                        .and_then(Value::as_u64)
                        .is_some_and(|n| n > 0)
            });
        // Standalone controllers can also advertise attached inventory in Links.
        facts.populated |= ["Drives", "Volumes"].iter().any(|name| {
            value
                .get("Links")
                .and_then(|links| links.get(*name))
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty())
        });
        facts.empty_simple |= kind == "SimpleStorage" && empty_array(value, "Devices");
        facts.empty_collection |= empty_array(value, "Members");
        facts.sata_only |= value
            .get("SupportedDeviceProtocols")
            .and_then(Value::as_array)
            .is_some_and(|protocols| {
                !protocols.is_empty() && protocols.iter().all(|p| p.as_str() == Some("SATA"))
            });
        facts.other_protocols |= value
            .get("SupportedDeviceProtocols")
            .is_some_and(|protocols| {
                !protocols.as_array().is_some_and(|items| {
                    !items.is_empty() && items.iter().all(|p| p.as_str() == Some("SATA"))
                })
            });
        facts.uncertain_inventory |=
            [Some(value), value.get("Links")]
                .into_iter()
                .flatten()
                .any(|inventory| {
                    ["Drives", "Volumes"].iter().any(|name| {
                        inventory.get(*name).is_some_and(|v| !v.is_array())
                            || inventory.get(format!("{name}@odata.nextLink")).is_some()
                    })
                });
        if let Some(members) = value.get("Members").and_then(Value::as_array) {
            let complete = value.get("Members@odata.nextLink").is_none()
                && value.get("@odata.nextLink").is_none()
                && value
                    .get("Members@odata.count")
                    .is_none_or(|count| count.as_u64() == Some(members.len() as u64));
            facts.complete_members |= complete;
            facts.incomplete_members |= !complete;
            facts.members.extend(
                members
                    .iter()
                    .enumerate()
                    .map(|(index, member)| child_key(key, "Members", member, index)),
            );
        }
        if kind == "Storage" {
            facts.storage = Some(Storage {
                empty_drives: empty_array(value, "Drives"),
                volumes: value
                    .pointer("/Volumes/@odata.id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                empty_volumes: empty_array(value, "Volumes"),
                controllers: value
                    .get("StorageControllers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .enumerate()
                    .map(|(index, item)| child_key(key, "StorageControllers", item, index))
                    .collect(),
                controller_collection: value
                    .pointer("/Controllers/@odata.id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                // A missing Volumes inventory is normally unknown. The narrower
                // SATA case is checked against every linked controller below.
                sata_without_volumes: value.pointer("/Status/Health").and_then(Value::as_str)
                    == Some("OK")
                    && value.pointer("/Status/State").and_then(Value::as_str) == Some("Enabled")
                    && !value
                        .as_object()
                        .unwrap()
                        .keys()
                        .any(|k| k == "Volumes" || k.starts_with("Volumes@")),
            });
        }
        for summary in crate::hpe_power::summaries(key, value) {
            self.observe_context(key, &summary, None);
        }
        for name in crate::collector::LINK_KEYS.iter().chain(["Members"].iter()) {
            if let Some(array) = value.get(*name).and_then(Value::as_array) {
                for (index, item) in array.iter().enumerate() {
                    self.observe_context(
                        &crate::correlation::embedded_uri(key, name, item, index),
                        item,
                        (kind == "Power" && *name == "PowerControl").then_some("PowerControl"),
                    );
                }
            }
        }
    }

    pub(crate) fn exclusions(
        &self,
        observations: &BTreeMap<String, Observation>,
    ) -> BTreeMap<String, AssessmentExclusion> {
        let mut excluded = BTreeMap::new();
        let mut controllers = BTreeMap::new();
        for (key, facts) in &self.0 {
            if facts.disabled && !facts.other_state {
                excluded.insert(key.clone(), AssessmentExclusion::Disabled);
            } else if facts.absent && !facts.other_presence {
                excluded.insert(key.clone(), AssessmentExclusion::Absent);
            } else if facts.informational && !facts.has_status {
                excluded.insert(key.clone(), AssessmentExclusion::Informational);
            }
            let empty_storage = !facts.populated
                && !facts.unavailable
                && facts.storage.as_ref().is_some_and(|storage| {
                    storage.empty_drives
                        && (storage.empty_volumes
                            || storage
                                .volumes
                                .as_ref()
                                .and_then(|uri| self.0.get(uri))
                                .is_some_and(|v| v.empty_collection && !v.populated)
                            || (storage.sata_without_volumes
                                && !facts.reported_fault
                                && self.empty_sata_controllers(storage)))
                });
            if !facts.populated && !facts.unavailable && (facts.empty_simple || empty_storage) {
                excluded
                    .entry(key.clone())
                    .or_insert(AssessmentExclusion::EmptyController);
            }
            if let Some(storage) = &facts.storage {
                // Only explicit Redfish references associate standalone controller
                // resources with their storage inventory; never names/path guesses.
                // A shared controller is neutral only if every known owner is empty.
                let members = storage
                    .controller_collection
                    .as_ref()
                    .and_then(|uri| self.0.get(uri))
                    .into_iter()
                    .flat_map(|collection| &collection.members);
                for controller in storage.controllers.iter().chain(members) {
                    controllers
                        .entry(controller.clone())
                        .and_modify(|empty| *empty &= empty_storage)
                        .or_insert(empty_storage);
                }
            }
        }
        for (controller, empty) in controllers {
            if empty
                && self
                    .0
                    .get(&controller)
                    .is_some_and(|v| !v.populated && !v.unavailable)
            {
                excluded
                    .entry(controller)
                    .or_insert(AssessmentExclusion::EmptyController);
            }
        }
        excluded.retain(|key, _| {
            observations
                .get(key)
                .is_some_and(|o| o.health == Health::Unknown)
                && self.0.get(key).is_none_or(|v| !v.reported_fault)
        });
        excluded
    }

    fn empty_sata_controllers(&self, storage: &Storage) -> bool {
        let mut controllers: BTreeSet<_> = storage.controllers.iter().collect();
        if let Some(collection) = &storage.controller_collection {
            let Some(facts) = self
                .0
                .get(collection)
                .filter(|f| f.complete_members && !f.incomplete_members && !f.members.is_empty())
            else {
                return false;
            };
            controllers.extend(&facts.members);
        }
        !controllers.is_empty()
            && controllers.iter().all(|key| {
                self.0.get(*key).is_some_and(|f| {
                    f.sata_only
                        && !f.other_protocols
                        && !f.uncertain_inventory
                        && !f.populated
                        && !f.unavailable
                        && !f.reported_fault
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn live_fixture() -> Vec<Value> {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/hpe-applicability.json")).unwrap();
        fixture["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["body"].clone())
            .collect()
    }
    fn assess(
        values: &[Value],
    ) -> (
        BTreeMap<String, Observation>,
        BTreeMap<String, AssessmentExclusion>,
    ) {
        let mut a = Applicability::default();
        let mut obs = BTreeMap::new();
        for value in values {
            let uri = value["@odata.id"].as_str().unwrap();
            a.observe(uri, value);
            crate::collector::normalize(uri, value, &mut obs, &mut Vec::new());
        }
        let excluded = a.exclusions(&obs);
        (obs, excluded)
    }
    #[test]
    fn live_ilo_fixture_explains_all_28_unknowns_without_inventing_healthy_readings() {
        let (obs, excluded) = assess(&live_fixture());
        assert_eq!(excluded.len(), 28);
        for (reason, count) in [
            (AssessmentExclusion::Absent, 23),
            (AssessmentExclusion::Informational, 1),
            (AssessmentExclusion::EmptyController, 4),
        ] {
            assert_eq!(excluded.values().filter(|&&r| r == reason).count(), count);
        }
        assert!(obs
            .values()
            .filter(|o| o.health == Health::Unknown)
            .all(|o| excluded.contains_key(&o.key)));
        for (key, reason) in &excluded {
            assert_eq!(obs[key].health, Health::Unknown);
            if *reason == AssessmentExclusion::Absent {
                assert!(obs[key].reading.is_none());
            }
        }
        let snapshot = crate::model::Snapshot {
            observations: obs.into_values().collect(),
            assessment_exclusions: excluded,
            ..Default::default()
        };
        let evaluation = crate::acknowledgement::Evaluation {
            statuses: BTreeMap::new(),
        };
        assert_eq!(evaluation.overall(Some(&snapshot), false), "ok");
        assert_eq!(evaluation.overall(Some(&snapshot), true), "unknown");
    }

    fn ilo6_power_fixture() -> Vec<Value> {
        serde_json::from_str::<Value>(include_str!(
            "../tests/fixtures/hpe-ilo6-power-supplies.json"
        ))
        .unwrap()["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["body"].clone())
            .collect()
    }

    #[test]
    fn ilo6_empty_psu_bay_is_absent_in_both_redfish_views() {
        let values = ilo6_power_fixture();
        let (observations, exclusions) = assess(&values);
        let absent_keys = [
            "/redfish/v1/Chassis/1/Power/#PowerSupplies/1",
            "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1/",
        ];
        assert_eq!(exclusions.len(), 2);
        for key in absent_keys {
            assert_eq!(observations[key].health, Health::Unknown);
            assert_eq!(observations[key].reading, None);
            assert_eq!(exclusions[key], AssessmentExclusion::Absent);
        }
        for key in [
            "/redfish/v1/Chassis/1/Power/#PowerSupplies/0",
            "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/0/",
        ] {
            assert_eq!(observations[key].health, Health::Ok);
            assert!(!exclusions.contains_key(key));
        }
        // Preserve the original vendor response; absence is never fabricated OK.
        assert_eq!(values[0]["PowerSupplies"][1]["Status"]["Health"], "Warning");
        assert_eq!(values[2]["Status"]["Health"], "Warning");
        let snapshot = crate::model::Snapshot {
            observations: observations.into_values().collect(),
            assessment_exclusions: exclusions,
            ..Default::default()
        };
        let evaluation = crate::acknowledgement::Evaluation {
            statuses: BTreeMap::new(),
        };
        assert_eq!(evaluation.overall(Some(&snapshot), false), "ok");
        assert_eq!(evaluation.overall(Some(&snapshot), true), "unknown");
    }

    #[test]
    fn ilo6_absence_exception_preserves_independent_faults() {
        let absent = ilo6_power_fixture().pop().unwrap();
        assert!(hpe_absent_power_supply_warning(&absent));
        for (pointer, value) in [
            ("/Status/State", json!("Enabled")),
            ("/Status/State", json!("UnavailableOffline")),
            ("/Status/Health", json!("Critical")),
            ("/Status/HealthRollup", json!("Warning")),
            ("/Status/HealthRollup", json!("Critical")),
            ("/Status/Conditions", json!([{"Severity":"Warning"}])),
            ("/Status/Conditions", json!([{"Severity":"Critical"}])),
            ("/Status/Conditions", json!([{}])),
            ("/Status/Conditions", Value::Null),
            ("/Oem/Hpe/@odata.type", json!("#Other.v1_0_0.Other")),
            ("/Oem/Hpe/PowerSupplyStatus", json!({"State":"Failed"})),
            ("/Oem/Hpe/Mismatched", json!(true)),
        ] {
            let mut changed = absent.clone();
            // The fixture contains no optional HealthRollup/Conditions/output fields.
            let (parent, field) = pointer.rsplit_once('/').unwrap();
            changed
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.into(), value);
            assert!(!hpe_absent_power_supply_warning(&changed), "{pointer}");
            let (observations, exclusions) = assess(&[changed.clone()]);
            let key = changed["@odata.id"].as_str().unwrap();
            assert!(
                matches!(observations[key].health, Health::Warning | Health::Critical),
                "{pointer}"
            );
            assert!(!exclusions.contains_key(key), "{pointer}");
        }
        // An explicitly present representation prevents an absence exclusion.
        let mut a = Applicability::default();
        let key = absent["@odata.id"].as_str().unwrap();
        a.observe(key, &absent);
        a.observe(key, &json!({"Status":{"State":"Enabled"}}));
        assert!(a
            .exclusions(&observations(&[(key, Health::Unknown)]))
            .is_empty());
    }

    #[test]
    fn ilo6_179_standard_psu_without_oem_is_absent_but_requires_hpe_schema_evidence() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/hpe-ilo6-179-power-supplies.json"
        ))
        .unwrap();
        let values: Vec<Value> = fixture["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["body"].clone())
            .collect();
        let (obs, excluded) = assess(&values);
        assert_eq!(excluded.len(), 2);
        for (key, observation) in &obs {
            assert_eq!(observation.health, Health::Unknown);
            assert_eq!(excluded[key], AssessmentExclusion::Absent);
        }
        let original = &values[1];
        assert!(original.get("Oem").is_none());
        for (field, value) in [
            ("Name", json!("Power Supply 2")),
            ("Name", Value::Null),
            ("@odata.type", json!("#Sensor.v1_0_0.Sensor")),
            ("@odata.type", Value::Null),
            ("Oem", json!({"OtherVendor":{}})),
            ("Oem", Value::Null),
            ("Oem", json!({"Hpe":{"@odata.type":"#Other.v1_0_0.Other"}})),
            ("Status", json!({"State":"Enabled","Health":"Warning"})),
            ("Status", json!({"State":"Absent","Health":"Critical"})),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(!hpe_absent_power_supply_warning(&changed), "{field}");
            let (obs, excluded) = assess(&[changed.clone()]);
            assert!(
                matches!(
                    obs[changed["@odata.id"].as_str().unwrap()].health,
                    Health::Warning | Health::Critical
                ),
                "{field}"
            );
            assert!(excluded.is_empty(), "{field}");
        }
    }

    #[test]
    fn absent_is_not_neutral_when_another_representation_is_present_or_faulty() {
        for extra in [
            json!({"State":"Enabled"}),
            json!({"State":"UnavailableOffline"}),
            json!({"Health":"Warning"}),
            json!({"Health":"Critical"}),
            json!({"Conditions":[{"Severity":"Critical"}]}),
        ] {
            let mut a = Applicability::default();
            a.observe("fan", &json!({"Status":{"State":"Absent"}}));
            a.observe("fan", &json!({"Status":extra}));
            assert!(a
                .exclusions(&observations(&[("fan", Health::Unknown)]))
                .is_empty());
        }
    }
    #[test]
    fn untyped_power_requires_explicit_power_control_membership_and_no_status() {
        for (parent_kind, child, expected) in [
            ("Power", json!({"PowerConsumedWatts":78}), true),
            (
                "Power",
                json!({"PowerConsumedWatts":78,"Status":null}),
                false,
            ),
            (
                "Power",
                json!({"PowerConsumedWatts":78,"Status":{"Health":"Warning"}}),
                false,
            ),
            (
                "Power",
                json!({"PowerConsumedWatts":78,"@odata.type":"#Sensor.v1_0_0.Sensor"}),
                false,
            ),
            ("Other", json!({"PowerConsumedWatts":78}), false),
        ] {
            let parent = json!({"@odata.id":"power","@odata.type":format!("#Power.v1_3_0.{parent_kind}"),"PowerControl":[child]});
            let (obs, excluded) = assess(&[parent]);
            assert_eq!(excluded.contains_key("power#PowerControl:0"), expected);
            assert!(!obs.is_empty());
        }
    }
    #[test]
    fn sata_without_volumes_requires_healthy_complete_sata_only_empty_inventory() {
        let storage = "/redfish/v1/Systems/1/Storage/DA000004/";
        let embedded = "/redfish/v1/Systems/1/Storage/DA000004#/StorageControllers/0/";
        let controller = format!("{storage}Controllers/0/");
        for case in 0..13 {
            let mut values = live_fixture();
            let root = values
                .iter_mut()
                .find(|v| v["@odata.id"] == storage)
                .unwrap();
            match case {
                0 => root["Drives"] = json!([{"@odata.id":"/redfish/v1/Drives/1"}]),
                1 => root["Volumes"] = Value::Null,
                2 => root["Volumes"] = json!({"@odata.id":"missing"}),
                3 => root["Status"]["Health"] = Value::Null,
                4 => root["Status"]["State"] = json!("UnavailableOffline"),
                5 => {
                    root["StorageControllers"][0]["SupportedDeviceProtocols"] =
                        json!(["SATA", "SAS"])
                }
                6 => root["Drives@odata.count"] = json!(1),
                7 => root["Volumes@odata.count"] = json!(0),
                12 => root["Drives@odata.count"] = Value::Null,
                _ => {}
            }
            match case {
                8 => values.retain(|v| v["@odata.id"] != controller),
                9 => {
                    values
                        .iter_mut()
                        .find(|v| v["@odata.id"] == format!("{storage}Controllers/"))
                        .unwrap()["Members@odata.nextLink"] = json!("next")
                }
                10 => {
                    values
                        .iter_mut()
                        .find(|v| v["@odata.id"] == controller)
                        .unwrap()["Links"] = json!({"Volumes":{"@odata.id":"missing"}})
                }
                11 => {
                    values
                        .iter_mut()
                        .find(|v| v["@odata.id"] == controller)
                        .unwrap()["Status"]["Health"] = json!("Critical")
                }
                _ => {}
            }
            let (_, excluded) = assess(&values);
            assert!(!excluded.contains_key(embedded), "case {case}");
            assert!(!excluded.contains_key(&controller), "case {case}");
        }
    }

    fn observations(values: &[(&str, Health)]) -> BTreeMap<String, Observation> {
        values
            .iter()
            .map(|(key, health)| {
                (
                    key.to_string(),
                    Observation {
                        key: key.to_string(),
                        label: key.to_string(),
                        health: *health,
                        reading: None,
                        unit: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn disabled_is_neutral_but_faults_and_other_unavailable_states_are_not() {
        for (state, health, neutral) in [
            ("Disabled", Health::Unknown, true),
            ("Disabled", Health::Warning, false),
            ("Disabled", Health::Critical, false),
            ("Absent", Health::Unknown, true),
            ("Absent", Health::Warning, false),
            ("Absent", Health::Critical, false),
            ("UnavailableOffline", Health::Unknown, false),
            ("Starting", Health::Unknown, false),
        ] {
            let mut a = Applicability::default();
            a.observe("/redfish/v1/component", &json!({"Status":{"State":state}}));
            assert_eq!(
                a.exclusions(&observations(&[("/redfish/v1/component", health)]))
                    .contains_key("/redfish/v1/component"),
                neutral
            );
        }
    }

    #[test]
    fn empty_storage_requires_inventory_and_propagates_only_explicit_links() {
        let mut a = Applicability::default();
        a.observe("storage", &json!({"@odata.type":"#Storage.v1_4_0.Storage","Drives":[],"Volumes":{"@odata.id":"volumes"},
            "StorageControllers":[{"@odata.id":"controller","Status":{"Health":null,"State":"Enabled"}}]}));
        let obs = observations(&[
            ("storage", Health::Unknown),
            ("controller", Health::Unknown),
            ("unrelated", Health::Unknown),
        ]);
        assert!(a.exclusions(&obs).is_empty()); // Missing/failed volumes is not empty.
        a.observe("volumes", &json!({"Members":[],"Members@odata.count":0}));
        assert_eq!(a.exclusions(&obs).len(), 2);
        a.observe(
            "storage",
            &json!({"@odata.type":"#SimpleStorage.v1_2_0.SimpleStorage","Devices":[]}),
        );
        assert_eq!(a.exclusions(&obs).len(), 2); // Dell aliases must retain Storage references.
        a.observe("controller", &json!({"Devices":[{"Name":"Disk"}]}));
        assert_eq!(a.exclusions(&obs).len(), 1);
    }

    #[test]
    fn empty_idrac_storage_explains_all_four_representations_and_overall_health() {
        let storage = "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Embedded.1-1";
        let controller = format!("{storage}/Controllers/RAID.Embedded.1-1");
        let resources = [
            json!({"@odata.id":"/redfish/v1/Systems/System.Embedded.1/SimpleStorage/RAID.Embedded.1-1",
                "@odata.type":"#SimpleStorage.v1_2_0.SimpleStorage","Name":"PERC S140 Controller",
                "Devices":[],"Status":{"State":"Enabled","Health":null}}),
            json!({"@odata.id":storage,"@odata.type":"#Storage.v1_14_0.Storage",
                "Name":"PERC S140 Controller","Status":{"State":"Enabled","Health":null},
                "Drives":[],"Volumes":{"@odata.id":format!("{storage}/Volumes")},
                "Controllers":{"@odata.id":format!("{storage}/Controllers")},
                "StorageControllers":[{"@odata.id":format!("{storage}#/StorageControllers/0"),
                    "Name":"PERC S140 Controller","Status":{"State":"Enabled","Health":null}}]}),
            json!({"@odata.id":format!("{storage}/Volumes"),"Members":[],"Members@odata.count":0}),
            json!({"@odata.id":format!("{storage}/Controllers"),
                "Members":[{"@odata.id":controller}],"Members@odata.count":1}),
            json!({"@odata.id":controller,"@odata.type":"#StorageController.v1_6_0.StorageController",
                "Name":"PERC S140 Controller","Status":{"State":"Enabled","Health":null}}),
            json!({"@odata.id":"/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1",
                "@odata.type":"#Storage.v1_14_0.Storage","Name":"PERC H330 Adapter","Status":{"Health":"OK"},
                "Drives":[{"@odata.id":"disk"}]}),
        ];
        let mut a = Applicability::default();
        let mut obs = BTreeMap::new();
        for resource in resources.iter().rev() {
            a.observe("unused", resource);
            crate::collector::normalize("unused", resource, &mut obs, &mut Vec::new());
        }
        assert_eq!(obs.len(), 5);
        let mut snapshot = crate::model::Snapshot {
            observations: obs.values().cloned().collect(),
            ..Default::default()
        };
        let evaluation = crate::acknowledgement::Evaluation {
            statuses: BTreeMap::new(),
        };
        assert_eq!(evaluation.overall(Some(&snapshot), false), "unknown");
        snapshot.assessment_exclusions = a.exclusions(&obs);
        assert_eq!(snapshot.assessment_exclusions.len(), 4);
        assert_eq!(
            snapshot.assessment_exclusions[&controller],
            AssessmentExclusion::EmptyController
        );
        assert_eq!(evaluation.overall(Some(&snapshot), false), "ok");
    }

    #[test]
    fn controller_collection_exemptions_require_safe_inventory_and_explicit_membership() {
        for (controller_value, expected) in [
            (json!({"Status":{"State":"Enabled","Health":null}}), true),
            (json!({"Status":{"State":"UnavailableOffline"}}), false),
            (json!({"Status":{"Health":"Warning"}}), false),
            (json!({"Status":{"Health":"Critical"}}), false),
            (json!({"Links":{"Volumes":[{"@odata.id":"volume"}]}}), false),
            (json!({"Links":{"Drives":[{"@odata.id":"disk"}]}}), false),
        ] {
            let mut a = Applicability::default();
            a.observe(
                "storage",
                &json!({"@odata.type":"#Storage.v1_14_0.Storage","Drives":[],"Volumes":[],
                "Controllers":{"@odata.id":"controllers"}}),
            );
            a.observe("controller", &controller_value);
            let obs = observations(&[
                ("controller", Health::Unknown),
                ("unrelated", Health::Unknown),
            ]);
            assert!(a.exclusions(&obs).is_empty()); // A collection link alone is insufficient.
            a.observe(
                "controllers",
                &json!({"Members":[{"@odata.id":"controller"}]}),
            );
            assert_eq!(
                a.exclusions(&obs).contains_key("controller"),
                expected,
                "{controller_value}"
            );
            assert!(!a.exclusions(&obs).contains_key("unrelated"));
        }
        for inventory in [
            json!({"Drives":[]}),
            json!({"Drives":[],"Volumes":{"@odata.id":"missing"}}),
            json!({"Drives":[{}],"Volumes":[]}),
            json!({"Drives":[],"Volumes":[],"Drives@odata.count":1}),
            json!({"Drives":[],"Volumes":[],"Volumes@odata.nextLink":"next"}),
        ] {
            let mut a = Applicability::default();
            let mut storage = inventory;
            storage["@odata.type"] = json!("#Storage.v1_14_0.Storage");
            storage["Controllers"] = json!({"@odata.id":"controllers"});
            a.observe("storage", &storage);
            a.observe(
                "controllers",
                &json!({"Members":[{"@odata.id":"controller"}]}),
            );
            a.observe("controller", &json!({"Status":{"Health":null}}));
            assert!(a
                .exclusions(&observations(&[("controller", Health::Unknown)]))
                .is_empty());
        }
    }

    #[test]
    fn shared_controller_with_populated_storage_cannot_be_excluded() {
        let mut a = Applicability::default();
        a.observe(
            "empty",
            &json!({"@odata.type":"#Storage.v1_14_0.Storage","Drives":[],"Volumes":[],
            "Controllers":{"@odata.id":"controllers"}}),
        );
        a.observe(
            "used",
            &json!({"@odata.type":"#Storage.v1_14_0.Storage","Drives":[{}],"Volumes":[],
            "Controllers":{"@odata.id":"controllers"}}),
        );
        a.observe(
            "controllers",
            &json!({"Members":[{"@odata.id":"controller"}]}),
        );
        a.observe("controller", &json!({"Status":{"Health":null}}));
        assert!(a
            .exclusions(&observations(&[("controller", Health::Unknown)]))
            .is_empty());
    }

    #[test]
    fn embedded_controller_without_odata_id_uses_the_observation_key() {
        let mut a = Applicability::default();
        a.observe(
            "storage",
            &json!({"@odata.type":"#Storage.v1_4_0.Storage","Drives":[],"Volumes":[],
            "StorageControllers":[{"MemberId":"0","Status":{"Health":null}}]}),
        );
        assert_eq!(
            a.exclusions(&observations(&[(
                "storage#StorageControllers:0",
                Health::Unknown
            )]))
            .get("storage#StorageControllers:0"),
            Some(&AssessmentExclusion::EmptyController)
        );
    }

    #[test]
    fn missing_active_inconsistent_or_paginated_inventory_is_not_empty() {
        for value in [
            json!({}),
            json!({"Devices":[{}]}),
            json!({"Devices":[],"Devices@odata.count":1}),
            json!({"Devices":[],"Devices@odata.nextLink":"next"}),
        ] {
            let mut value = value;
            value["@odata.type"] = json!("#SimpleStorage.v1_2_0.SimpleStorage");
            let mut a = Applicability::default();
            a.observe("controller", &value);
            assert!(a
                .exclusions(&observations(&[("controller", Health::Unknown)]))
                .is_empty());
        }
        let mut a = Applicability::default();
        a.observe(
            "controller",
            &json!({"@odata.type":"#SimpleStorage.v1_2_0.SimpleStorage","Devices":[]}),
        );
        assert!(a
            .exclusions(&observations(&[("controller", Health::Critical)]))
            .is_empty());
        a.observe(
            "controller",
            &json!({"Status":{"State":"UnavailableOffline"}}),
        );
        assert!(a
            .exclusions(&observations(&[("controller", Health::Unknown)]))
            .is_empty());
        let mut a = Applicability::default();
        a.observe("controller", &json!({"@odata.type":"#SimpleStorage.v1_2_0.SimpleStorage","Devices":[],"Status":{"Health":"Critical"}}));
        a.observe("controller", &json!({"Status":{"Health":null}}));
        assert!(a
            .exclusions(&observations(&[("controller", Health::Unknown)]))
            .is_empty());
    }

    #[test]
    fn power_measurement_without_status_is_informational_not_a_sensor_exemption() {
        for (kind, status, health, expected) in [
            ("PowerControl", None, Health::Unknown, true),
            ("Sensor", None, Health::Unknown, false),
            (
                "PowerControl",
                Some(json!({"State":"UnavailableOffline"})),
                Health::Unknown,
                false,
            ),
            ("PowerControl", None, Health::Critical, false),
        ] {
            let mut value =
                json!({"@odata.type":format!("#Power.v1_4_0.{kind}"),"PowerConsumedWatts":106});
            if let Some(status) = status {
                value["Status"] = status;
            }
            let mut a = Applicability::default();
            a.observe("power", &value);
            assert_eq!(
                a.exclusions(&observations(&[("power", health)]))
                    .contains_key("power"),
                expected
            );
        }
    }
}

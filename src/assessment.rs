//! Applicability is separate from health: an excluded unknown is not an OK
//! observation and must never clear an earlier component fault.
use crate::model::{AssessmentExclusion, Health, Observation};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Facts {
    disabled: bool,
    other_state: bool,
    unavailable: bool,
    reported_fault: bool,
    informational: bool,
    has_status: bool,
    empty_simple: bool,
    populated: bool,
    empty_collection: bool,
    members: BTreeSet<String>,
    storage: Option<Storage>,
}

struct Storage {
    empty_drives: bool,
    volumes: Option<String>,
    empty_volumes: bool,
    controllers: Vec<String>,
    controller_collection: Option<String>,
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
            .and_then(Value::as_u64)
            .unwrap_or(0)
            == 0
        && value.get(format!("{name}@odata.nextLink")).is_none()
}

fn child_key(parent: &str, name: &str, item: &Value, index: usize) -> String {
    item.get("@odata.id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| crate::correlation::embedded_uri(parent, name, item, index))
}

impl Applicability {
    pub(crate) fn observe(&mut self, fallback: &str, value: &Value) {
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
            facts.unavailable |= !matches!(state, "Disabled" | "Enabled");
        }
        facts.has_status |= value.get("Status").is_some();
        facts.reported_fault |= ["/Status/Health", "/Status/HealthRollup"]
            .iter()
            .any(|path| {
                matches!(
                    value.pointer(path).and_then(Value::as_str),
                    Some("Warning" | "Critical")
                )
            });
        facts.informational |= kind == "PowerControl"
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
        if let Some(members) = value.get("Members").and_then(Value::as_array) {
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
            });
        }
        for name in crate::collector::LINK_KEYS.iter().chain(["Members"].iter()) {
            if let Some(array) = value.get(*name).and_then(Value::as_array) {
                for (index, item) in array.iter().enumerate() {
                    self.observe(
                        &crate::correlation::embedded_uri(key, name, item, index),
                        item,
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
                                .is_some_and(|v| v.empty_collection && !v.populated))
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
            ("Absent", Health::Unknown, false),
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

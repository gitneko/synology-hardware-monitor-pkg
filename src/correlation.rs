//! Notification grouping follows explicit Redfish containment/dependency links.
//! This is an explainable noise policy, not proof of physical fault causality.
use crate::model::Health;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Resource {
    pub kind: String,
    pub own_health: Option<Health>,
    pub rollup: Option<Health>,
    pub children: BTreeSet<String>,
    #[serde(default)]
    pub associated_systems: BTreeSet<String>,
    #[serde(default)]
    pub independent_condition: bool,
    #[serde(default)]
    pub condition_origins: BTreeSet<String>,
    #[serde(default)]
    pub condition_fingerprint: String,
}
fn health(v: Option<&Value>) -> Option<Health> {
    match v.and_then(Value::as_str) {
        Some("Critical") => Some(Health::Critical),
        Some("Warning") => Some(Health::Warning),
        Some("OK") => Some(Health::Ok),
        _ => None,
    }
}
fn valid(key: &str) -> bool {
    key.starts_with("/redfish/v1/")
        && key.len() <= 4096
        && !key.chars().any(char::is_control)
        && !key.contains('?')
}
fn links(v: &Value) -> Vec<String> {
    if let Some(a) = v.as_array() {
        return a.iter().flat_map(links).collect();
    }
    v.get("@odata.id")
        .and_then(Value::as_str)
        .filter(|k| valid(k))
        .map(|k| vec![k.to_owned()])
        .unwrap_or_default()
}
pub fn embedded_uri(uri: &str, name: &str, item: &Value, index: usize) -> String {
    let id = item
        .get("MemberId")
        .or_else(|| item.get("Id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| index.to_string());
    format!("{uri}#{name}:{id}")
}
pub fn observe(fallback: &str, value: &Value, resources: &mut BTreeMap<String, Resource>) {
    if value.get("Message").is_some() {
        return;
    }
    let key = value
        .get("@odata.id")
        .and_then(Value::as_str)
        .unwrap_or(fallback);
    if !valid(key) {
        return;
    }
    let mut node = Resource {
        kind: value
            .get("@odata.type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into(),
        own_health: health(value.pointer("/Status/Health")),
        rollup: health(value.pointer("/Status/HealthRollup")),
        ..Default::default()
    };
    for name in crate::collector::LINK_KEYS.iter().chain(["Members"].iter()) {
        // Service root inventories and log services are not a fault dependency.
        if matches!(
            *name,
            "Systems" | "Chassis" | "Managers" | "LogServices" | "Entries"
        ) {
            continue;
        }
        if let Some(v) = value.get(*name) {
            node.children.extend(links(v));
            if let Some(array) = v.as_array() {
                for (index, item) in array.iter().enumerate() {
                    let uri = embedded_uri(key, name, item, index);
                    if item.get("Status").is_some()
                        || item.get("Reading").is_some()
                        || item.get("@odata.id").is_none()
                    {
                        let child = item
                            .get("@odata.id")
                            .and_then(Value::as_str)
                            .unwrap_or(&uri);
                        if valid(child) {
                            node.children.insert(child.into());
                        }
                        observe(&uri, item, resources);
                    }
                }
            }
        }
    }
    for summary in crate::hpe_power::summaries(key, value) {
        let child = summary["@odata.id"]
            .as_str()
            .expect("local summary identity");
        node.children.insert(child.into());
        observe(child, &summary, resources);
    }
    if let Some(rel) = value.get("Links") {
        for name in [
            "PoweredBy",
            "CooledBy",
            "Contains",
            "Drives",
            "Storage",
            "DiskDrives",
            "LogicalDrives",
            "ArrayControllers",
        ] {
            if let Some(v) = rel.get(name) {
                node.children.extend(links(v));
            }
        }
        // ComputerSystem -> associated Chassis is a dependency; reverse links from
        // components and Chassis.ComputerSystems are not containment and form cycles.
        if node.kind.starts_with("#ComputerSystem.") {
            if let Some(v) = rel.get("Chassis") {
                node.children.extend(links(v));
            }
        }
        if node.kind.starts_with("#Chassis.") {
            if let Some(v) = rel.get("ComputerSystems") {
                node.associated_systems.extend(links(v));
            }
        }
    }
    for rel in [
        value.get("Links"),
        value.pointer("/Oem/Hpe"),
        value.pointer("/Oem/Hpe/Links"),
    ]
    .into_iter()
    .flatten()
    {
        for name in crate::collector::HPE_STORAGE_LINK_KEYS {
            if let Some(v) = rel.get(*name) {
                node.children.extend(links(v));
            }
        }
    }
    // An explicit fault on this resource, or an unknown fault origin, remains separate.
    if let Some(conditions) = value
        .pointer("/Status/Conditions")
        .and_then(Value::as_array)
    {
        node.condition_origins = conditions
            .iter()
            .filter(|c| !matches!(c.get("Severity").and_then(Value::as_str), Some("OK")))
            .filter_map(|c| {
                c.pointer("/OriginOfCondition/@odata.id")
                    .and_then(Value::as_str)
            })
            .map(str::to_owned)
            .collect();
        node.independent_condition = conditions
            .iter()
            .filter(|c| !matches!(c.get("Severity").and_then(Value::as_str), Some("OK")))
            .any(|c| {
                c.pointer("/OriginOfCondition/@odata.id")
                    .and_then(Value::as_str)
                    .is_none_or(|origin| origin == key || !valid(origin))
            });
    }
    // Ignore timestamps and human-readable messages: only stable fault/identity data
    // distinguishes a new cause at the same resource and severity.
    let mut conditions: Vec<String> = value
        .pointer("/Status/Conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|c| c.get("Severity").and_then(Value::as_str) != Some("OK"))
        .map(|c| {
            serde_json::json!([
                c.get("MessageId"),
                c.get("MessageArgs"),
                c.pointer("/OriginOfCondition/@odata.id"),
                c.get("Severity")
            ])
            .to_string()
        })
        .collect();
    conditions.sort();
    conditions.dedup();
    node.condition_fingerprint =
        serde_json::json!([value.get("UUID"), value.get("SerialNumber"), conditions]).to_string();
    resources
        .entry(key.into())
        .and_modify(|old| {
            old.children.extend(node.children.clone());
            old.associated_systems
                .extend(node.associated_systems.clone());
            if !node.kind.is_empty() {
                old.kind = node.kind.clone();
                old.own_health = node.own_health;
                old.rollup = node.rollup;
                old.independent_condition = node.independent_condition;
                old.condition_origins = node.condition_origins.clone();
                old.condition_fingerprint = node.condition_fingerprint.clone();
            }
        })
        .or_insert(node);
}
pub(crate) fn summary(resource: &Resource) -> bool {
    [
        "ComputerSystem",
        "Chassis",
        "PowerSubsystem",
        "ThermalSubsystem",
        "Power",
        "Thermal",
        "Storage",
        "HpeSmartStorage",
        "HpeSmartStorageArrayController",
        "HpeSmartStorageLogicalDrive",
    ]
    .iter()
    .any(|kind| resource.kind.rsplit('.').next() == Some(*kind))
}
fn aggregate(resource: &Resource) -> bool {
    summary(resource)
        && !resource.independent_condition
        && !matches!(
            (resource.own_health, resource.rollup),
            (Some(Health::Critical), Some(Health::Warning | Health::Ok))
                | (Some(Health::Warning), Some(Health::Ok))
        )
}
pub(crate) fn descendants(start: &str, resources: &BTreeMap<String, Resource>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut queue = vec![start.to_owned()];
    while let Some(key) = queue.pop() {
        if !found.insert(key.clone()) {
            continue;
        }
        if let Some(r) = resources.get(&key) {
            queue.extend(r.children.iter().cloned());
        }
    }
    found.remove(start);
    found
}
fn fault(h: Health) -> bool {
    matches!(h, Health::Critical | Health::Warning)
}
pub fn groups(
    resources: &BTreeMap<String, Resource>,
    states: &BTreeMap<String, Health>,
) -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::new();
    for (key, resource) in resources {
        let Some(&level) = states.get(key).filter(|&&h| fault(h)) else {
            continue;
        };
        if !aggregate(resource) {
            continue;
        }
        let below = descendants(key, resources);
        if resource
            .condition_origins
            .iter()
            .any(|origin| !below.contains(origin))
        {
            continue;
        }
        let candidates: Vec<_> = below
            .iter()
            .filter(|child| {
                states.get(*child).is_some_and(|&h| {
                    fault(h) && crate::identity::severity(h) >= crate::identity::severity(level)
                })
            })
            // A retained, currently unknown summary cannot become the fallback
            // alarm after its formerly associated concrete component recovers.
            .filter(|child| {
                resources.get(*child).is_none_or(|r| {
                    !aggregate(r) || r.own_health.is_some_and(fault) || r.rollup.is_some_and(fault)
                })
            })
            .filter(|child| !descendants(child, resources).contains(key))
            .cloned()
            .collect();
        let leaves: Vec<_> = candidates
            .iter()
            .filter(|child| {
                // Independent component faults are never suppressed by their children.
                if resources.get(*child).is_none_or(|r| !aggregate(r)) {
                    return true;
                }
                let deeper = descendants(child, resources);
                !candidates.iter().any(|other| {
                    other != *child
                        && deeper.contains(other)
                        && crate::identity::severity(states[other])
                            >= crate::identity::severity(states[*child])
                })
            })
            .cloned()
            .collect();
        if !leaves.is_empty() {
            result.insert(key.clone(), leaves);
        }
    }
    result
}
pub fn canonicalize(
    resources: &mut BTreeMap<String, Resource>,
    aliases: &BTreeMap<String, String>,
) {
    for (alias, canonical) in aliases {
        if let Some(old) = resources.remove(alias) {
            resources.entry(canonical.clone()).or_insert(old);
        }
        for node in resources.values_mut() {
            if node.associated_systems.remove(alias) {
                node.associated_systems.insert(canonical.clone());
            }
            if node.condition_origins.remove(alias) {
                node.condition_origins.insert(canonical.clone());
            }
            if node.children.remove(alias) {
                node.children.insert(canonical.clone());
            }
        }
    }
    // HPE reports SmartStorage on the system, and its warning on the associated
    // chassis as well. Project only that storage dependency, with reciprocal
    // association evidence; adding Chassis -> ComputerSystem would form a cycle.
    let mut storage_dependencies = Vec::new();
    for (chassis, node) in resources
        .iter()
        .filter(|(_, r)| r.kind.starts_with("#Chassis."))
    {
        for system in &node.associated_systems {
            if let Some(system) = resources
                .get(system)
                .filter(|r| r.kind.starts_with("#ComputerSystem.") && r.children.contains(chassis))
            {
                for child in &system.children {
                    if resources
                        .get(child)
                        .is_some_and(|r| r.kind.rsplit('.').next() == Some("HpeSmartStorage"))
                    {
                        storage_dependencies.push((chassis.clone(), child.clone()));
                    }
                }
            }
        }
    }
    for (chassis, storage) in storage_dependencies {
        resources
            .get_mut(&chassis)
            .unwrap()
            .children
            .insert(storage);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    pub(crate) const SYSTEM: &str = "/redfish/v1/Systems/System.Embedded.1";
    pub(crate) const CHASSIS: &str = "/redfish/v1/Chassis/System.Embedded.1";
    pub(crate) const SUBSYSTEM: &str = "/redfish/v1/Chassis/System.Embedded.1/PowerSubsystem";
    pub(crate) const PSU: &str =
        "/redfish/v1/Chassis/System.Embedded.1/PowerSubsystem/PowerSupplies/PSU.Slot.1";
    pub(crate) const HPE_SUMMARIES: [&str; 5] = [
        "/redfish/v1/Systems/1/",
        "/redfish/v1/Chassis/1/",
        "/redfish/v1/Systems/1/SmartStorage/",
        "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/2/",
        "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/2/LogicalDrives/1/",
    ];
    pub(crate) const HPE_FAILED: &str =
        "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/2/DiskDrives/0/";
    pub(crate) const HPE_OK: &str =
        "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/2/DiskDrives/1/";
    pub(crate) fn fixture() -> crate::model::Snapshot {
        from_fixture(include_str!("../tests/fixtures/dell-r340-hierarchy.json"))
    }
    pub(crate) fn hpe_fixture() -> crate::model::Snapshot {
        from_fixture(include_str!(
            "../tests/fixtures/hpe-smartstorage-hierarchy.json"
        ))
    }
    fn from_fixture(raw: &str) -> crate::model::Snapshot {
        let fixture: Value = serde_json::from_str(raw).unwrap();
        let mut snapshot = crate::model::Snapshot::default();
        let mut observations = BTreeMap::new();
        let mut identities = crate::identity::PsuIdentities::default();
        for resource in fixture["resources"].as_array().unwrap() {
            let uri = resource["uri"].as_str().unwrap();
            let body = &resource["body"];
            crate::collector::normalize(uri, body, &mut observations, &mut snapshot.logs);
            identities.observe(uri, body);
            observe(uri, body, &mut snapshot.resources);
        }
        snapshot.resource_aliases = identities.merge(&mut observations);
        canonicalize(&mut snapshot.resources, &snapshot.resource_aliases);
        snapshot.observations = observations.into_values().collect();
        snapshot
    }
    #[test]
    fn hpe_live_storage_hierarchy_groups_to_the_failed_physical_drive_without_cycles() {
        let snapshot = hpe_fixture();
        let states = snapshot
            .observations
            .iter()
            .map(|o| (o.key.clone(), o.health))
            .collect();
        let grouped = groups(&snapshot.resources, &states);
        for parent in HPE_SUMMARIES {
            assert_eq!(grouped[parent], vec![HPE_FAILED]);
            assert!(!descendants(HPE_FAILED, &snapshot.resources).contains(parent));
        }
        assert!(!grouped.contains_key(HPE_FAILED));
        let drive = snapshot
            .observations
            .iter()
            .find(|o| o.key == HPE_FAILED)
            .unwrap();
        assert_eq!(drive.health, Health::Critical);
        assert!(drive.label.contains("1I:1:1"));
        assert!(!summary(&snapshot.resources[HPE_FAILED]));
    }
    #[test]
    fn hpe_controller_faults_and_unexplained_or_missing_dependencies_remain_separate() {
        let mut snapshot = hpe_fixture();
        let mut states: BTreeMap<_, _> = snapshot
            .observations
            .iter()
            .map(|o| (o.key.clone(), o.health))
            .collect();
        let controller = HPE_SUMMARIES[3];
        snapshot
            .resources
            .get_mut(controller)
            .unwrap()
            .independent_condition = true;
        let grouped = groups(&snapshot.resources, &states);
        assert!(!grouped.contains_key(controller));
        assert!(grouped[HPE_SUMMARIES[2]].contains(&controller.to_owned()));
        assert!(grouped[HPE_SUMMARIES[2]].contains(&HPE_FAILED.to_owned()));
        snapshot
            .resources
            .get_mut(controller)
            .unwrap()
            .independent_condition = false;
        snapshot.resources.get_mut(controller).unwrap().rollup = Some(Health::Ok);
        assert!(!groups(&snapshot.resources, &states).contains_key(controller));
        snapshot.resources.get_mut(controller).unwrap().rollup = None;
        states.insert(HPE_FAILED.into(), Health::Unknown);
        states.insert(HPE_SUMMARIES[4].into(), Health::Unknown);
        assert!(!groups(&snapshot.resources, &states).contains_key(controller));
        // A physical drive with links is still a concrete alarm, not a summary.
        snapshot
            .resources
            .get_mut(HPE_FAILED)
            .unwrap()
            .children
            .insert(HPE_OK.into());
        states.insert(HPE_FAILED.into(), Health::Critical);
        states.insert(HPE_OK.into(), Health::Critical);
        assert!(!groups(&snapshot.resources, &states).contains_key(HPE_FAILED));
    }
    #[test]
    fn hpe_chassis_projection_requires_reciprocal_associations_and_keeps_old_snapshots_readable() {
        let raw: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/hpe-smartstorage-hierarchy.json"
        ))
        .unwrap();
        for remove_forward in [false, true] {
            let mut resources = BTreeMap::new();
            for item in raw["resources"].as_array().unwrap() {
                let mut body = item["body"].clone();
                if remove_forward && item["uri"] == HPE_SUMMARIES[0] {
                    body["Links"].as_object_mut().unwrap().remove("Chassis");
                } else if !remove_forward && item["uri"] == HPE_SUMMARIES[1] {
                    body["Links"]
                        .as_object_mut()
                        .unwrap()
                        .remove("ComputerSystems");
                }
                observe(item["uri"].as_str().unwrap(), &body, &mut resources);
            }
            canonicalize(&mut resources, &BTreeMap::new());
            assert!(!descendants(HPE_SUMMARIES[1], &resources).contains(HPE_FAILED));
        }
        let legacy: Resource = serde_json::from_value(json!({
            "kind":"#Chassis.v1_0_0.Chassis", "own_health":"warning", "rollup":null, "children":[]
        }))
        .unwrap();
        assert!(legacy.associated_systems.is_empty());
    }
    #[test]
    fn live_offline_links_correlate_all_summaries_to_one_retained_psu() {
        let snapshot = fixture();
        assert_eq!(
            snapshot
                .observations
                .iter()
                .find(|o| o.key == PSU)
                .unwrap()
                .health,
            Health::Unknown
        );
        let states = BTreeMap::from([
            (SYSTEM.into(), Health::Critical),
            (CHASSIS.into(), Health::Critical),
            (SUBSYSTEM.into(), Health::Critical),
            (PSU.into(), Health::Critical),
        ]);
        let grouped = groups(&snapshot.resources, &states);
        for parent in [SYSTEM, CHASSIS, SUBSYSTEM] {
            assert_eq!(grouped[parent], vec![PSU]);
        }
    }
    #[test]
    fn unknown_links_stronger_summaries_independent_conditions_and_cycles_stay_separate() {
        let snapshot = fixture();
        let mut nodes = snapshot.resources;
        let mut states = BTreeMap::from([
            (SYSTEM.into(), Health::Critical),
            (PSU.into(), Health::Warning),
        ]);
        assert!(!groups(&nodes, &states).contains_key(SYSTEM));
        states.insert(PSU.into(), Health::Critical);
        nodes
            .get_mut(SYSTEM)
            .unwrap()
            .condition_origins
            .insert("/redfish/v1/Other/Unrelated".into());
        assert!(!groups(&nodes, &states).contains_key(SYSTEM));
        nodes.get_mut(SYSTEM).unwrap().condition_origins.clear();
        nodes.get_mut(SYSTEM).unwrap().independent_condition = true;
        assert!(!groups(&nodes, &states).contains_key(SYSTEM));
        nodes.get_mut(SYSTEM).unwrap().independent_condition = false;
        nodes.get_mut(SYSTEM).unwrap().rollup = Some(Health::Warning);
        assert!(!groups(&nodes, &states).contains_key(SYSTEM));
        nodes.get_mut(SYSTEM).unwrap().rollup = Some(Health::Critical);
        nodes.get_mut(SYSTEM).unwrap().children.clear();
        assert!(!groups(&nodes, &states).contains_key(SYSTEM));
        nodes.get_mut(SYSTEM).unwrap().children.insert(PSU.into());
        nodes.get_mut(PSU).unwrap().children.insert(SYSTEM.into());
        assert!(!groups(&nodes, &states).contains_key(SYSTEM));
        let mut collected = BTreeMap::new();
        observe(
            SYSTEM,
            &json!({"@odata.type":"#ComputerSystem.v1_0_0.ComputerSystem","Status":{"Health":"Critical","Conditions":[{"Severity":"Critical"}]},"Links":{"PoweredBy":[{"@odata.id":PSU}]}}),
            &mut collected,
        );
        assert!(collected[SYSTEM].independent_condition);
        let mut absent_severity = BTreeMap::new();
        observe(
            SYSTEM,
            &json!({"@odata.type":"#ComputerSystem.v1_0_0.ComputerSystem","Status":{"Health":"Critical","Conditions":[{"MessageId":"Test.SelfFault"}]}}),
            &mut absent_severity,
        );
        assert!(absent_severity[SYSTEM].independent_condition);
    }
    #[test]
    fn independent_component_faults_and_distinct_faults_are_not_merged() {
        let mut snapshot = fixture();
        let second = PSU.replace("Slot.1", "Slot.2");
        let states = BTreeMap::from([
            (SYSTEM.into(), Health::Critical),
            (PSU.into(), Health::Critical),
            (second.clone(), Health::Critical),
        ]);
        let grouped = groups(&snapshot.resources, &states);
        assert_eq!(grouped[SYSTEM].len(), 2);
        assert!(!grouped.contains_key(PSU));
        assert!(!grouped.contains_key(&second));
        snapshot.resources.get_mut(PSU).unwrap().kind = "#Power.v1_7_1.PowerSupply".into();
        snapshot
            .resources
            .get_mut(PSU)
            .unwrap()
            .children
            .insert(second.clone());
        assert!(!groups(&snapshot.resources, &states).contains_key(PSU));
    }
}

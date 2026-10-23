//! Extract only explicitly advertised HPE power health and redundancy.
//! Local fragment identities are never enqueued as HTTP requests. These checks
//! remain independent of individual PSU absence and never infer a redundancy
//! requirement from inventory, capacity, bay count or previous observations.
use serde_json::{json, Value};

fn resource(key: &str, label: &str, status: &Value, minimum: Option<&str>) -> Value {
    let mut status = status.as_object().cloned().unwrap_or_default();
    let rank = |s: &str| match s {
        "Critical" => 3,
        "Warning" => 2,
        "OK" => 1,
        _ => 0,
    };
    let strongest = [
        status.get("Health").and_then(Value::as_str),
        status.get("HealthRollup").and_then(Value::as_str),
        minimum,
    ]
    .into_iter()
    .flatten()
    .chain(
        status
            .get("Conditions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("Severity").and_then(Value::as_str)),
    )
    .max_by_key(|s| rank(s))
    .unwrap_or("Unknown")
    .to_owned();
    status.insert("Health".into(), json!(strongest));
    json!({"@odata.id":key,"Name":label,"Status":status})
}

fn redundancy(out: &mut Vec<Value>, key: String, label: &str, value: &Value) {
    let reported = value.as_str().unwrap_or("Unknown");
    let health = match reported {
        "Redundant" | "NonRedundant" => "OK",
        "FailedRedundant" => "Warning",
        _ => "Unknown",
    };
    let reported: String = reported
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    out.push(resource(
        &key,
        &format!("{label} [{reported}]"),
        &json!({}),
        Some(health),
    ));
}

pub(crate) fn summaries(fallback: &str, value: &Value) -> Vec<Value> {
    let key = value
        .get("@odata.id")
        .and_then(Value::as_str)
        .unwrap_or(fallback);
    // Synthetic child resources have no schema and cannot recurse into this path.
    let kind = value
        .get("@odata.type")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut out = Vec::new();
    if kind.starts_with("#ComputerSystem.") && kind.ends_with(".ComputerSystem") {
        if let Some(aggregate) = value.pointer("/Oem/Hpe/AggregateHealthStatus") {
            let base = format!("{key}#/Oem/Hpe/AggregateHealthStatus");
            if let Some(supplies) = aggregate.get("PowerSupplies") {
                let mismatch = supplies
                    .get("PowerSuppliesMismatch")
                    .and_then(Value::as_bool)
                    == Some(true);
                out.push(resource(
                    &format!("{base}/PowerSupplies"),
                    "Netzteile (HPE-Gesamtzustand)",
                    supplies.get("Status").unwrap_or(&Value::Null),
                    mismatch.then_some("Warning"),
                ));
            }
            if let Some(state) = aggregate.get("PowerSupplyRedundancy") {
                redundancy(
                    &mut out,
                    format!("{base}/PowerSupplyRedundancy"),
                    "Netzteilredundanz (HPE)",
                    state,
                );
            }
        }
    }
    if kind.starts_with("#Power.") && kind.ends_with(".Power") {
        if let Some(domains) = value.pointer("/Oem/Hpe/Domains").and_then(Value::as_array) {
            for (index, domain) in domains.iter().enumerate() {
                let base = format!("{key}#/Oem/Hpe/Domains/{index}");
                if let Some(status) = domain.get("Status") {
                    out.push(resource(
                        &base,
                        &format!("Stromversorgungsdomäne (HPE) [{}]", index + 1),
                        status,
                        None,
                    ));
                }
                if let Some(state) = domain.get("PowerSupplyRedundancy") {
                    redundancy(
                        &mut out,
                        format!("{base}/PowerSupplyRedundancy"),
                        &format!("Netzteilredundanz (HPE) [{}]", index + 1),
                        state,
                    );
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AssessmentExclusion, Health, Snapshot};
    use std::collections::BTreeMap;

    fn assess(values: &[Value]) -> Snapshot {
        let mut snapshot = Snapshot::default();
        let mut observations = BTreeMap::new();
        let mut applicability = crate::assessment::Applicability::default();
        let mut identities = crate::identity::PsuIdentities::default();
        for v in values {
            let key = v["@odata.id"].as_str().unwrap();
            crate::collector::normalize(key, v, &mut observations, &mut snapshot.logs);
            applicability.observe(key, v);
            identities.observe(key, v);
            crate::correlation::observe(key, v, &mut snapshot.resources);
        }
        snapshot.resource_aliases = identities.merge(&mut observations);
        snapshot.assessment_exclusions = applicability.exclusions(&observations);
        snapshot.observations = observations.into_values().collect();
        snapshot
    }
    fn health(s: &Snapshot, key: &str) -> Health {
        s.observations.iter().find(|o| o.key == key).unwrap().health
    }
    fn system(aggregate: Value) -> Value {
        json!({"@odata.id":"/redfish/v1/Systems/1/","@odata.type":"#ComputerSystem.v1_19_0.ComputerSystem",
            "PowerState":"Off","Status":{"Health":"OK","State":"Disabled"},
            "Oem":{"Hpe":{"AggregateHealthStatus":aggregate}}})
    }
    const SUPPLIES: &str = "/redfish/v1/Systems/1/#/Oem/Hpe/AggregateHealthStatus/PowerSupplies";
    const REDUNDANCY: &str =
        "/redfish/v1/Systems/1/#/Oem/Hpe/AggregateHealthStatus/PowerSupplyRedundancy";

    #[test]
    fn live_powered_off_inventory_is_neutral_and_explicit_power_aggregate_is_ok() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/hpe-ilo6-179-power-off.json"
        ))
        .unwrap();
        let values: Vec<_> = fixture["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["body"].clone())
            .collect();
        let original = values.clone();
        let s = assess(&values);
        for key in [
            "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/0/",
            "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1/",
            "/redfish/v1/Chassis/1/Power/#PowerSupplies/1",
        ] {
            assert_eq!(health(&s, key), Health::Unknown);
            assert_eq!(s.assessment_exclusions[key], AssessmentExclusion::Absent);
        }
        assert_eq!(
            health(&s, "/redfish/v1/Chassis/1/Power/#PowerSupplies/0"),
            Health::Ok
        );
        assert_eq!(health(&s, SUPPLIES), Health::Ok);
        assert!(!s.observations.iter().any(|o| o.key == REDUNDANCY));
        assert!(!s
            .observations
            .iter()
            .any(|o| matches!(o.health, Health::Warning | Health::Critical)));
        assert_eq!(values, original);
    }

    #[test]
    fn inventory_and_stale_wattage_do_not_turn_hpe_absence_into_a_fault_or_reading() {
        for oem_state in [None, Some("Ok"), Some("GoodInStandby")] {
            let mut v = json!({"@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/0/",
                "@odata.type":"#PowerSupply.v1_6_0.PowerSupply","Name":"HpeServerPowerSupply",
                "SerialNumber":"INSTALLED","Manufacturer":"ACBEL","Model":"P03178-B21","SparePartNumber":"P44412-001",
                "PowerCapacityWatts":1000,"LastPowerOutputWatts":29,"Reading":29,
                "Status":{"State":"Absent","Health":"Warning"}});
            if let Some(state) = oem_state {
                v["Oem"] = json!({"Hpe":{"@odata.type":"#HpeServerPowerSupply.v2_1_0.HpeServerPowerSupply",
                    "PowerSupplyStatus":{"State":state}}});
            }
            let s = assess(&[v]);
            assert_eq!(s.observations[0].health, Health::Unknown);
            assert_eq!(s.observations[0].reading, None);
            assert_eq!(s.assessment_exclusions.len(), 1);
        }
    }

    #[test]
    fn failed_aggregate_and_mismatch_stay_alarms_while_host_is_disabled() {
        for (status, mismatch, expected) in [
            (json!({"Health":"Warning"}), false, Health::Warning),
            (json!({"Health":"Critical"}), false, Health::Critical),
            (
                json!({"Health":"OK","HealthRollup":"Critical"}),
                true,
                Health::Critical,
            ),
            (json!({"Health":"OK"}), true, Health::Warning),
            (
                json!({"Health":"OK","Conditions":[{"Severity":"Critical"}]}),
                false,
                Health::Critical,
            ),
        ] {
            let s = assess(&[system(
                json!({"PowerSupplies":{"Status":status,"PowerSuppliesMismatch":mismatch}}),
            )]);
            assert_eq!(health(&s, SUPPLIES), expected);
            assert!(!s.assessment_exclusions.contains_key(SUPPLIES));
            assert_eq!(s.resources[SUPPLIES].own_health, Some(expected));
            assert!(s.resources["/redfish/v1/Systems/1/"]
                .children
                .contains(SUPPLIES));
            let evaluation = crate::acknowledgement::Evaluation {
                statuses: BTreeMap::new(),
            };
            assert_eq!(
                evaluation.overall(Some(&s), false),
                if expected == Health::Critical {
                    "critical"
                } else {
                    "warning"
                }
            );
        }
    }

    #[test]
    fn redundancy_requires_explicit_device_evidence_and_nonredundant_is_not_a_failure() {
        for (state, expected) in [
            (json!("Redundant"), Health::Ok),
            (json!("NonRedundant"), Health::Ok),
            (json!("FailedRedundant"), Health::Warning),
            (json!("Unknown"), Health::Unknown),
            (Value::Null, Health::Unknown),
            (json!("FutureValue"), Health::Unknown),
        ] {
            let s = assess(&[system(json!({"PowerSupplyRedundancy":state}))]);
            assert_eq!(health(&s, REDUNDANCY), expected);
            assert!(!s.assessment_exclusions.contains_key(REDUNDANCY));
        }
        assert!(summaries("", &system(json!({}))).is_empty());
        let s = assess(&[system(
            json!({"PowerSupplies":{"PowerSuppliesMismatch":false}}),
        )]);
        assert_eq!(health(&s, SUPPLIES), Health::Unknown);
    }

    #[test]
    fn legacy_domain_and_both_standard_redundancy_arrays_preserve_faults() {
        let legacy = json!({"@odata.id":"/redfish/v1/Chassis/1/Power/","@odata.type":"#Power.v1_7_1.Power",
            "Redundancy":[{"MemberId":"0","Status":{"Health":"Critical"}}],
            "Oem":{"Hpe":{"Domains":[{"Status":{"Health":"Warning"},"PowerSupplyRedundancy":"FailedRedundant"},
                {"PowerSupplyRedundancy":"NonRedundant"}]}}});
        let modern = json!({"@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem/","@odata.type":"#PowerSubsystem.v1_1_2.PowerSubsystem",
            "PowerSupplyRedundancy":[{"Status":{"Health":"Critical"},"RedundancyType":"NotRedundant"}]});
        let s = assess(&[legacy, modern]);
        for (key, h) in [
            (
                "/redfish/v1/Chassis/1/Power/#Redundancy:0",
                Health::Critical,
            ),
            (
                "/redfish/v1/Chassis/1/Power/#/Oem/Hpe/Domains/0",
                Health::Warning,
            ),
            (
                "/redfish/v1/Chassis/1/Power/#/Oem/Hpe/Domains/0/PowerSupplyRedundancy",
                Health::Warning,
            ),
            (
                "/redfish/v1/Chassis/1/Power/#/Oem/Hpe/Domains/1/PowerSupplyRedundancy",
                Health::Ok,
            ),
            (
                "/redfish/v1/Chassis/1/PowerSubsystem/#PowerSupplyRedundancy:0",
                Health::Critical,
            ),
        ] {
            assert_eq!(health(&s, key), h, "{key}");
            assert_eq!(s.resources[key].own_health, Some(h), "{key}");
            assert!(!s.assessment_exclusions.contains_key(key));
        }
    }

    #[test]
    fn unrelated_oem_objects_and_log_records_do_not_create_power_summaries() {
        let mut v = system(json!({"PowerSupplies":{"Status":{"Health":"Critical"}}}));
        v["@odata.type"] = json!("#Other.v1_0_0.Other");
        assert!(summaries("", &v).is_empty());
        assert!(summaries("", &json!({"Message":"PSU removed","Severity":"Warning"})).is_empty());
    }
}

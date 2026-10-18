use crate::model::*;
use anyhow::{Context, Result};
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;
use url::Url;

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_RESOURCES: usize = 256;
pub(crate) const LINK_KEYS: &[&str] = &[
    "Systems",
    "Chassis",
    "Managers",
    "Storage",
    "SimpleStorage",
    "Controllers",
    "Drives",
    "Volumes",
    "Thermal",
    "Power",
    "PowerSubsystem",
    "ThermalSubsystem",
    "Fans",
    "Temperatures",
    "Voltages",
    "PowerControl",
    "Redundancy",
    "PowerSupplies",
    "Sensors",
    "LogServices",
    "Entries",
    "SmartStorage",
    "ArrayControllers",
    "DiskDrives",
    "LogicalDrives",
    "StorageControllers",
];

pub struct Redfish {
    client: Client,
    origin: Url,
}

impl Redfish {
    pub fn new(device: &Device) -> Result<Self> {
        device.validate()?;
        let origin = Url::parse(&device.endpoint)?;
        let redirect_origin = origin.clone();
        let redirects = Policy::custom(move |attempt| {
            if attempt.previous().len() >= 4
                || safe_link(&redirect_origin, attempt.url().as_str()).is_err()
            {
                attempt.error("unsafe or excessive Redfish redirect")
            } else {
                attempt.follow()
            }
        });
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(redirects)
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(1)
            .user_agent(concat!("hardware-monitor/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = &device.ca_file {
            let ca = std::fs::read(path).context("read device CA certificate")?;
            for cert in reqwest::Certificate::from_pem_bundle(&ca)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        if let Some(pem) = &device.ca_pem {
            for cert in reqwest::Certificate::from_pem_bundle(pem.as_bytes())? {
                builder = builder.add_root_certificate(cert);
            }
        }
        Ok(Self {
            client: builder.build()?,
            origin,
        })
    }

    pub async fn poll(&self, username: &str, password: &str) -> Result<Snapshot> {
        tokio::time::timeout(Duration::from_secs(90), self.walk(username, password))
            .await
            .context("poll deadline exceeded")?
    }

    /// A bounded read of the service root. Does not change BMC configuration or
    /// record historical hardware logs, alarms or monitoring snapshots.
    pub async fn probe(&self, username: &str, password: &str) -> Result<Value> {
        let mut response = self
            .client
            .get(self.origin.join("redfish/v1/")?)
            .basic_auth(username, Some(password))
            .header("OData-Version", "4.0")
            .send()
            .await
            .map_err(|_| anyhow::anyhow!(crate::dsm::BoundaryError("connection_tls_or_network")))?;
        match response.status() {
            StatusCode::UNAUTHORIZED => {
                anyhow::bail!(crate::dsm::BoundaryError("connection_credentials_rejected"))
            }
            StatusCode::FORBIDDEN => {
                anyhow::bail!(crate::dsm::BoundaryError("connection_permission_denied"))
            }
            status if !status.is_success() => {
                anyhow::bail!(crate::dsm::BoundaryError("connection_http_error"))
            }
            _ => {}
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            anyhow::anyhow!(crate::dsm::BoundaryError("connection_response_invalid"))
        })? {
            anyhow::ensure!(
                bytes.len() + chunk.len() <= 512 * 1024,
                crate::dsm::BoundaryError("connection_response_too_large")
            );
            bytes.extend_from_slice(&chunk);
        }
        let root: Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!(crate::dsm::BoundaryError("connection_not_redfish")))?;
        anyhow::ensure!(
            root.is_object()
                && (root.get("RedfishVersion").is_some()
                    || ["Systems", "Chassis", "Managers"]
                        .iter()
                        .any(|k| root.get(k).is_some())),
            crate::dsm::BoundaryError("connection_not_redfish")
        );
        Ok(
            serde_json::json!({"reachable":true,"redfish_version":root.get("RedfishVersion").and_then(Value::as_str).map(|s|s.chars().take(80).collect::<String>()),"systems":root.get("Systems").is_some(),"chassis":root.get("Chassis").is_some(),"managers":root.get("Managers").is_some()}),
        )
    }

    async fn get_with_retry(
        &self,
        url: Url,
        username: &str,
        password: &str,
    ) -> (reqwest::Result<reqwest::Response>, u8) {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let response = self
                .client
                .get(url.clone())
                .header("OData-Version", "4.0")
                .basic_auth(username, Some(password))
                .send()
                .await;
            let retry = match &response {
                Ok(r) => matches!(r.status().as_u16(), 500 | 502 | 503 | 504),
                Err(e) => e.is_timeout(),
            };
            if retry && attempts < 2 {
                drop(response);
                tokio::time::sleep(Duration::from_millis(300)).await;
            } else {
                return (response, attempts);
            }
        }
    }

    async fn walk(&self, username: &str, password: &str) -> Result<Snapshot> {
        let mut queue = VecDeque::from(["/redfish/v1/".to_owned()]);
        let mut visited = HashSet::new();
        let mut result = Snapshot {
            logs_complete: true,
            ..Default::default()
        };
        let mut total_bytes = 0usize;
        let mut observations = BTreeMap::new();
        let mut identities = crate::identity::PsuIdentities::default();
        while let Some(path) = queue.pop_front() {
            let url = safe_link(&self.origin, &path)?;
            if !visited.insert(url.to_string()) {
                continue;
            }
            anyhow::ensure!(
                visited.len() <= MAX_RESOURCES,
                "Redfish resource budget exceeded; poll discarded"
            );
            let (response, attempts) = self.get_with_retry(url, username, password).await;
            let mut response = match response {
                Ok(r) => r,
                Err(_) => {
                    if visited.len() == 1 {
                        anyhow::bail!("Redfish connection/TLS failure");
                    }
                    result.logs_complete = false;
                    result.capabilities.push(Capability {
                        uri: path.clone(),
                        outcome: "transport_error".into(),
                        http_status: None,
                        attempts,
                    });
                    continue;
                }
            };
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED {
                anyhow::bail!("Redfish authentication rejected");
            }
            if !status.is_success() {
                if visited.len() == 1 {
                    anyhow::bail!("Redfish root returned HTTP {}", status.as_u16());
                }
                result.logs_complete = false;
                result.capabilities.push(Capability {
                    uri: path.clone(),
                    outcome: match status {
                        StatusCode::FORBIDDEN => "forbidden_permission_or_license",
                        StatusCode::NOT_FOUND => "not_found",
                        _ => "http_error",
                    }
                    .into(),
                    http_status: Some(status.as_u16()),
                    attempts,
                });
                continue;
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    bytes.len() + chunk.len() <= MAX_BODY,
                    "Redfish response exceeds size limit"
                );
                bytes.extend_from_slice(&chunk);
                total_bytes += chunk.len();
                anyhow::ensure!(
                    total_bytes <= 16 * 1024 * 1024,
                    "Redfish poll byte budget exceeded"
                );
            }
            let value: Value = serde_json::from_slice(&bytes).context("invalid Redfish JSON")?;
            anyhow::ensure!(value.is_object(), "Redfish resource must be an object");
            result.capabilities.push(Capability {
                uri: path.clone(),
                outcome: "available".into(),
                http_status: Some(status.as_u16()),
                attempts,
            });
            normalize(&path, &value, &mut observations, &mut result.logs);
            identities.observe(&path, &value);
            crate::correlation::observe(&path, &value, &mut result.resources);
            anyhow::ensure!(
                observations.len() <= 4096 && result.logs.len() <= 4096,
                "Redfish item budget exceeded"
            );
            discover(&value, &mut queue);
        }
        result.resource_aliases = identities.merge(&mut observations);
        crate::correlation::canonicalize(&mut result.resources, &result.resource_aliases);
        for capability in &result.capabilities {
            observations.insert(
                format!("coverage:{}", capability.uri),
                Observation {
                    key: format!("coverage:{}", capability.uri),
                    label: format!("{}: {}", capability.uri, capability_description(capability)),
                    health: if capability.outcome == "available" {
                        Health::Ok
                    } else {
                        Health::Warning
                    },
                    reading: None,
                    unit: None,
                },
            );
        }
        result.observations = observations.into_values().collect();
        result.observations.push(Observation {
            key: "collector".into(),
            label: "Management-Abfrage erfolgreich".into(),
            health: Health::Ok,
            reading: None,
            unit: None,
        });
        Ok(result)
    }
}

pub fn safe_link(origin: &Url, path: &str) -> Result<Url> {
    let target = origin.join(path)?;
    anyhow::ensure!(
        target.scheme() == "https"
            && target.origin() == origin.origin()
            && target.username().is_empty()
            && target.password().is_none()
            && target.fragment().is_none()
            && (target.path() == "/redfish/v1" || target.path().starts_with("/redfish/v1/")),
        "unsafe Redfish link rejected"
    );
    Ok(target)
}

fn add_links(value: &Value, queue: &mut VecDeque<String>) {
    if let Some(link) = value.get("@odata.id").and_then(Value::as_str) {
        // Fragment identifiers address embedded JSON objects already normalized from the parent.
        // They are never independent HTTP requests; safe_link remains strict for real requests.
        if !link.contains('#') {
            queue.push_back(link.into());
        }
    }
    if let Some(array) = value.as_array() {
        for v in array {
            add_links(v, queue);
        }
    }
}

fn discover(value: &Value, queue: &mut VecDeque<String>) {
    for key in LINK_KEYS {
        if let Some(v) = value.get(*key) {
            add_links(v, queue);
        }
    }
    if let Some(members) = value.get("Members").and_then(Value::as_array) {
        for member in members {
            // Expanded Redfish members already contain their representation. Fetch only links.
            // This avoids thousands of redundant GETs for paged Dell Lifecycle/SEL entries.
            let expanded = member.get("Status").is_some()
                || (member.get("Message").is_some()
                    && (member.get("EntryType").is_some() || member.get("Created").is_some()))
                || member.get("ReadingCelsius").is_some()
                || member.get("Reading").is_some();
            if !expanded {
                add_links(member, queue);
            }
            discover(member, queue);
        }
    }
    for key in ["Members@odata.nextLink", "@odata.nextLink"] {
        if let Some(path) = value.get(key).and_then(Value::as_str) {
            queue.push_back(path.into());
        }
    }
    // HPE OEM discovery without fixed system IDs or paths to writable configuration resources.
    if let Some(hpe) = value.pointer("/Oem/Hpe") {
        for key in ["Links", "SmartStorage"] {
            if let Some(v) = hpe.get(key) {
                add_links(v, queue);
                discover(v, queue);
            }
        }
    }
    if let Some(links) = value.get("Links") {
        for key in ["DiskDrives", "LogicalDrives", "ArrayControllers"] {
            if let Some(v) = links.get(key) {
                add_links(v, queue);
            }
        }
    }
}

fn capability_description(capability: &Capability) -> String {
    if capability.outcome == "available" {
        if capability.attempts > 1 {
            "erfolgreich nach Wiederholung".into()
        } else {
            "erfolgreich".into()
        }
    } else if let Some(status) = capability.http_status {
        format!(
            "HTTP {status}{}",
            if capability.attempts > 1 {
                " nach Wiederholung"
            } else {
                ""
            }
        )
    } else {
        "Netzwerk- oder TLS-Fehler".into()
    }
}

fn unavailable(value: &Value) -> bool {
    matches!(
        value.pointer("/Status/State").and_then(Value::as_str),
        Some(
            "Absent"
                | "UnavailableOffline"
                | "StandbyOffline"
                | "Disabled"
                | "Starting"
                | "Updating"
                | "InTest"
        )
    )
}

fn health(value: &Value) -> Health {
    // Explicit BMC faults remain faults even when the failed component is offline.
    // Availability still prevents an OK status or stale readings being trusted.
    let fields = [
        value.pointer("/Status/Health"),
        value.pointer("/Status/HealthRollup"),
    ];
    if fields
        .iter()
        .any(|v| v.and_then(Value::as_str) == Some("Critical"))
    {
        Health::Critical
    } else if fields
        .iter()
        .any(|v| v.and_then(Value::as_str) == Some("Warning"))
    {
        Health::Warning
    } else if unavailable(value) {
        Health::Unknown
    } else if fields
        .iter()
        .any(|v| v.and_then(Value::as_str) == Some("OK"))
    {
        Health::Ok
    } else {
        Health::Unknown
    }
}

pub(crate) fn normalize(
    uri: &str,
    value: &Value,
    observations: &mut BTreeMap<String, Observation>,
    logs: &mut Vec<HardwareLog>,
) {
    let is_log = value.get("Message").is_some()
        && (value.get("EntryType").is_some() || value.get("Created").is_some());
    if is_log {
        let message = value.get("Message").and_then(Value::as_str).unwrap_or("");
        let created = value
            .get("Created")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // The timestamp/message protect against reused entry IDs after log clear or rollover.
        let canonical = value
            .get("@odata.id")
            .and_then(Value::as_str)
            .unwrap_or(uri)
            .split(['?', '#'])
            .next()
            .unwrap_or(uri);
        let identity = serde_json::to_vec(&(canonical, value.get("Id"), &created, message))
            .unwrap_or_default();
        logs.push(HardwareLog {
            fingerprint: format!("{:x}", Sha256::digest(identity)),
            message: message.chars().take(1000).collect(),
            severity: match value.get("Severity").and_then(Value::as_str) {
                Some("Critical") => Health::Critical,
                Some("Warning") => Health::Warning,
                Some("OK") => Health::Ok,
                _ => Health::Unknown,
            },
            created,
        });
        return;
    }
    if value.get("Status").is_some()
        || value.get("ReadingCelsius").is_some()
        || value.get("Reading").is_some()
        || value.get("ReadingVolts").is_some()
        || value.get("PowerConsumedWatts").is_some()
    {
        let mut h = health(value);
        let reading = value
            .get("ReadingCelsius")
            .or_else(|| value.get("ReadingVolts"))
            .or_else(|| value.get("PowerConsumedWatts"))
            .or_else(|| value.get("Reading"))
            .and_then(Value::as_f64)
            .filter(|_| !unavailable(value));
        let unit = if value.get("ReadingCelsius").is_some() {
            Some("Cel".into())
        } else if value.get("ReadingVolts").is_some() {
            Some("V".into())
        } else if value.get("PowerConsumedWatts").is_some() {
            Some("W".into())
        } else {
            value
                .get("ReadingUnits")
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        if let Some(reading) = reading {
            let upper_critical = value.get("UpperThresholdCritical").and_then(Value::as_f64);
            let upper_warning = value
                .get("UpperThresholdNonCritical")
                .and_then(Value::as_f64);
            let lower_critical = value.get("LowerThresholdCritical").and_then(Value::as_f64);
            let lower_warning = value
                .get("LowerThresholdNonCritical")
                .and_then(Value::as_f64);
            if upper_critical.is_some_and(|n| reading >= n)
                || lower_critical.is_some_and(|n| reading <= n)
            {
                h = Health::Critical;
            } else if (upper_warning.is_some_and(|n| reading >= n)
                || lower_warning.is_some_and(|n| reading <= n))
                && h != Health::Critical
            {
                h = Health::Warning;
            }
        }
        let key = value
            .get("@odata.id")
            .and_then(Value::as_str)
            .unwrap_or(uri)
            .to_owned();
        observations.insert(
            key.clone(),
            Observation {
                key,
                label: {
                    let name = value
                        .get("Name")
                        .and_then(Value::as_str)
                        .unwrap_or(uri)
                        .chars()
                        .take(200)
                        .collect::<String>();
                    let aggregate = value
                        .get("@odata.type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| {
                            kind.contains("ComputerSystem.") || kind.contains("Chassis.")
                        });
                    let name = if aggregate {
                        format!("{name} – Gesamtgesundheit")
                    } else {
                        name
                    };
                    match value.get("PowerState").and_then(Value::as_str) {
                        Some("Off") => format!("{name} (Betrieb: ausgeschaltet)"),
                        Some("On") => format!("{name} (Betrieb: eingeschaltet)"),
                        Some("PoweringOn") => format!("{name} (Betrieb: wird eingeschaltet)"),
                        Some("PoweringOff") => format!("{name} (Betrieb: wird ausgeschaltet)"),
                        _ => name,
                    }
                },
                health: h,
                reading,
                unit,
            },
        );
    }
    for key in LINK_KEYS.iter().chain(["Members"].iter()) {
        if let Some(array) = value.get(*key).and_then(Value::as_array) {
            for (index, item) in array.iter().enumerate() {
                normalize(
                    &crate::correlation::embedded_uri(uri, key, item, index),
                    item,
                    observations,
                    logs,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn live_dell_fragments_are_local_objects_and_are_not_fetched() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/dell-r340-redfish.json")).unwrap();
        let mut queue = VecDeque::new();
        let mut observations = BTreeMap::new();
        let mut logs = Vec::new();
        for resource in fixture["resources"].as_array().unwrap() {
            normalize(
                resource["uri"].as_str().unwrap(),
                &resource["body"],
                &mut observations,
                &mut logs,
            );
            discover(&resource["body"], &mut queue);
        }
        assert!(queue.iter().all(|uri| !uri.contains('#')));
        assert!(observations
            .keys()
            .any(|uri| uri.contains("#/Temperatures/")));
        assert!(observations
            .keys()
            .any(|uri| uri.contains("#/PowerSupplies/")));
        assert!(observations
            .keys()
            .any(|uri| uri.contains("#/StorageControllers/")));
    }
    #[test]
    fn expanded_log_members_need_no_individual_gets() {
        let page = json!({"Members":[{"@odata.id":"/redfish/v1/Managers/1/LogServices/SEL/Entries/1","Id":"1","Message":"Synthetic test","EntryType":"Event","Created":"2026-01-01T00:00:00Z"}],"Members@odata.nextLink":"/redfish/v1/Managers/1/LogServices/SEL/Entries?$skip=1"});
        let mut queue = VecDeque::new();
        discover(&page, &mut queue);
        assert_eq!(
            queue,
            VecDeque::from(["/redfish/v1/Managers/1/LogServices/SEL/Entries?$skip=1".to_owned()])
        );
    }
    #[test]
    fn links_are_same_origin_and_read_only_discovery() {
        let origin = Url::parse("https://ilo.example/").unwrap();
        for path in [
            "https://evil.example/redfish/v1/",
            "//evil.example/redfish/v1/",
            "http://ilo.example/redfish/v1/",
            "/etc/passwd",
            "/redfish/v1/../../webapi",
            "https://user@ilo.example/redfish/v1/",
        ] {
            assert!(safe_link(&origin, path).is_err(), "{path}");
        }
        assert!(safe_link(&origin, "/redfish/v1/Systems?$skip=20").is_ok());
        let mut queue = VecDeque::new();
        discover(
            &json!({"Oem":{"Hpe":{"Links":{"SmartStorage":{"@odata.id":"/redfish/v1/Systems/42/SmartStorage"}}}},"Actions":{"Reset":{"target":"/reset"}}}),
            &mut queue,
        );
        assert_eq!(
            queue,
            VecDeque::from(["/redfish/v1/Systems/42/SmartStorage".to_owned()])
        );
    }
    #[test]
    fn unavailable_state_never_reports_ok_or_uses_stale_readings() {
        for state in ["Absent", "UnavailableOffline", "StandbyOffline", "Disabled"] {
            let value = json!({"Name":"sensor","Status":{"State":state,"Health":"OK"},"Reading":100,"UpperThresholdCritical":90});
            let mut observations = BTreeMap::new();
            let mut logs = Vec::new();
            normalize("/redfish/v1/sensor", &value, &mut observations, &mut logs);
            let observation = observations.values().next().unwrap();
            assert_eq!(observation.health, Health::Unknown);
            assert_eq!(observation.reading, None);
        }
    }
    #[test]
    fn explicit_offline_faults_survive_normalization_without_trusting_readings() {
        // Regression for the real PS1: Critical + UnavailableOffline was lost.
        for state in [
            "Absent",
            "UnavailableOffline",
            "StandbyOffline",
            "Disabled",
            "Starting",
            "Updating",
            "InTest",
        ] {
            for (field, severity, expected) in [
                ("Health", "Critical", Health::Critical),
                ("Health", "Warning", Health::Warning),
                ("HealthRollup", "Critical", Health::Critical),
                ("HealthRollup", "Warning", Health::Warning),
            ] {
                let mut value = json!({"Name":"PS1 Status", "Status":{"State":state},"Reading":100,"UpperThresholdCritical":90});
                value["Status"][field] = json!(severity);
                let mut observations = BTreeMap::new();
                normalize(
                    "/redfish/v1/Chassis/test/Power#/PowerSupplies/0",
                    &value,
                    &mut observations,
                    &mut Vec::new(),
                );
                let observation = observations.values().next().unwrap();
                assert_eq!(observation.health, expected, "{state} {field} {severity}");
                assert_eq!(observation.reading, None);
            }
        }
        // Once available again, a fresh explicit OK can resolve the alarm.
        assert_eq!(
            health(&json!({"Status":{"State":"Enabled","Health":"OK"}})),
            Health::Ok
        );
    }
    #[test]
    fn power_state_cannot_create_or_clear_health_faults() {
        for power in ["On", "Off", "PoweringOn", "PoweringOff"] {
            for (reported, expected) in [("OK", Health::Ok), ("Critical", Health::Critical)] {
                let value = json!({"@odata.type":"#ComputerSystem.v1_17_0.ComputerSystem","Name":"System","PowerState":power,"Status":{"Health":reported,"State":"Enabled"}});
                let mut observations = BTreeMap::new();
                normalize(
                    "/redfish/v1/Systems/test",
                    &value,
                    &mut observations,
                    &mut Vec::new(),
                );
                let observation = observations.values().next().unwrap();
                assert_eq!(observation.health, expected);
                assert!(observation.label.contains("Gesamtgesundheit"));
            }
        }
    }
    #[test]
    fn vendor_fixtures_health_and_thresholds() {
        for fixture in [
            include_str!("../tests/fixtures/hpe-thermal.json"),
            include_str!("../tests/fixtures/dell-storage.json"),
        ] {
            let value: Value = serde_json::from_str(fixture).unwrap();
            let mut observations = BTreeMap::new();
            let mut logs = Vec::new();
            normalize("/redfish/v1/test", &value, &mut observations, &mut logs);
            assert!(observations.values().any(|o| o.health == Health::Critical));
            assert!(observations.values().any(|o| o.health == Health::Unknown));
        }
    }
}

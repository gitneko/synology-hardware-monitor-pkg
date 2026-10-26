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

#[derive(Debug)]
pub struct PollFailure {
    uri: String,
    reason: &'static str,
}
impl PollFailure {
    fn new(uri: &str, reason: &'static str) -> Self {
        Self {
            uri: uri
                .split(['?', '#'])
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect(),
            reason,
        }
    }
}
impl std::fmt::Display for PollFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.uri, failure_description(self.reason))
    }
}
impl std::error::Error for PollFailure {}

pub fn poll_failure_label(error: &anyhow::Error) -> String {
    match error.downcast_ref::<PollFailure>() {
        Some(failure) => format!("Management-Abfrage fehlgeschlagen · {failure}"),
        None => {
            "Management-Abfrage fehlgeschlagen (Netzwerk, TLS, Anmeldung oder Zeitlimit)".into()
        }
    }
}

pub fn failure_description(reason: &str) -> &'static str {
    match reason {
        "log_selection_unsupported" => {
            "Chronologische Hardwarelog-Auswahl vom Controller nicht unterstützt"
        }
        "deadline" => "Zeitlimit der vollständigen Abfrage erreicht",
        "resource_limit" => "Ressourcenlimit der Abfrage erreicht",
        "byte_limit" => "Datenmengenlimit der Abfrage erreicht",
        "item_limit" => "Messwert- oder Hardwareloglimit erreicht",
        "response_limit" => "Antwort überschreitet das Größenlimit",
        "invalid_response" => "Ungültige Redfish-Antwort",
        "authentication" => "Anmeldung abgewiesen (HTTP 401)",
        "http_error" => "HTTP-Fehler an der Redfish-Startseite",
        "certificate_error" => "Serverzertifikat stimmt nicht überein oder ist zeitlich ungültig",
        "timeout" => "Zeitlimit der Teilabfrage erreicht",
        "unsafe_link" => "Unsicherer Redfish-Verweis abgewiesen",
        "tls_error" => "TLS-Verbindung fehlgeschlagen",
        _ => "Netzwerk- oder TLS-Fehler",
    }
}

fn transport_reason(error: &anyhow::Error) -> &'static str {
    match error
        .downcast_ref::<crate::dsm::BoundaryError>()
        .map(|e| e.0)
    {
        Some("connection_certificate_mismatch" | "connection_certificate_expired") => {
            "certificate_error"
        }
        Some("connection_tls_incompatible") => "tls_error",
        Some("connection_response_too_large") => "response_limit",
        _ if error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
            || error
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|e| e.is_timeout()) =>
        {
            "timeout"
        }
        _ => "transport_error",
    }
}

struct PollProgress {
    snapshot: Snapshot,
    observations: BTreeMap<String, Observation>,
    identities: crate::identity::PsuIdentities,
    applicability: crate::assessment::Applicability,
    current: String,
    root_received: bool,
}
impl Default for PollProgress {
    fn default() -> Self {
        Self {
            snapshot: Snapshot {
                logs_complete: true,
                ..Default::default()
            },
            observations: BTreeMap::new(),
            identities: Default::default(),
            applicability: Default::default(),
            current: "/redfish/v1/".into(),
            root_received: false,
        }
    }
}
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
    "PowerSupplyRedundancy",
    "PowerSupplies",
    "Sensors",
    "LogServices",
    "Entries",
    "SmartStorage",
    "ArrayControllers",
    "DiskDrives",
    "LogicalDrives",
    "StorageControllers",
    "PhysicalDrives",
    "DataDrives",
    "StorageEnclosures",
    "UnconfiguredDrives",
];

// Only inventory dependencies, never OEM configuration or action targets.
pub(crate) const HPE_STORAGE_LINK_KEYS: &[&str] = &[
    "SmartStorage",
    "ArrayControllers",
    "DiskDrives",
    "PhysicalDrives",
    "LogicalDrives",
    "DataDrives",
    "StorageEnclosures",
    "UnconfiguredDrives",
];

pub struct Redfish {
    client: Client,
    pinned: Option<crate::legacy_tls::PinnedClient>,
    origin: Url,
    deadline: Duration,
    session: std::sync::Mutex<Option<Session>>,
    hardware_log: HardwareLogRead,
}

struct Session {
    token: zeroize::Zeroizing<String>,
    location: Url,
}

fn sensitive_header(token: &str) -> Result<reqwest::header::HeaderValue> {
    let mut value = reqwest::header::HeaderValue::from_str(token)?;
    value.set_sensitive(true);
    Ok(value)
}

pub(crate) fn session_collection_path(path: &str) -> bool {
    matches!(
        path.strip_suffix('/').unwrap_or(path),
        "/redfish/v1/Sessions" | "/redfish/v1/SessionService/Sessions"
    )
}
pub(crate) fn session_resource_path(path: &str) -> bool {
    // iLO advertises both the collection and the created session with a final
    // slash. Accept one optional slash for validation, preserving the URL sent.
    let path = path.strip_suffix('/').unwrap_or(path);
    [
        "/redfish/v1/Sessions/",
        "/redfish/v1/SessionService/Sessions/",
    ]
    .iter()
    .any(|prefix| {
        path.strip_prefix(prefix).is_some_and(|id| {
            !id.is_empty()
                && id.len() <= 256
                && id != "."
                && id != ".."
                && id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.~".contains(&c))
        })
    })
}

impl Redfish {
    pub fn new(device: &Device) -> Result<Self> {
        device.validate()?;
        let origin = Url::parse(&device.endpoint)?;
        let redirect_origin = origin.clone();
        let redirects = Policy::custom(move |attempt| {
            if attempt.previous().len() >= 4
                || attempt
                    .previous()
                    .iter()
                    .any(|u| session_collection_path(u.path()) || session_resource_path(u.path()))
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
            pinned: device
                .pinned_certificate_pem
                .as_ref()
                .map(|pem| crate::legacy_tls::PinnedClient::new(pem))
                .transpose()?,
            origin,
            deadline: Duration::from_secs(device.poll_timeout_seconds()),
            session: std::sync::Mutex::new(None),
            hardware_log: device.hardware_log.clone(),
        })
    }

    pub async fn poll(&self, username: &str, password: &str) -> Result<Snapshot> {
        self.poll_with_deadline(username, password, self.deadline)
            .await
    }

    async fn poll_with_deadline(
        &self,
        username: &str,
        password: &str,
        deadline: Duration,
    ) -> Result<Snapshot> {
        let mut progress = PollProgress::default();
        let outcome =
            tokio::time::timeout(deadline, self.walk(username, password, &mut progress)).await;
        self.close_session().await;
        let failure = match outcome {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some(anyhow::anyhow!(PollFailure::new(
                &progress.current,
                "deadline"
            ))),
        };
        if let Some(error) = failure {
            let failure = error
                .downcast_ref::<PollFailure>()
                .context("unclassified collection failure")?;
            if !progress.root_received
                || matches!(failure.reason, "authentication" | "certificate_error")
            {
                return Err(error);
            }
            progress.snapshot.logs_complete = false;
            progress
                .snapshot
                .capabilities
                .retain(|c| c.uri != failure.uri);
            progress.snapshot.capabilities.push(Capability {
                uri: failure.uri.clone(),
                outcome: failure.reason.into(),
                http_status: None,
                attempts: 1,
            });
        }
        let mut result = progress.snapshot;
        if let HardwareLogRead::Latest { limit } = self.hardware_log {
            // Merge the newest candidates from each advertised log service.
            result.logs.sort_by(|a, b| {
                b.created
                    .as_deref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .cmp(
                        &a.created
                            .as_deref()
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()),
                    )
                    .then_with(|| a.fingerprint.cmp(&b.fingerprint))
            });
            result.logs.dedup_by(|a, b| a.fingerprint == b.fingerprint);
            result.logs.truncate(limit as usize);
        }
        let mut observations = progress.observations;
        result.resource_aliases = progress.identities.merge(&mut observations);
        result.assessment_exclusions = progress.applicability.exclusions(&observations);
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
        let incomplete = result.capabilities.iter().any(|c| c.outcome != "available");
        result.observations = observations.into_values().collect();
        result.observations.push(Observation {
            key: "collector".into(),
            label: if incomplete {
                "Management-Abfrage unvollständig"
            } else {
                "Management-Abfrage erfolgreich"
            }
            .into(),
            health: if incomplete {
                Health::Warning
            } else {
                Health::Ok
            },
            reading: None,
            unit: None,
        });
        Ok(result)
    }

    /// Read the root and advertised hardware collections. The root alone may
    /// be public, so it cannot establish access to the protected data areas.
    pub async fn probe(&self, username: &str, password: &str) -> Result<Value> {
        let outcome = tokio::time::timeout(
            Duration::from_secs(16),
            self.probe_resources(username, password),
        )
        .await
        .map_err(|_| anyhow::anyhow!(crate::dsm::BoundaryError("connection_timeout")))
        .and_then(|result| result);
        self.close_session().await;
        outcome
    }

    async fn probe_resources(&self, username: &str, password: &str) -> Result<Value> {
        let root = self
            .probe_resource(self.origin.join("redfish/v1/")?, username, password)
            .await?;
        anyhow::ensure!(
            root.is_object()
                && (root.get("RedfishVersion").is_some()
                    || ["Systems", "Chassis", "Managers"]
                        .iter()
                        .any(|k| root.get(k).is_some())),
            crate::dsm::BoundaryError("connection_not_redfish")
        );
        self.open_session(&root, username, password).await?;
        let mut checked = 0;
        for key in ["Systems", "Chassis", "Managers"] {
            if let Some(link) = root
                .get(key)
                .and_then(|v| v.get("@odata.id"))
                .and_then(Value::as_str)
            {
                let url = safe_link(&self.origin, link).map_err(|_| {
                    anyhow::anyhow!(crate::dsm::BoundaryError("connection_response_invalid"))
                })?;
                let collection = self.probe_resource(url, username, password).await?;
                anyhow::ensure!(
                    collection.get("Members").is_some_and(Value::is_array),
                    crate::dsm::BoundaryError("connection_response_invalid")
                );
                checked += 1;
            }
        }
        Ok(
            serde_json::json!({"reachable":true,"checked_collections":checked,"certificate_fingerprint":self.pinned.as_ref().map(|p|p.fingerprint()),"redfish_version":root.get("RedfishVersion").and_then(Value::as_str).map(|s|s.chars().take(80).collect::<String>()),"systems":root.get("Systems").is_some(),"chassis":root.get("Chassis").is_some(),"managers":root.get("Managers").is_some()}),
        )
    }

    async fn probe_resource(&self, url: Url, username: &str, password: &str) -> Result<Value> {
        let mut response = self.get(url, username, password).await.map_err(|error| {
            if error.downcast_ref::<crate::dsm::BoundaryError>().is_some() {
                error
            } else {
                anyhow::anyhow!(crate::dsm::BoundaryError("connection_tls_or_network"))
            }
        })?;
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
        serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!(crate::dsm::BoundaryError("connection_not_redfish")))
    }

    async fn get(&self, url: Url, username: &str, password: &str) -> Result<reqwest::Response> {
        let token = self
            .session
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.token.clone());
        let auth = token.as_ref().map_or(
            crate::legacy_tls::Auth::Basic(username, password),
            |token| crate::legacy_tls::Auth::Token(token),
        );
        if let Some(client) = &self.pinned {
            client.get_authenticated(&self.origin, url, auth).await
        } else {
            let request = self.client.get(url).header("OData-Version", "4.0");
            Ok(match token {
                Some(token) => request.header("X-Auth-Token", sensitive_header(&token)?),
                None => request.basic_auth(username, Some(password)),
            }
            .send()
            .await?)
        }
    }

    async fn session_request(
        &self,
        url: Url,
        method: reqwest::Method,
        auth: crate::legacy_tls::Auth<'_>,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        safe_link(&self.origin, url.as_str())?;
        anyhow::ensure!(
            url.query().is_none()
                && ((method == reqwest::Method::POST && session_collection_path(url.path()))
                    || (method == reqwest::Method::DELETE
                        && session_resource_path(url.path())
                        && body.is_empty())),
            "only authentication session operations are permitted"
        );
        if let Some(client) = &self.pinned {
            return client
                .session_request(&self.origin, url, method, auth, body)
                .await;
        }
        let mut request = self
            .client
            .request(method, url)
            .header("OData-Version", "4.0")
            .header("Content-Type", "application/json")
            .body(body);
        if let crate::legacy_tls::Auth::Token(token) = auth {
            request = request.header("X-Auth-Token", sensitive_header(token)?);
        }
        Ok(request.send().await?)
    }

    async fn open_session(&self, root: &Value, username: &str, password: &str) -> Result<()> {
        let Some(link) = root
            .pointer("/Links/Sessions/@odata.id")
            .and_then(Value::as_str)
        else {
            return Ok(());
        };
        let target = safe_link(&self.origin, link).map_err(|_| {
            anyhow::anyhow!(crate::dsm::BoundaryError("connection_response_invalid"))
        })?;
        anyhow::ensure!(
            session_collection_path(target.path()) && target.query().is_none(),
            crate::dsm::BoundaryError("connection_response_invalid")
        );
        #[derive(serde::Serialize)]
        struct Credentials<'a> {
            #[serde(rename = "UserName")]
            username: &'a str,
            #[serde(rename = "Password")]
            password: &'a str,
        }
        let body = serde_json::to_vec(&Credentials { username, password })?;
        let mut response = self
            .session_request(
                target.clone(),
                reqwest::Method::POST,
                crate::legacy_tls::Auth::None,
                body,
            )
            .await?;
        if matches!(response.status().as_u16(), 403 | 404 | 405 | 501) {
            return Ok(());
        }
        if response.status() == StatusCode::UNAUTHORIZED {
            anyhow::bail!(crate::dsm::BoundaryError("connection_credentials_rejected"));
        }
        anyhow::ensure!(
            response.status() == StatusCode::CREATED || response.status() == StatusCode::OK,
            crate::dsm::BoundaryError("connection_http_error")
        );
        let token = response
            .headers()
            .get("X-Auth-Token")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty() && s.len() <= 8192)
            .ok_or(crate::dsm::BoundaryError("connection_response_invalid"))?;
        let location = response
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .ok_or(crate::dsm::BoundaryError("connection_response_invalid"))?;
        let location = safe_link(&self.origin, location).map_err(|_| {
            anyhow::anyhow!(crate::dsm::BoundaryError("connection_response_invalid"))
        })?;
        anyhow::ensure!(
            session_resource_path(location.path())
                && location
                    .path()
                    .starts_with(&(target.path().trim_end_matches('/').to_owned() + "/"))
                && location.query().is_none(),
            crate::dsm::BoundaryError("connection_response_invalid")
        );
        let session = Session {
            token: zeroize::Zeroizing::new(token.to_owned()),
            location,
        };
        *self.session.lock().unwrap() = Some(session);
        let mut bytes = 0;
        while let Some(chunk) = response.chunk().await? {
            bytes += chunk.len();
            anyhow::ensure!(
                bytes <= 512 * 1024,
                crate::dsm::BoundaryError("connection_response_too_large")
            );
        }
        Ok(())
    }

    async fn close_session(&self) {
        let session = self.session.lock().unwrap().take();
        if let Some(session) = session {
            let _ = tokio::time::timeout(
                Duration::from_secs(3),
                self.session_request(
                    session.location,
                    reqwest::Method::DELETE,
                    crate::legacy_tls::Auth::Token(&session.token),
                    Vec::new(),
                ),
            )
            .await;
        }
    }

    async fn get_with_retry(
        &self,
        url: Url,
        username: &str,
        password: &str,
    ) -> (Result<reqwest::Response>, u8) {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let response = self.get(url.clone(), username, password).await;
            let retry = match &response {
                Ok(r) => matches!(r.status().as_u16(), 500 | 502 | 503 | 504),
                Err(e) => {
                    e.downcast_ref::<reqwest::Error>()
                        .is_some_and(|e| e.is_timeout())
                        || e.downcast_ref::<tokio::time::error::Elapsed>().is_some()
                }
            };
            if retry && attempts < 2 {
                drop(response);
                tokio::time::sleep(Duration::from_millis(300)).await;
            } else {
                return (response, attempts);
            }
        }
    }

    async fn walk(
        &self,
        username: &str,
        password: &str,
        progress: &mut PollProgress,
    ) -> Result<()> {
        let mut queue = VecDeque::from(["/redfish/v1/".to_owned()]);
        let mut log_queue = VecDeque::new();
        let mut visited = HashSet::new();
        let result = &mut progress.snapshot;
        let observations = &mut progress.observations;
        let mut total_bytes = 0usize;
        let mut ordered = HashSet::new();
        let mut selected = std::collections::BTreeMap::<String, usize>::new();
        while let Some(path) = queue.pop_front().or_else(|| log_queue.pop_front()) {
            if self.hardware_log == HardwareLogRead::Disabled && log_resource(&path) {
                result.logs_complete = false;
                continue;
            }
            let mut url = safe_link(&self.origin, &path)
                .map_err(|_| anyhow::anyhow!(PollFailure::new("Redfish-Verweis", "unsafe_link")))?;
            if let HardwareLogRead::Latest { limit } = self.hardware_log {
                if url.path().trim_end_matches('/').ends_with("/Entries")
                    && !ordered.contains(url.path())
                {
                    url.query_pairs_mut()
                        .append_pair("$orderby", "Created desc")
                        .append_pair("$top", &limit.to_string());
                    ordered.insert(url.path().to_owned());
                }
            }
            progress.current = url.path().to_owned();
            if !visited.insert(url.to_string()) {
                continue;
            }
            anyhow::ensure!(
                visited.len() <= MAX_RESOURCES,
                PollFailure::new(&progress.current, "resource_limit")
            );
            let (response, attempts) = self.get_with_retry(url, username, password).await;
            let mut response = match response {
                Ok(r) => r,
                Err(error) => {
                    let reason = transport_reason(&error);
                    if visited.len() == 1 || reason == "certificate_error" {
                        anyhow::bail!(PollFailure::new(&progress.current, reason));
                    }
                    result.logs_complete = false;
                    result.capabilities.push(Capability {
                        uri: path.clone(),
                        outcome: reason.into(),
                        http_status: None,
                        attempts,
                    });
                    continue;
                }
            };
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED {
                anyhow::bail!(PollFailure::new(&progress.current, "authentication"));
            }
            if !status.is_success() {
                if visited.len() == 1 {
                    anyhow::bail!(PollFailure::new(&progress.current, "http_error"));
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
            let value: Result<Value> = async {
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| {
                    anyhow::anyhow!(PollFailure::new(&progress.current, "transport_error"))
                })? {
                    anyhow::ensure!(
                        bytes.len() + chunk.len() <= MAX_BODY,
                        PollFailure::new(&progress.current, "response_limit")
                    );
                    bytes.extend_from_slice(&chunk);
                    total_bytes += chunk.len();
                    anyhow::ensure!(
                        total_bytes <= 16 * 1024 * 1024,
                        PollFailure::new(&progress.current, "byte_limit")
                    );
                }
                let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
                    anyhow::anyhow!(PollFailure::new(&progress.current, "invalid_response"))
                })?;
                anyhow::ensure!(
                    value.is_object(),
                    PollFailure::new(&progress.current, "invalid_response")
                );
                Ok(value)
            }
            .await;
            let value = match value {
                Ok(value) => value,
                Err(error) => {
                    let failure = error
                        .downcast_ref::<PollFailure>()
                        .context("unclassified response failure")?;
                    if visited.len() == 1 || failure.reason == "byte_limit" {
                        return Err(error);
                    }
                    result.logs_complete = false;
                    result.capabilities.push(Capability {
                        uri: progress.current.clone(),
                        outcome: failure.reason.into(),
                        http_status: None,
                        attempts,
                    });
                    continue;
                }
            };
            if let HardwareLogRead::Latest { limit } = self.hardware_log {
                if log_entry_collection(&path, &value) {
                    let mut url = safe_link(&self.origin, &path)?;
                    let collection = url.path().to_owned();
                    if !ordered.contains(&collection) {
                        url.query_pairs_mut()
                            .append_pair("$orderby", "Created desc")
                            .append_pair("$top", &limit.to_string());
                        ordered.insert(collection);
                        log_queue.push_front(url.to_string());
                        continue;
                    }
                    let members = value["Members"].as_array().unwrap();
                    let times = members
                        .iter()
                        .map(|m| {
                            m.get("Created")
                                .and_then(Value::as_str)
                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        })
                        .collect::<Vec<_>>();
                    if times
                        .windows(2)
                        .any(|w| matches!((&w[0],&w[1]),(Some(a),Some(b)) if a<b))
                    {
                        result.logs_complete = false;
                        result.capabilities.push(Capability {
                            uri: path.clone(),
                            outcome: "log_selection_unsupported".into(),
                            http_status: None,
                            attempts: 1,
                        });
                        continue;
                    }
                    let count = selected.entry(collection).or_default();
                    // Reject ignored $top instead of claiming that an arbitrary first page is newest.
                    if *count + members.len() > limit as usize {
                        result.logs_complete = false;
                        result.capabilities.push(Capability {
                            uri: path.clone(),
                            outcome: "log_selection_unsupported".into(),
                            http_status: None,
                            attempts: 1,
                        });
                        continue;
                    }
                    *count += members.len();
                }
            }
            let mut resource_observations = BTreeMap::new();
            let mut resource_logs = Vec::new();
            normalize(
                &path,
                &value,
                &mut resource_observations,
                &mut resource_logs,
            );
            let mut selection_valid = true;
            if matches!(self.hardware_log, HardwareLogRead::Latest { .. }) {
                resource_logs.retain(|log| {
                    let valid = log
                        .created
                        .as_deref()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .is_some();
                    selection_valid &= valid;
                    valid
                });
                if !selection_valid {
                    result.logs_complete = false;
                }
            }
            anyhow::ensure!(
                observations.len() + resource_observations.len() <= 4096
                    && result.logs.len() + resource_logs.len() <= 4096,
                PollFailure::new(&progress.current, "item_limit")
            );
            observations.extend(resource_observations);
            result.logs.extend(resource_logs);
            result.capabilities.push(Capability {
                uri: path.clone(),
                outcome: if selection_valid {
                    "available"
                } else {
                    "log_selection_unsupported"
                }
                .into(),
                http_status: if selection_valid {
                    Some(status.as_u16())
                } else {
                    None
                },
                attempts,
            });
            progress.root_received = true;
            if visited.len() == 1 {
                self.open_session(&value, username, password)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!(PollFailure::new(
                            &progress.current,
                            if crate::dsm::error_code(&error) == "connection_credentials_rejected" {
                                "authentication"
                            } else {
                                transport_reason(&error)
                            }
                        ))
                    })?;
            }
            progress.identities.observe(&path, &value);
            progress.applicability.observe(&path, &value);
            crate::correlation::observe(&path, &value, &mut result.resources);
            enqueue_resources(&path, &value, &mut queue, &mut log_queue);
            if let HardwareLogRead::Latest { limit } = self.hardware_log {
                let collection = safe_link(&self.origin, &path)?.path().to_owned();
                if selected
                    .get(&collection)
                    .is_some_and(|n| *n >= limit as usize)
                {
                    log_queue.retain(|link| {
                        safe_link(&self.origin, link).is_ok_and(|url| url.path() != collection)
                    });
                }
            }
        }
        Ok(())
    }
}

fn log_entry_collection(path: &str, value: &Value) -> bool {
    value.get("Members").is_some_and(Value::is_array)
        && (value["@odata.type"]
            .as_str()
            .is_some_and(|s| s.contains("LogEntryCollection"))
            || path
                .split('?')
                .next()
                .unwrap_or(path)
                .trim_end_matches('/')
                .ends_with("/Entries")
            || (log_resource(path)
                && value["Members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m.get("Message").is_some() || m.get("EntryType").is_some())))
}

fn log_resource(path: &str) -> bool {
    path.split(['/', '?', '#']).any(|segment| {
        ["LogServices", "LogService", "LogEntries", "Logs"]
            .iter()
            .any(|name| segment.eq_ignore_ascii_case(name))
    })
}

fn enqueue_resources(
    path: &str,
    value: &Value,
    hardware: &mut VecDeque<String>,
    logs: &mut VecDeque<String>,
) {
    let mut discovered = VecDeque::new();
    discover(value, &mut discovered);
    for link in discovered {
        if log_resource(path) || log_resource(&link) {
            logs.push_back(link);
        } else {
            hardware.push_back(link);
        }
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
    // Keep OEM polling and fault dependencies on the same explicit inventory links.
    for links in [
        value.get("Links"),
        value.pointer("/Oem/Hpe"),
        value.pointer("/Oem/Hpe/Links"),
    ]
    .into_iter()
    .flatten()
    {
        for key in HPE_STORAGE_LINK_KEYS {
            if let Some(v) = links.get(*key) {
                add_links(v, queue);
                discover(v, queue);
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
        failure_description(&capability.outcome).into()
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
    if crate::assessment::hpe_absent_power_supply_warning(value) {
        return Health::Unknown;
    }
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
                    let name = if value
                        .get("@odata.type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| {
                            kind.rsplit('.').next() == Some("HpeSmartStorageDiskDrive")
                        }) {
                        let location = value
                            .get("Location")
                            .and_then(Value::as_str)
                            .filter(|location| !location.trim().is_empty())
                            .map(|location| {
                                location
                                    .chars()
                                    .filter(|c| !c.is_control())
                                    .take(80)
                                    .collect::<String>()
                            });
                        location
                            .map_or_else(|| name.clone(), |location| format!("{name} ({location})"))
                    } else if aggregate {
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
    for summary in crate::hpe_power::summaries(uri, value) {
        normalize(uri, &summary, observations, logs);
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
    #[test]
    fn authentication_operations_are_confined_to_session_endpoints() {
        assert!(session_collection_path("/redfish/v1/Sessions"));
        assert!(session_collection_path("/redfish/v1/Sessions/"));
        assert!(session_collection_path(
            "/redfish/v1/SessionService/Sessions/"
        ));
        assert!(session_resource_path(
            "/redfish/v1/SessionService/Sessions/42-ab"
        ));
        assert!(session_resource_path(
            "/redfish/v1/SessionService/Sessions/42-ab/"
        ));
        assert!(session_resource_path("/redfish/v1/Sessions/owned/"));
        for path in [
            "/redfish/v1/Sessions//",
            "/redfish/v1/SessionService/Sessions//",
            "/redfish/v1/Chassis/",
        ] {
            assert!(!session_collection_path(path), "{path}");
        }
        for path in [
            "/redfish/v1/Systems/1",
            "/redfish/v1/Sessions/../Chassis",
            "/redfish/v1/Sessions/%2e%2e",
            "/redfish/v1/Sessions/a%2f..%2fChassis",
            "/redfish/v1/Sessions/",
            "/redfish/v1/Sessions//",
            "/redfish/v1/Sessions/owned//",
            "/redfish/v1/Sessions/owned/child/",
            "/redfish/v1/SessionService/Sessions/../Chassis/",
            "/redfish/v1/SessionService/Sessions/%2f/",
        ] {
            assert!(!session_resource_path(path), "{path}");
        }
    }
    #[test]
    fn older_dell_logs_are_deferred_behind_hardware_and_raid_resources() {
        let mut hardware = VecDeque::new();
        let mut logs = VecDeque::new();
        enqueue_resources(
            "/redfish/v1/Managers/iDRAC.Embedded.1",
            &json!({"LogServices":{"@odata.id":"/redfish/v1/Managers/iDRAC.Embedded.1/Logs"}}),
            &mut hardware,
            &mut logs,
        );
        enqueue_resources(
            "/redfish/v1/Systems/System.Embedded.1",
            &json!({"SimpleStorage":{"@odata.id":"/redfish/v1/Systems/System.Embedded.1/SimpleStorage"}}),
            &mut hardware,
            &mut logs,
        );
        assert_eq!(
            hardware.into_iter().collect::<Vec<_>>(),
            ["/redfish/v1/Systems/System.Embedded.1/SimpleStorage"]
        );
        assert_eq!(
            logs.into_iter().collect::<Vec<_>>(),
            ["/redfish/v1/Managers/iDRAC.Embedded.1/Logs"]
        );
        assert!(log_resource(
            "/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Lclog"
        ));
    }
    #[test]
    fn poll_diagnostics_use_only_classified_reasons_and_redacted_resource_paths() {
        let error = anyhow::anyhow!(super::PollFailure::new(
            "/redfish/v1/Systems/test?token=synthetic-sensitive-query",
            "authentication"
        ));
        let label = super::poll_failure_label(&error);
        assert!(label.contains("/redfish/v1/Systems/test: Anmeldung abgewiesen (HTTP 401)"));
        assert!(!label.contains("synthetic-sensitive-query"));
        assert!(crate::i18n::label(&label, crate::i18n::Language::En)
            .contains("Sign-in rejected (HTTP 401)"));
        let unexpected = anyhow::anyhow!("synthetic-sensitive-internal-detail");
        assert!(!super::poll_failure_label(&unexpected).contains("synthetic-sensitive"));
    }
    use super::*;
    use serde_json::json;
    #[test]
    fn live_hpe_links_reach_physical_drives_even_through_logical_drive_membership() {
        use crate::correlation::tests::{HPE_FAILED, HPE_OK};
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/hpe-smartstorage-hierarchy.json"
        ))
        .unwrap();
        for through_logical_drive in [false, true] {
            let mut bodies = BTreeMap::new();
            for item in fixture["resources"].as_array().unwrap() {
                let mut body = item["body"].clone();
                if through_logical_drive {
                    if let Some(links) = body.get_mut("Links").and_then(Value::as_object_mut) {
                        links.remove("PhysicalDrives");
                    }
                }
                bodies.insert(item["uri"].as_str().unwrap().to_owned(), body);
            }
            let mut queue = VecDeque::from([
                "/redfish/v1/Systems/".to_owned(),
                "/redfish/v1/Chassis/".to_owned(),
            ]);
            let mut visited = HashSet::new();
            let mut observations = BTreeMap::new();
            let mut logs = Vec::new();
            while let Some(uri) = queue.pop_front() {
                if !visited.insert(uri.clone()) {
                    continue;
                }
                // Other system inventories are outside this selected storage fixture.
                if let Some(body) = bodies.get(&uri) {
                    discover(body, &mut queue);
                    normalize(&uri, body, &mut observations, &mut logs);
                }
            }
            assert_eq!(observations[HPE_FAILED].health, Health::Critical);
            assert_eq!(observations[HPE_OK].health, Health::Ok);
            for suffix in [
                "LogicalDrives/1/DataDrives/",
                "StorageEnclosures/0/",
                "StorageEnclosures/1/",
                "UnconfiguredDrives/",
            ] {
                assert!(visited.iter().any(|uri| uri.ends_with(suffix)), "{suffix}");
            }
            assert!(logs.is_empty());
        }
        let mut queue = VecDeque::new();
        discover(
            &json!({"Oem":{"Hpe":{"Links":{"Settings":{"@odata.id":"/redfish/v1/Systems/1/Settings/"},"Reset":{"target":"/redfish/v1/Systems/1/Actions/Reset"}}}}}),
            &mut queue,
        );
        assert!(queue.is_empty());
    }
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
        queue.clear();
        discover(
            &json!({"Oem":{"Hpe":{"SmartStorage":{"ArrayControllers":{"@odata.id":"/redfish/v1/Systems/42/SmartStorage/ArrayControllers/"}}}}}),
            &mut queue,
        );
        assert_eq!(
            queue,
            VecDeque::from(["/redfish/v1/Systems/42/SmartStorage/ArrayControllers/".to_owned()])
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

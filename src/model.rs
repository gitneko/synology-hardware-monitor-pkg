use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Ok,
    Warning,
    Critical,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub key: String,
    pub label: String,
    pub health: Health,
    pub reading: Option<f64>,
    pub unit: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub uri: String,
    pub outcome: String,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default = "one_attempt")]
    pub attempts: u8,
}
fn one_attempt() -> u8 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareLog {
    pub fingerprint: String,
    pub message: String,
    pub severity: Health,
    pub created: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub assessment_exclusions: std::collections::BTreeMap<String, AssessmentExclusion>,
    #[serde(default)]
    pub resource_aliases: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub resources: std::collections::BTreeMap<String, crate::correlation::Resource>,
    #[serde(default)]
    pub notification_groups: std::collections::BTreeMap<String, Vec<String>>,
    pub observations: Vec<Observation>,
    pub capabilities: Vec<Capability>,
    pub logs: Vec<HardwareLog>,
    pub logs_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentExclusion {
    Disabled,
    EmptyController,
    Informational,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfile {
    #[default]
    Standard,
    Idrac7,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub username: String,
    pub interval_seconds: u64,
    pub repeat_seconds: Option<i64>,
    pub alerts_enabled: bool,
    pub ca_file: Option<String>,
    #[serde(default)]
    pub ca_pem: Option<String>,
    #[serde(default)]
    pub tls_profile: TlsProfile,
    #[serde(default)]
    pub pinned_certificate_pem: Option<String>,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
}

fn enabled_default() -> bool {
    true
}

impl Device {
    pub fn poll_timeout_seconds(&self) -> u64 {
        match self.tls_profile {
            TlsProfile::Idrac7 => 300,
            TlsProfile::Standard => 90,
        }
    }

    pub fn stale_after_seconds(&self) -> u64 {
        self.interval_seconds * 2
            + if self.tls_profile == TlsProfile::Idrac7 {
                self.poll_timeout_seconds()
            } else {
                0
            }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.id.is_empty()
                && self.id.len() <= 80
                && self
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
            "invalid device id"
        );
        anyhow::ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 160
                && !self.name.chars().any(char::is_control),
            "invalid device name"
        );
        let u = url::Url::parse(&self.endpoint)?;
        anyhow::ensure!(
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
                && u.path() == "/",
            "endpoint must be an HTTPS origin without credentials, path or query"
        );
        anyhow::ensure!(
            (30..=86400).contains(&self.interval_seconds),
            "poll interval must be 30..86400 seconds"
        );
        anyhow::ensure!(
            self.repeat_seconds.is_none_or(|n| n >= 300),
            "repeat interval must be at least 300 seconds"
        );
        anyhow::ensure!(
            !self.username.trim().is_empty()
                && self.username.len() <= 128
                && !self.username.chars().any(char::is_control),
            "invalid username"
        );
        anyhow::ensure!(
            self.ca_file.is_none() || self.ca_pem.is_none(),
            "choose one trust source"
        );
        if let Some(pem) = &self.ca_pem {
            validate_certificates(pem)?;
        }
        match self.tls_profile {
            TlsProfile::Standard => anyhow::ensure!(
                self.pinned_certificate_pem.is_none(),
                "standard TLS requires CA/hostname validation"
            ),
            TlsProfile::Idrac7 => {
                anyhow::ensure!(
                    self.ca_file.is_none() && self.ca_pem.is_none(),
                    "pinning cannot grant CA trust"
                );
                let pem = self.pinned_certificate_pem.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("server certificate required for iDRAC7 mode")
                })?;
                crate::legacy_tls::certificate(pem)?;
            }
        }
        Ok(())
    }
}

pub fn validate_certificates(pem: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        pem.len() <= 65536 && !pem.is_empty(),
        "certificate size invalid"
    );
    let mut remaining = pem.trim();
    let mut count = 0;
    while !remaining.is_empty() {
        anyhow::ensure!(
            remaining.starts_with("-----BEGIN CERTIFICATE-----"),
            "only PEM certificates allowed"
        );
        let end = remaining
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| anyhow::anyhow!("incomplete certificate"))?
            + "-----END CERTIFICATE-----".len();
        let certificate = &remaining[..end];
        anyhow::ensure!(
            reqwest::Certificate::from_pem_bundle(certificate.as_bytes())?.len() == 1,
            "certificate invalid"
        );
        remaining = remaining[end..].trim();
        count += 1;
        anyhow::ensure!(count <= 8, "too many certificates");
    }
    anyhow::ensure!(count > 0, "certificate missing");
    Ok(())
}

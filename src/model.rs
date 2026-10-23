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
    /// Unsupported optional groups do not widen the profile's assessment scope.
    /// Transport/decoding failures still block assessment, even for such groups.
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default = "one_attempt")]
    pub attempts: u8,
}
impl Capability {
    pub fn blocks_assessment(&self) -> bool {
        self.outcome != "available" && !(self.optional && self.outcome == "unsupported")
    }
}
fn one_attempt() -> u8 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareLog {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<LogIdentity>,
    pub fingerprint: String,
    pub message: String,
    pub severity: Health,
    pub created: Option<String>,
}

/// An occurrence must identify one record in a known component/generation.
/// A MessageId alone is an event type and cannot authorize deduplication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Occurrence {
    pub vendor: String,
    pub record_id: String,
    pub component: String,
    pub generation: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogIdentity {
    pub record_id: Option<String>,
    pub message_id: Option<String>,
    pub component: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<Occurrence>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_identities: Vec<crate::identity::Component>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snmp: Option<crate::snmp::polling::Metadata>,
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
    Absent,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryProtocol {
    #[default]
    Redfish,
    Snmp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub primary_protocol: PrimaryProtocol,
    #[serde(default)]
    pub snmp_poll: Option<crate::snmp::config::PollConfig>,
    #[serde(default)]
    pub snmp_traps: Option<crate::snmp::config::TrapConfig>,
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
    pub fn primary_target_changed(&self, other: &Self) -> bool {
        if self.primary_protocol != other.primary_protocol {
            return true;
        }
        match self.primary_protocol {
            PrimaryProtocol::Redfish => self.endpoint != other.endpoint,
            PrimaryProtocol::Snmp => match (&self.snmp_poll, &other.snmp_poll) {
                (Some(a), Some(b)) => !a.same_target(b),
                _ => true,
            },
        }
    }

    pub fn poll_timeout_seconds(&self) -> u64 {
        if self.primary_protocol == PrimaryProtocol::Snmp {
            return 60;
        }
        match self.tls_profile {
            TlsProfile::Idrac7 => 300,
            TlsProfile::Standard => 90,
        }
    }

    pub fn stale_after_seconds(&self) -> u64 {
        self.interval_seconds * 2
            + if self.tls_profile == TlsProfile::Idrac7
                || self.primary_protocol == PrimaryProtocol::Snmp
            {
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
        anyhow::ensure!(
            (30..=86400).contains(&self.interval_seconds),
            "poll interval must be 30..86400 seconds"
        );
        anyhow::ensure!(
            self.repeat_seconds.is_none_or(|n| n >= 300),
            "repeat interval must be at least 300 seconds"
        );
        if let Some(config) = &self.snmp_poll {
            config.validate()?;
        }
        if let Some(config) = &self.snmp_traps {
            config.validate()?;
        }
        if self.primary_protocol == PrimaryProtocol::Snmp {
            anyhow::ensure!(
                self.snmp_poll.is_some(),
                "SNMP primary requires polling configuration"
            );
            anyhow::ensure!(
                self.endpoint.is_empty()
                    && self.username.is_empty()
                    && self.ca_file.is_none()
                    && self.ca_pem.is_none()
                    && self.pinned_certificate_pem.is_none()
                    && self.tls_profile == TlsProfile::Standard,
                "SNMP primary must not contain Redfish settings"
            );
            return Ok(());
        }
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

#[cfg(test)]
mod capability_tests {
    use super::*;
    #[test]
    fn optional_absence_is_neutral_but_failures_and_legacy_groups_still_block() {
        for outcome in [
            "available",
            "unsupported",
            "snmp_timeout",
            "snmp_invalid_response",
            "snmp_item_limit",
        ] {
            for optional in [false, true] {
                let c = Capability {
                    uri: "snmp:test".into(),
                    outcome: outcome.into(),
                    optional,
                    http_status: None,
                    attempts: 1,
                };
                assert_eq!(
                    c.blocks_assessment(),
                    outcome != "available" && !(optional && outcome == "unsupported")
                );
            }
        }
        let legacy: Capability =
            serde_json::from_str(r#"{"uri":"old","outcome":"unsupported"}"#).unwrap();
        assert!(!legacy.optional);
        assert!(legacy.blocks_assessment());
    }
}

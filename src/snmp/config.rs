use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProtocol {
    Sha1,
    #[default]
    Sha256,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyProtocol {
    #[default]
    Aes128,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "version", rename_all = "snake_case", deny_unknown_fields)]
pub enum Security {
    V1 {},
    V2c {},
    V3 {
        username: String,
        #[serde(default)]
        auth: AuthProtocol,
        #[serde(default)]
        privacy: PrivacyProtocol,
    },
}
impl Security {
    pub fn validate(&self) -> Result<()> {
        if let Self::V3 { username, .. } = self {
            ensure!(
                !username.is_empty() && username.len() <= 32,
                "invalid SNMP user length"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Generic,
    NetworkGeneric,
    DellIdrac,
    HpeIlo5,
    SynologyDsm,
    UpsGeneric,
    ApcUps,
    EatonUps,
}
fn agent_port() -> u16 {
    161
}
fn timeout() -> u64 {
    2000
}
fn retries() -> u8 {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollConfig {
    pub host: String,
    #[serde(default = "agent_port")]
    pub port: u16,
    pub security: Security,
    #[serde(default)]
    pub context_name: String,
    #[serde(default)]
    pub context_engine_id: Option<String>,
    #[serde(default)]
    pub profile: Profile,
    #[serde(default = "timeout")]
    pub timeout_ms: u64,
    #[serde(default = "retries")]
    pub retries: u8,
}
impl PollConfig {
    pub fn validate(&self) -> Result<()> {
        validate_host(&self.host)?;
        ensure!(
            self.port > 0 && (100..=10000).contains(&self.timeout_ms) && self.retries <= 1,
            "invalid SNMP request limits"
        );
        self.security.validate()?;
        validate_context(
            &self.security,
            &self.context_name,
            self.context_engine_id.as_deref(),
        )
    }
    pub fn same_credentials_scope(&self, other: &Self) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.security == other.security
            && self.context_name == other.context_name
            && self.context_engine_id == other.context_engine_id
    }
    pub fn same_target(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port && self.profile == other.profile
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrapConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_sources: Vec<IpAddr>,
    pub security: Security,
    #[serde(default)]
    pub engine_ids: Vec<String>,
    #[serde(default)]
    pub context_name: String,
    #[serde(default)]
    pub context_engine_ids: Vec<String>,
    #[serde(default)]
    pub profile: Profile,
}
impl TrapConfig {
    pub fn validate(&self) -> Result<()> {
        self.security.validate()?;
        ensure!(
            self.allowed_sources.len() <= 16 && (!self.enabled || !self.allowed_sources.is_empty()),
            "invalid SNMP source allowlist"
        );
        for ip in &self.allowed_sources {
            validate_source(ip)?;
        }
        ensure!(
            self.allowed_sources
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == self.allowed_sources.len(),
            "duplicate SNMP source"
        );
        ensure!(
            self.engine_ids.len() <= 16 && self.context_engine_ids.len() <= 16,
            "SNMP engine limit"
        );
        for ids in [&self.engine_ids, &self.context_engine_ids] {
            for id in ids {
                validate_engine_id(id)?;
            }
            ensure!(
                ids.iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    == ids.len(),
                "duplicate SNMP engine"
            );
        }
        validate_context(&self.security, &self.context_name, None)?;
        if !matches!(self.security, Security::V3 { .. }) {
            ensure!(
                self.engine_ids.is_empty() && self.context_engine_ids.is_empty(),
                "community traps have no USM engine"
            );
        }
        Ok(())
    }
    pub fn same_credentials_scope(&self, other: &Self) -> bool {
        self.allowed_sources == other.allowed_sources
            && self.security == other.security
            && self.engine_ids == other.engine_ids
            && self.context_name == other.context_name
            && self.context_engine_ids == other.context_engine_ids
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverSettings {
    pub enabled: bool,
    pub listen_port: u16,
    pub listen_addresses: Vec<IpAddr>,
}
impl Default for ReceiverSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: 1162,
            listen_addresses: vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        }
    }
}
impl ReceiverSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.listen_port >= 1024
                && !self.listen_addresses.is_empty()
                && self.listen_addresses.len() <= 16,
            "invalid SNMP listener address/port"
        );
        let mut unique = std::collections::HashSet::new();
        for ip in &self.listen_addresses {
            ensure!(
                !ip.is_multicast() && *ip != IpAddr::V4(Ipv4Addr::BROADCAST) && unique.insert(ip),
                "invalid or duplicate SNMP bind"
            );
            if !ip.is_unspecified() {
                ensure!(
                    !self
                        .listen_addresses
                        .iter()
                        .any(|a| a.is_unspecified() && a.is_ipv4() == ip.is_ipv4()),
                    "overlapping SNMP binds"
                );
            }
        }
        Ok(())
    }
}

pub fn validate_engine_id(id: &str) -> Result<()> {
    ensure!(
        (10..=64).contains(&id.len())
            && id.len().is_multiple_of(2)
            && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid SNMP engine ID"
    );
    ensure!(
        !id.bytes().all(|b| b == b'0') && !id.bytes().all(|b| b.eq_ignore_ascii_case(&b'f')),
        "reserved SNMP engine ID"
    );
    Ok(())
}
fn validate_context(security: &Security, name: &str, engine: Option<&str>) -> Result<()> {
    ensure!(name.len() <= 32, "SNMP context exceeds 32 bytes");
    if let Some(id) = engine {
        validate_engine_id(id)?;
    }
    ensure!(
        matches!(security, Security::V3 { .. }) || (name.is_empty() && engine.is_none()),
        "community polling has no v3 context"
    );
    Ok(())
}
fn validate_source(ip: &IpAddr) -> Result<()> {
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast() && *ip != IpAddr::V4(Ipv4Addr::BROADCAST),
        "invalid SNMP source"
    );
    Ok(())
}
fn validate_host(host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_source(&ip);
    }
    ensure!(
        !host.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "invalid SNMP numeric address"
    );
    ensure!(
        !host.is_empty() && host.len() <= 253 && host.is_ascii(),
        "invalid SNMP host"
    );
    for part in host.strip_suffix('.').unwrap_or(host).split('.') {
        ensure!(
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid SNMP hostname"
        );
    }
    Ok(())
}

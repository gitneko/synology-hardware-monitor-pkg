use super::config::Security;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    SnmpPoll,
    SnmpTraps,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SnmpPoll => "snmp_poll",
            Self::SnmpTraps => "snmp_traps",
        }
    }
    pub fn aad(self, device: &str) -> String {
        format!("device:{device}:{}", self.as_str())
    }
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credentials {
    Community {
        community: String,
    },
    Usm {
        auth_password: String,
        priv_password: String,
    },
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials([REDACTED])")
    }
}
impl Credentials {
    pub fn validate(&self, security: &Security) -> Result<()> {
        match (self, security) {
            (Self::Community { community }, Security::V1 { .. } | Security::V2c { .. }) => ensure!(
                !community.is_empty() && community.len() <= 255,
                "invalid SNMP community length"
            ),
            (
                Self::Usm {
                    auth_password,
                    priv_password,
                },
                Security::V3 { .. },
            ) => {
                ensure!(
                    (8..=1024).contains(&auth_password.len())
                        && (8..=1024).contains(&priv_password.len()),
                    "invalid SNMP passphrase length"
                );
            }
            _ => anyhow::bail!("SNMP credential type does not match version"),
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretUpdate {
    Keep {},
    Clear {},
    Replace { credentials: Credentials },
}
impl Default for SecretUpdate {
    fn default() -> Self {
        Self::Keep {}
    }
}
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretUpdates {
    #[serde(default)]
    pub snmp_poll: SecretUpdate,
    #[serde(default)]
    pub snmp_traps: SecretUpdate,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCredentialsInput {
    pub redfish_password: Option<String>,
    #[serde(default)]
    pub snmp: SecretUpdates,
}
impl Drop for DeviceCredentialsInput {
    fn drop(&mut self) {
        if let Some(password) = &mut self.redfish_password {
            password.zeroize();
        }
    }
}
impl DeviceCredentialsInput {
    pub fn read() -> Result<Self> {
        use std::io::Read;
        let mut plain = zeroize::Zeroizing::new(Vec::new());
        std::io::stdin().take(16385).read_to_end(&mut plain)?;
        ensure!(plain.len() <= 16384, "credential input too large");
        serde_json::from_slice(&plain).map_err(|_| anyhow::anyhow!("invalid credential document"))
    }
}

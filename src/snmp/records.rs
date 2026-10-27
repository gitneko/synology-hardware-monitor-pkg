//! Bounded logical records; network packets and USM key/time caches never belong here.
use crate::model::Health;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Redfish,
    SnmpPoll,
    SnmpTrap,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentIdentity {
    pub source: EvidenceSource,
    pub locator: String,
    pub aliases: Vec<String>,
    pub generation: i64,
    pub revision: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<super::traps::Event>,
    pub fingerprint: String,
    pub trap_oid: String,
    pub source: std::net::IpAddr,
    pub verified: bool,
    pub component_key: Option<String>,
    #[serde(default)]
    pub restored: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_boots: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handling: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEvidence {
    pub source: EvidenceSource,
    pub revision: i64,
    pub generation: i64,
    pub health: Health,
    pub received: i64,
    pub active: bool,
    #[serde(default)]
    pub sequence: i64,
    #[serde(default)]
    pub provisional: bool,
    #[serde(default)]
    pub confirmation: String,
    #[serde(default)]
    pub conditions: std::collections::BTreeMap<String, Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<super::traps::Identity>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub health: Health,
    pub sequence: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<crate::model::Occurrence>,
}
fn text(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "invalid SNMP record text"
    );
    Ok(())
}
fn counter(value: i64) -> Result<()> {
    ensure!(
        (0..=i64::MAX / 4).contains(&value),
        "invalid SNMP record counter"
    );
    Ok(())
}
impl ComponentIdentity {
    fn validate(&self) -> Result<()> {
        text(&self.locator, 1024)?;
        ensure!(self.aliases.len() <= 64, "too many component aliases");
        for alias in &self.aliases {
            text(alias, 256)?;
        }
        counter(self.generation)?;
        counter(self.revision)
    }
}
impl Receipt {
    fn validate(&self) -> Result<()> {
        if let Some(event) = &self.event {
            text(&event.message, 1024)?;
            text(&event.condition, 256)?;
            ensure!(event.component_kind.len() <= 64, "trap component kind");
            if let Some(identity) = &event.identity {
                ensure!(
                    serde_json::to_vec(identity)?.len() <= 1024,
                    "trap identity size"
                );
            }
            if let Some(occurrence) = &event.occurrence {
                ensure!(
                    serde_json::to_vec(occurrence)?.len() <= 1024,
                    "trap occurrence size"
                );
            }
        }
        text(&self.fingerprint, 256)?;
        let arcs = self
            .trap_oid
            .split('.')
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            (2..=128).contains(&arcs.len()) && arcs[0] <= 2 && (arcs[0] == 2 || arcs[1] <= 39),
            "invalid trap OID"
        );
        ensure!(
            !self.source.is_unspecified() && !self.source.is_multicast(),
            "invalid receipt source"
        );
        if let Some(version) = &self.version {
            ensure!(
                matches!(version.as_str(), "v1" | "v2c" | "v3"),
                "invalid receipt version"
            );
        }
        if let Some(boots) = self.engine_boots {
            ensure!(boots <= i32::MAX as u32, "invalid receipt engine boots");
        }
        if let Some(engine) = &self.engine_id {
            super::config::validate_engine_id(engine)?;
        }
        if let Some(handling) = &self.handling {
            text(handling, 64)?;
        }
        if let Some(key) = &self.component_key {
            text(key, 1024)?;
        }
        Ok(())
    }
}
impl ObservationEvidence {
    fn validate(&self) -> Result<()> {
        counter(self.revision)?;
        counter(self.generation)?;
        counter(self.received)?;
        counter(self.sequence)?;
        ensure!(
            self.confirmation.len() <= 64 && self.conditions.len() <= 16,
            "trap evidence bounds"
        );
        for (name, condition) in &self.conditions {
            text(name, 256)?;
            counter(condition.sequence)?;
            ensure!(
                serde_json::to_vec(condition)?.len() <= 2048,
                "trap condition size"
            );
        }
        Ok(())
    }
}
/// Run inside the restore transaction; retained evidence never becomes live input.
pub fn validate_restored(conn: &rusqlite::Connection) -> Result<()> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM snmp_receipts", [], |r| r.get(0))?;
    ensure!(count <= 10000, "too many SNMP receipts");
    for table in ["component_identity", "observation_evidence"] {
        let mut q = conn.prepare(&format!("SELECT device,key,data FROM {table}"))?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (device, key, raw) in rows {
            text(&key, 1024)?;
            ensure!(raw.len() <= 4096, "SNMP record size");
            if table == "component_identity" {
                serde_json::from_str::<ComponentIdentity>(&raw)?.validate()?;
            } else {
                let mut evidence: ObservationEvidence = serde_json::from_str(&raw)?;
                evidence.validate()?;
                let receipt_id: Option<i64> = conn.query_row(
                    "SELECT receipt_id FROM observation_evidence WHERE device=?1 AND key=?2",
                    rusqlite::params![device, key],
                    |r| r.get(0),
                )?;
                if let Some(id) = receipt_id {
                    ensure!(
                        conn.query_row(
                            "SELECT EXISTS(SELECT 1 FROM snmp_receipts WHERE id=?1 AND device=?2)",
                            rusqlite::params![id, device],
                            |r| r.get::<_, bool>(0)
                        )?,
                        "evidence receipt mismatch"
                    );
                }
                evidence.active = false;
                evidence.provisional = false;
                evidence.confirmation = "restored".into();
                conn.execute(
                    "UPDATE observation_evidence SET data=?3 WHERE device=?1 AND key=?2",
                    rusqlite::params![device, key, serde_json::to_string(&evidence)?],
                )?;
            }
        }
    }
    let mut q = conn.prepare("SELECT id,device,data FROM snmp_receipts")?;
    let rows = q
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, device, raw) in rows {
        ensure!(raw.len() <= 4096, "SNMP receipt size");
        let mut receipt: Receipt = serde_json::from_str(&raw)?;
        receipt.validate()?;
        let event_id: Option<i64> = conn.query_row(
            "SELECT event_id FROM snmp_receipts WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        if let Some(event) = event_id {
            ensure!(
                conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE id=?1 AND device=?2)",
                    rusqlite::params![event, device],
                    |r| r.get::<_, bool>(0)
                )?,
                "receipt event mismatch"
            );
        }
        receipt.restored = true;
        conn.execute(
            "UPDATE snmp_receipts SET data=?2 WHERE id=?1",
            rusqlite::params![id, serde_json::to_string(&receipt)?],
        )?;
    }
    Ok(())
}

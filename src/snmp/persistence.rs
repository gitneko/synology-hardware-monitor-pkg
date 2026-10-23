use super::{config::*, secrets::*};
use crate::{
    model::{Device, PrimaryProtocol},
    store::Store,
    vault::Vault,
};
use anyhow::{ensure, Result};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

pub type SealedUpdate = (Purpose, Option<Vec<u8>>);
pub type PreparedSecrets = Vec<SealedUpdate>;

/// Logical archive tables; local engine files and runtime epoch are intentionally excluded.
pub const TABLES: &[(&str, &str)] = &[
    ("protocol_secrets", "device,purpose,secret,revision"),
    ("snmp_receiver_settings", "id,config,revision"),
    ("component_identity", "device,key,data"),
    ("snmp_receipts", "id,device,revision,received,event_id,data"),
    ("observation_evidence", "device,key,receipt_id,data"),
];
pub fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE INDEX IF NOT EXISTS snmp_event_kind ON events(kind,id);
      CREATE TABLE IF NOT EXISTS snmp_alarm_clock(device TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, sequence INTEGER NOT NULL CHECK(sequence>=0));
      CREATE TABLE IF NOT EXISTS protocol_secrets(device TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,purpose TEXT NOT NULL CHECK(purpose IN ('snmp_poll','snmp_traps')),secret BLOB NOT NULL,revision INTEGER NOT NULL CHECK(revision>=0),PRIMARY KEY(device,purpose));
      CREATE TABLE IF NOT EXISTS snmp_receiver_settings(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>=0));
      CREATE TABLE IF NOT EXISTS component_identity(device TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,key TEXT NOT NULL,data TEXT NOT NULL CHECK(length(CAST(data AS BLOB))<=4096),PRIMARY KEY(device,key));
      CREATE TABLE IF NOT EXISTS snmp_receipts(id INTEGER PRIMARY KEY,device TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,revision INTEGER NOT NULL CHECK(revision>=0),received INTEGER NOT NULL CHECK(received>=0),event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,data TEXT NOT NULL CHECK(length(CAST(data AS BLOB))<=4096));
      CREATE TABLE IF NOT EXISTS observation_evidence(device TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,key TEXT NOT NULL,receipt_id INTEGER REFERENCES snmp_receipts(id) ON DELETE SET NULL,data TEXT NOT NULL CHECK(length(CAST(data AS BLOB))<=4096),PRIMARY KEY(device,key));
      CREATE TABLE IF NOT EXISTS snmp_runtime(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL CHECK(epoch>=0));
      INSERT OR IGNORE INTO snmp_runtime VALUES(1,0);")?;
    conn.execute(
        "INSERT OR IGNORE INTO snmp_receiver_settings VALUES(1,?1,0)",
        [serde_json::to_string(&ReceiverSettings::default())?],
    )?;
    Ok(())
}
pub fn invalidate(conn: &Connection) -> Result<()> {
    ensure!(
        conn.execute(
            "UPDATE snmp_runtime SET epoch=epoch+1 WHERE id=1 AND epoch<9223372036854775806",
            []
        )? == 1,
        "SNMP runtime epoch exhausted"
    );
    Ok(())
}
pub fn security(device: &Device, purpose: Purpose) -> Option<&Security> {
    match purpose {
        Purpose::SnmpPoll => device.snmp_poll.as_ref().map(|c| &c.security),
        Purpose::SnmpTraps => device.snmp_traps.as_ref().map(|c| &c.security),
    }
}
pub fn scope_equal(old: &Device, new: &Device, purpose: Purpose) -> bool {
    match purpose {
        Purpose::SnmpPoll => match (&old.snmp_poll, &new.snmp_poll) {
            (Some(a), Some(b)) => {
                a.same_credentials_scope(b) && old.primary_protocol == new.primary_protocol
            }
            (None, None) => true,
            _ => false,
        },
        Purpose::SnmpTraps => match (&old.snmp_traps, &new.snmp_traps) {
            (Some(a), Some(b)) => a.same_credentials_scope(b),
            (None, None) => true,
            _ => false,
        },
    }
}
/// Prepare ciphertext before writing; no secret appears in device JSON or error text.
pub fn prepare_secrets(
    store: &Store,
    vault: &Vault,
    device: &Device,
    updates: &SecretUpdates,
) -> Result<PreparedSecrets> {
    let old = store.get(&device.id)?;
    let mut prepared = Vec::new();
    for (purpose, action) in [
        (Purpose::SnmpPoll, &updates.snmp_poll),
        (Purpose::SnmpTraps, &updates.snmp_traps),
    ] {
        let config = security(device, purpose);
        let cipher = match action {
            SecretUpdate::Keep { .. } => {
                let saved = store.protocol_secret(&device.id, purpose)?;
                if saved.is_some() {
                    ensure!(
                        old.as_ref()
                            .is_some_and(|(old, _, _)| scope_equal(old, device, purpose)),
                        "SNMP credential replacement or clear required after identity change"
                    );
                }
                saved
            }
            SecretUpdate::Clear { .. } => None,
            SecretUpdate::Replace { credentials } => {
                credentials
                    .validate(config.ok_or_else(|| {
                        anyhow::anyhow!("SNMP credentials require configuration")
                    })?)?;
                let plain = Zeroizing::new(serde_json::to_vec(credentials)?);
                Some(vault.seal(&purpose.aad(&device.id), &plain)?)
            }
        };
        ensure!(
            config.is_some() || cipher.is_none(),
            "clear unused SNMP credentials explicitly"
        );
        if let (Some(config), Some(cipher)) = (config, &cipher) {
            let plain = vault.unseal(&purpose.aad(&device.id), cipher)?;
            serde_json::from_slice::<Credentials>(&plain)?.validate(config)?;
        }
        let required = device.enabled
            && match purpose {
                Purpose::SnmpPoll => device.primary_protocol == PrimaryProtocol::Snmp,
                Purpose::SnmpTraps => device.snmp_traps.as_ref().is_some_and(|c| c.enabled),
            };
        ensure!(
            !required || cipher.is_some(),
            "SNMP credentials required for enabled input"
        );
        prepared.push((purpose, cipher));
    }
    Ok(prepared)
}
impl Store {
    pub fn protocol_secret(&self, id: &str, purpose: Purpose) -> Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .query_row(
                "SELECT secret FROM protocol_secrets WHERE device=?1 AND purpose=?2",
                params![id, purpose.as_str()],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn receiver_settings(&self) -> Result<(ReceiverSettings, i64)> {
        let (raw, rev): (String, i64) = self.0.query_row(
            "SELECT config,revision FROM snmp_receiver_settings WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let settings: ReceiverSettings = serde_json::from_str(&raw)?;
        settings.validate()?;
        Ok((settings, rev))
    }
    pub fn receiver_epoch(&self) -> Result<i64> {
        Ok(self
            .0
            .query_row("SELECT epoch FROM snmp_runtime WHERE id=1", [], |r| {
                r.get(0)
            })?)
    }
    pub fn save_receiver_settings(
        &mut self,
        settings: &ReceiverSettings,
        revision: i64,
        actor: &str,
    ) -> Result<()> {
        settings.validate()?;
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure!((0..i64::MAX/4).contains(&revision) && tx.execute("UPDATE snmp_receiver_settings SET config=?1,revision=revision+1 WHERE id=1 AND revision=?2",params![serde_json::to_string(settings)?,revision])?==1,crate::dsm::BoundaryError("device_conflict"));
        invalidate(&tx)?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'snmp.receiver.update','application','ok',?2)",params![actor,crate::now()])?;
        tx.commit()?;
        Ok(())
    }
}

//! Versioned encrypted logical archive. Never execute SQL or filesystem paths from a backup.
use crate::{dsm::BoundaryError, model::PrimaryProtocol, store::Store, vault::Vault};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use rusqlite::{
    params,
    types::{Value, ValueRef},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, num::NonZeroU32};
use zeroize::{Zeroize, Zeroizing};
pub const MAX_PLAIN: usize = 16 * 1024 * 1024;
pub const MAX_FILE: usize = 24 * 1024 * 1024;
const HEADER: &[u8] = b"HWMON-BACKUP-1\n";
const ITERATIONS: u32 = 600_000;
const TABLES: &[(&str,&str)]=&[
    ("counters","name,value"),
    ("devices","id,config,secret,last_poll,snapshot,logs_initialized,revision"),
    ("alarm_state","device,key,health,label,observed,emitted"),
    ("alarm_control","device,key,token,acknowledged,actor,acknowledged_at,reason,signature,reannounce"),
    ("events","id,device,key,kind,health,message,created,device_name,source_created,canonical_key,mail_reason,desktop_reason,correlated_keys,message_context"),
    ("hardware_logs","device,fingerprint,data"),
    ("mail_settings","id,config,secret,revision"),
    ("notification_settings","id,config,revision"),
    ("outbox","id,event_id,delivered,attempts,next_try,cancelled,transport"),
    ("mail_recipient","outbox_id,recipient,message_id,revision,delivered,attempts,next_try,error,permanent"),
    ("mail_replay", crate::mail_replay::COLUMNS),
    ("desktop_jobs","event_id,recipient,revision,delivered,attempts,next_try,error,cancelled"),
    ("audit_log","id,actor,action,device,outcome,created"),
];
const FORMAT: u32 = 5;
fn table_specs() -> impl Iterator<Item = &'static (&'static str, &'static str)> {
    TABLES.iter().chain(crate::snmp::persistence::TABLES.iter())
}
fn purpose(value: &str) -> Result<crate::snmp::secrets::Purpose> {
    match value {
        "snmp_poll" => Ok(crate::snmp::secrets::Purpose::SnmpPoll),
        "snmp_traps" => Ok(crate::snmp::secrets::Purpose::SnmpTraps),
        _ => anyhow::bail!("unknown protocol credential purpose"),
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
enum Cell {
    Null,
    Integer(i64),
    Text(String),
    Blob(String),
}
impl Drop for Cell {
    fn drop(&mut self) {
        match self {
            Self::Text(s) | Self::Blob(s) => s.zeroize(),
            _ => {}
        }
    }
}
impl Cell {
    fn sql(&self) -> Result<Value> {
        Ok(match self {
            Self::Null => Value::Null,
            Self::Integer(n) => Value::Integer(*n),
            Self::Text(s) => Value::Text(s.clone()),
            Self::Blob(s) => Value::Blob(STANDARD.decode(s)?),
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    format: u32,
    version: String,
    created: i64,
    tables: BTreeMap<String, Vec<Vec<Cell>>>,
}
impl Archive {
    fn validate_layout(&self) -> Result<()> {
        anyhow::ensure!(
            self.format == FORMAT && self.tables.len() == table_specs().count(),
            "version/tables"
        );
        for (table, columns) in table_specs() {
            let rows = self.tables.get(*table).context("missing table")?;
            anyhow::ensure!(
                rows.iter()
                    .flatten()
                    .all(|cell| !matches!(cell,Cell::Integer(n) if *n<0 || *n>i64::MAX/4)),
                "integer bounds"
            );
            anyhow::ensure!(
                rows.iter().all(|r| r.len() == columns.split(',').count()),
                "columns"
            );
        }
        Ok(())
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"version":self.version,"created":self.created,"devices":self.tables["devices"].len(),"events":self.tables["events"].len(),"alarms":self.tables["alarm_state"].len()})
    }
}
fn key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    anyhow::ensure!(
        password.chars().count() >= 12 && password.len() <= 1024,
        BoundaryError("backup_password_invalid")
    );
    let mut output = Zeroizing::new([0u8; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        output.as_mut(),
    );
    Ok(output)
}
pub fn encrypt(archive: &Archive, password: &str) -> Result<String> {
    let plain = Zeroizing::new(serde_json::to_vec(archive)?);
    anyhow::ensure!(plain.len() <= MAX_PLAIN, BoundaryError("backup_too_large"));
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
    let mut envelope = [HEADER, &salt, &nonce].concat();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &envelope,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    envelope.extend(encrypted);
    Ok(STANDARD.encode(envelope))
}
pub fn decrypt(file: &str, password: &str) -> Result<Archive> {
    let result = || -> Result<Archive> {
        anyhow::ensure!(file.len() <= MAX_FILE, BoundaryError("backup_too_large"));
        let envelope = STANDARD.decode(file.trim())?;
        let prefix = HEADER.len();
        let offset = prefix + 28;
        anyhow::ensure!(
            envelope.len() >= offset + 16 && envelope.starts_with(HEADER),
            "format"
        );
        let key = key(password, &envelope[prefix..prefix + 16])?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&envelope[prefix + 16..offset]),
                    Payload {
                        msg: &envelope[offset..],
                        aad: &envelope[..offset],
                    },
                )
                .map_err(|_| anyhow::anyhow!("authentication"))?,
        );
        anyhow::ensure!(plain.len() <= MAX_PLAIN, "size");
        let mut archive: Archive = serde_json::from_slice(&plain)?;
        if archive.format == 1 {
            let events = archive
                .tables
                .get_mut("events")
                .context("events table missing")?;
            anyhow::ensure!(events.iter().all(|row| row.len() == 13), "legacy columns");
            for row in events {
                row.push(Cell::Null);
            }
            archive.format = 2;
        }
        if archive.format == 2 {
            anyhow::ensure!(
                archive.tables.len() == TABLES.len() - 2
                    && !archive.tables.contains_key("alarm_control"),
                "legacy tables"
            );
            archive.tables.insert("alarm_control".into(), Vec::new());
            archive.format = 3;
        }
        if archive.format == 3 {
            anyhow::ensure!(
                archive.tables.len() == TABLES.len() - 1
                    && !archive.tables.contains_key("mail_replay"),
                "legacy replay table"
            );
            archive.tables.insert("mail_replay".into(), Vec::new());
            archive.format = 4;
        }
        if archive.format == 4 {
            anyhow::ensure!(
                archive.tables.len() == TABLES.len()
                    && TABLES.iter().all(|(t, _)| archive.tables.contains_key(*t)),
                "legacy SNMP tables"
            );
            for (table, _) in crate::snmp::persistence::TABLES {
                archive.tables.insert((*table).into(), Vec::new());
            }
            archive
                .tables
                .get_mut("snmp_receiver_settings")
                .unwrap()
                .push(vec![
                    Cell::Integer(1),
                    Cell::Text(serde_json::to_string(
                        &crate::snmp::config::ReceiverSettings::default(),
                    )?),
                    Cell::Integer(0),
                ]);
            archive.format = FORMAT;
        }
        archive.validate_layout()?;
        Ok(archive)
    };
    result().context(BoundaryError("backup_invalid"))
}
impl Store {
    pub fn make_archive(&self, vault: &Vault) -> Result<Archive> {
        let tx = self.0.unchecked_transaction()?;
        let mut tables = BTreeMap::new();
        let mut size = 0usize;
        // Caller holds the store mutex, so no application writer can interleave.
        for (table, columns) in table_specs() {
            let mut q = tx.prepare(&format!("SELECT {columns} FROM {table}"))?;
            let mut query = q.query([])?;
            let mut rows = Vec::new();
            while let Some(row) = query.next()? {
                let mut cells = Vec::new();
                for i in 0..columns.split(',').count() {
                    let value = match row.get_ref(i)? {
                        ValueRef::Null => Cell::Null,
                        ValueRef::Integer(n) => Cell::Integer(n),
                        ValueRef::Text(s) => Cell::Text(std::str::from_utf8(s)?.into()),
                        ValueRef::Blob(b) => Cell::Blob(STANDARD.encode(b)),
                        _ => anyhow::bail!("unsupported stored type"),
                    };
                    size += match &value {
                        Cell::Text(s) | Cell::Blob(s) => s.len() + 40,
                        _ => 40,
                    };
                    anyhow::ensure!(size <= MAX_PLAIN, BoundaryError("backup_too_large"));
                    cells.push(value);
                }
                if *table == "devices" || *table == "mail_settings" || *table == "protocol_secrets"
                {
                    let id = if *table == "devices" {
                        match &cells[0] {
                            Cell::Text(s) => s.clone(),
                            _ => anyhow::bail!("device ID"),
                        }
                    } else if *table == "protocol_secrets" {
                        let (Cell::Text(id), Cell::Text(p)) = (&cells[0], &cells[1]) else {
                            anyhow::bail!("protocol identity")
                        };
                        purpose(p)?.aad(id)
                    } else {
                        "settings:smtp".to_owned()
                    };
                    if let Cell::Blob(blob) = &mut cells[2] {
                        if !blob.is_empty() {
                            let secret = vault.unseal(&id, &STANDARD.decode(&*blob)?)?;
                            blob.zeroize();
                            *blob = STANDARD.encode(&*secret);
                        }
                    }
                    if *table == "devices" {
                        let Cell::Text(raw) = &mut cells[1] else {
                            anyhow::bail!("config")
                        };
                        let mut device: crate::model::Device = serde_json::from_str(raw)?;
                        if let Some(path) = device.ca_file.take() {
                            use std::io::Read;
                            let mut pem = String::new();
                            std::fs::File::open(path)?
                                .take(65537)
                                .read_to_string(&mut pem)?;
                            crate::model::validate_certificates(&pem)?;
                            device.ca_pem = Some(pem);
                            *raw = serde_json::to_string(&device)?;
                        }
                    }
                }
                rows.push(cells);
            }
            tables.insert((*table).into(), rows);
        }
        tx.commit()?;
        Ok(Archive {
            format: FORMAT,
            version: env!("CARGO_PKG_VERSION").into(),
            created: crate::now(),
            tables,
        })
    }
    pub fn audit_cursor(&self) -> Result<i64> {
        Ok(self
            .0
            .query_row("SELECT COALESCE(MAX(id),0) FROM audit_log", [], |r| {
                r.get(0)
            })?)
    }
    pub fn restore_archive(
        &mut self,
        archive: &Archive,
        vault: &Vault,
        actor: &str,
        expected_audit: i64,
    ) -> Result<()> {
        archive.validate_layout()?;
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let cursor: i64 = tx.query_row("SELECT COALESCE(MAX(id),0) FROM audit_log", [], |r| {
            r.get(0)
        })?;
        anyhow::ensure!(cursor == expected_audit, BoundaryError("backup_conflict"));
        let event_floor:i64=tx.query_row("SELECT MAX(COALESCE(MAX(id),0),COALESCE((SELECT value FROM counters WHERE name='events'),0)) FROM events",[],|r|r.get(0))?;
        let mail_revision: i64 = tx.query_row(
            "SELECT COALESCE(MAX(revision),0) FROM mail_settings",
            [],
            |r| r.get(0),
        )?;
        let notification_revision: i64 = tx.query_row(
            "SELECT COALESCE(MAX(revision),0) FROM notification_settings",
            [],
            |r| r.get(0),
        )?;
        let revision: i64 =
            tx.query_row("SELECT COALESCE(MAX(revision),0) FROM devices", [], |r| {
                r.get(0)
            })?;
        let receiver_revision: i64 = tx.query_row(
            "SELECT revision FROM snmp_receiver_settings WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        for (table, _) in crate::snmp::persistence::TABLES.iter().rev() {
            tx.execute(&format!("DELETE FROM {table}"), [])?;
        }
        for table in [
            "mail_replay",
            "mail_recipient",
            "desktop_jobs",
            "outbox",
            "alarm_control",
            "alarm_state",
            "hardware_logs",
            "events",
            "devices",
            "mail_settings",
            "notification_settings",
            "counters",
        ] {
            tx.execute(&format!("DELETE FROM {table}"), [])?;
        }
        for (table, columns) in table_specs() {
            let marks = vec!["?"; columns.split(',').count()].join(",");
            let sql = if *table == "audit_log" {
                "INSERT INTO audit_log(actor,action,device,outcome,created) SELECT ?1,?2,?3,?4,?5 WHERE NOT EXISTS(SELECT 1 FROM audit_log WHERE actor=?1 AND action=?2 AND device=?3 AND outcome=?4 AND created=?5)".into()
            } else {
                format!("INSERT INTO {table}({columns}) VALUES({marks})")
            };
            let mut statement = tx.prepare(&sql)?;
            for row in &archive.tables[*table] {
                let mut values = row.iter().map(Cell::sql).collect::<Result<Vec<_>>>()?;
                if *table == "devices" || *table == "mail_settings" || *table == "protocol_secrets"
                {
                    let id = if *table == "devices" {
                        match &values[0] {
                            Value::Text(s) => s.clone(),
                            _ => anyhow::bail!("device ID"),
                        }
                    } else if *table == "protocol_secrets" {
                        let (Value::Text(id), Value::Text(p)) = (&values[0], &values[1]) else {
                            anyhow::bail!("protocol identity")
                        };
                        purpose(p)?.aad(id)
                    } else {
                        "settings:smtp".to_owned()
                    };
                    if let Value::Blob(secret) = &values[2] {
                        if !secret.is_empty() {
                            let sealed = vault.seal(&id, secret)?;
                            if let Value::Blob(old) = &mut values[2] {
                                old.zeroize();
                            }
                            values[2] = Value::Blob(sealed);
                        }
                    }
                }
                if *table == "audit_log" {
                    statement.execute(rusqlite::params_from_iter(values.iter().skip(1)))?;
                } else {
                    statement.execute(rusqlite::params_from_iter(values))?;
                }
            }
        }
        // Imported acknowledgements require an explicit operator review on this installation.
        // Preserve attribution/reason, but never activate old suppression automatically.
        {
            let mut q = tx.prepare("SELECT token,acknowledged,actor,acknowledged_at,reason,signature,reannounce FROM alarm_control")?;
            let rows = q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?;
            for row in rows {
                let (token, ack, actor, at, reason, signature, reannounce) = row?;
                anyhow::ensure!(
                    token.len() == 32
                        && token.bytes().all(|c| c.is_ascii_hexdigit())
                        && matches!(ack, 0 | 1)
                        && matches!(reannounce, 0 | 1),
                    "alarm control"
                );
                anyhow::ensure!(
                    reason.as_ref().is_none_or(|s| !s.trim().is_empty()
                        && s.len() <= 1000
                        && !s.chars().any(char::is_control))
                        && actor.as_ref().is_none_or(|s| !s.is_empty()
                            && s.len() <= 1024
                            && !s.chars().any(char::is_control)),
                    "acknowledgement metadata"
                );
                anyhow::ensure!(
                    ack == 0 || (actor.is_some() && at.is_some() && reason.is_some()),
                    "acknowledgement attribution"
                );
                if !signature.is_empty() {
                    serde_json::from_str::<serde_json::Value>(&signature)?;
                }
            }
        }
        tx.execute(
            "UPDATE alarm_control SET token=lower(hex(randomblob(16))),acknowledged=0,reannounce=0",
            [],
        )?;
        crate::acknowledgement::initialize(&tx)?;
        // Preserve event identifiers across replacement and subsequent log clearing.
        tx.execute("INSERT INTO counters(name,value) SELECT 'events',MAX(?1,COALESCE(MAX(id),0),COALESCE((SELECT value FROM counters WHERE name='events'),0)) FROM events WHERE true ON CONFLICT(name) DO UPDATE SET value=excluded.value",[event_floor])?;
        {
            let mut q =
                tx.prepare("SELECT correlated_keys FROM events WHERE correlated_keys IS NOT NULL")?;
            for row in q.query_map([], |r| r.get::<_, String>(0))? {
                serde_json::from_str::<Vec<String>>(&row?)?;
            }
        }
        {
            let mut q =
                tx.prepare("SELECT message_context FROM events WHERE message_context IS NOT NULL")?;
            for row in q.query_map([], |r| r.get::<_, String>(0))? {
                let context: serde_json::Value = serde_json::from_str(&row?)?;
                anyhow::ensure!(
                    context["version"] == 1
                        && context["label"].is_string()
                        && context["retained"].is_boolean(),
                    "message context"
                );
            }
        }
        // Validate imported application records inside the transaction before committing.
        let mut devices = Vec::new();
        {
            let mut q = tx.prepare("SELECT id,config,secret,revision FROM devices")?;
            for row in q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })? {
                let (id, raw, secret, old_revision) = row?;
                let mut d: crate::model::Device = serde_json::from_str(&raw)?;
                d.validate()?;
                anyhow::ensure!(
                    d.id == id && d.ca_file.is_none() && old_revision >= 0,
                    "invalid restored device"
                );
                if d.primary_protocol == PrimaryProtocol::Redfish {
                    let plain = vault.unseal(&d.id, &secret)?;
                    anyhow::ensure!(
                        !plain.is_empty()
                            && plain.len() <= 4096
                            && std::str::from_utf8(&plain).is_ok(),
                        "device secret"
                    );
                } else {
                    anyhow::ensure!(secret.is_empty(), "SNMP device has Redfish password");
                }
                d.enabled = false;
                if let Some(traps) = &mut d.snmp_traps {
                    traps.enabled = false;
                }
                devices.push((d, old_revision));
            }
        }
        for (d, old_revision) in devices {
            let next = revision
                .max(old_revision)
                .checked_add(1)
                .context("revision overflow")?;
            tx.execute(
                "UPDATE devices SET config=?2,revision=?3 WHERE id=?1",
                params![d.id, serde_json::to_string(&d)?, next],
            )?;
        }
        {
            let mut q=tx.prepare("SELECT s.device,s.purpose,s.secret,s.revision,d.config,d.revision FROM protocol_secrets s JOIN devices d ON d.id=s.device")?;
            for row in q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })? {
                let (id, p, secret, revision, raw, device_revision) = row?;
                anyhow::ensure!(
                    (0..=device_revision).contains(&revision)
                        && (28..=8192).contains(&secret.len()),
                    "protocol secret revision/size"
                );
                let p = purpose(&p)?;
                let device: crate::model::Device = serde_json::from_str(&raw)?;
                let security = crate::snmp::persistence::security(&device, p)
                    .context("protocol config missing")?;
                let plain = vault.unseal(&p.aad(&id), &secret)?;
                serde_json::from_slice::<crate::snmp::secrets::Credentials>(&plain)?
                    .validate(security)?;
            }
            let (raw, rev): (String, i64) = tx.query_row(
                "SELECT config,revision FROM snmp_receiver_settings WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut receiver: crate::snmp::config::ReceiverSettings = serde_json::from_str(&raw)?;
            receiver.validate()?;
            receiver.enabled = false;
            tx.execute(
                "UPDATE snmp_receiver_settings SET config=?1,revision=?2 WHERE id=1",
                params![
                    serde_json::to_string(&receiver)?,
                    receiver_revision
                        .max(rev)
                        .checked_add(1)
                        .context("receiver revision overflow")?
                ],
            )?;
            crate::snmp::records::validate_restored(&tx)?;
            crate::snmp::persistence::invalidate(&tx)?;
        }
        {
            let mut q = tx.prepare("SELECT id,config,secret,revision FROM mail_settings")?;
            let rows = q
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (id, raw, secret, rev) in rows {
                let mut settings: crate::mail::Settings = serde_json::from_str(&raw)?;
                settings.validate()?;
                anyhow::ensure!(id == 1 && rev >= 0, "mail settings");
                if !secret.is_empty() {
                    let plain = vault.unseal("settings:smtp", &secret)?;
                    anyhow::ensure!(
                        plain.len() <= 4096 && std::str::from_utf8(&plain).is_ok(),
                        "mail secret"
                    );
                }
                settings.enabled = false;
                tx.execute(
                    "UPDATE mail_settings SET config=?1,revision=?2 WHERE id=1",
                    params![
                        serde_json::to_string(&settings)?,
                        mail_revision
                            .max(rev)
                            .checked_add(1)
                            .context("revision overflow")?
                    ],
                )?;
            }
        }
        {
            let mut q = tx.prepare("SELECT id,config,revision FROM notification_settings")?;
            let rows = q
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (id, raw, rev) in rows {
                let mut settings: crate::notification::Settings = serde_json::from_str(&raw)?;
                anyhow::ensure!(id == 1 && rev >= 0, "notification settings");
                settings.desktop_enabled = false;
                settings.desktop_recipient = None;
                tx.execute(
                    "UPDATE notification_settings SET config=?1,revision=?2 WHERE id=1",
                    params![
                        serde_json::to_string(&settings)?,
                        notification_revision
                            .max(rev)
                            .checked_add(1)
                            .context("revision overflow")?
                    ],
                )?;
            }
        }
        {
            let mut q =
                tx.prepare("SELECT health FROM alarm_state UNION ALL SELECT health FROM events")?;
            for row in q.query_map([], |r| r.get::<_, String>(0))? {
                serde_json::from_str::<crate::model::Health>(&row?)?;
            }
        }
        {
            let mut q = tx.prepare("SELECT snapshot FROM devices WHERE snapshot IS NOT NULL")?;
            for row in q.query_map([], |r| r.get::<_, String>(0))? {
                serde_json::from_str::<crate::model::Snapshot>(&row?)?;
            }
        }
        {
            let mut q = tx.prepare("SELECT data FROM hardware_logs")?;
            for row in q.query_map([], |r| r.get::<_, String>(0))? {
                serde_json::from_str::<crate::model::HardwareLog>(&row?)?;
            }
        }
        anyhow::ensure!(
            !tx.prepare("PRAGMA foreign_key_check")?.exists([])?,
            "foreign keys"
        );
        tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL", [])?;
        crate::mail_replay::cancel(&tx, crate::now())?;
        tx.execute(
            "UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL",
            [],
        )?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'backup.restore','application','Erfolgreich; Überwachung und Versand pausiert',?2)",params![actor,crate::now()])?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_history_roundtrips_but_pending_jobs_and_drafts_never_resume_and_format_three_still_loads(
    ) {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let v1 = Vault::open(&source.path().join("master.key")).unwrap();
        let v2 = Vault::open(&target.path().join("master.key")).unwrap();
        let mut s = Store::open(source.path()).unwrap();
        let settings = crate::mail::Settings {
            host: "localhost".into(),
            from_address: "sender@example.invalid".into(),
            recipients: vec!["alarm@example.invalid".into()],
            ..Default::default()
        };
        s.save_mail(&settings, b"", 0, "admin").unwrap();
        s.0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(1,'removed','drive','alarm','\"critical\"','Original hardware fault',100)",[]).unwrap();
        let first = s
            .preview_mail_replay(1, "alarm@example.invalid", "admin", 200)
            .unwrap();
        s.enqueue_mail_replay(first["id"].as_str().unwrap(), "admin", 200)
            .unwrap();
        let job = s.pending_mail_replay(200).unwrap().unwrap();
        s.finish_mail_replay(&job, None, 201).unwrap();
        let pending = s
            .preview_mail_replay(1, "alarm@example.invalid", "admin", 202)
            .unwrap();
        s.enqueue_mail_replay(pending["id"].as_str().unwrap(), "admin", 202)
            .unwrap();
        s.preview_mail_replay(1, "alarm@example.invalid", "admin", 203)
            .unwrap();
        let archive = s.make_archive(&v1).unwrap();
        let decoded = decrypt(
            &encrypt(&archive, "synthetic-backup-password").unwrap(),
            "synthetic-backup-password",
        )
        .unwrap();
        assert_eq!(decoded.format, FORMAT);
        let mut t = Store::open(target.path()).unwrap();
        t.restore_archive(&decoded, &v2, "target-admin", 0).unwrap();
        assert!(t.pending_mail_replay(crate::now()).unwrap().is_none());
        let history = t.mail_replay_history(1).unwrap();
        assert_eq!(history.len(), 2);
        assert!(history
            .iter()
            .any(|j| j["state"] == "submitted" && j["message_id"] == job.message_id));
        assert!(history.iter().any(|j| j["state"] == "cancelled"));
        let mut old = archive;
        for (table, _) in crate::snmp::persistence::TABLES {
            old.tables.remove(*table);
        }
        old.format = 3;
        old.tables.remove("mail_replay");
        let decoded = decrypt(
            &encrypt(&old, "synthetic-backup-password").unwrap(),
            "synthetic-backup-password",
        )
        .unwrap();
        assert_eq!(decoded.format, FORMAT);
        assert!(decoded.tables["mail_replay"].is_empty());
    }
    #[test]
    fn acknowledged_faults_roundtrip_but_require_review_and_old_format_two_still_imports() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let v1 = Vault::open(&source.path().join("master.key")).unwrap();
        let v2 = Vault::open(&target.path().join("master.key")).unwrap();
        let mut s = Store::open(source.path()).unwrap();
        let d = device();
        let now = crate::now();
        s.put(&d, &v1.seal(&d.id, b"synthetic-device-secret").unwrap())
            .unwrap();
        s.apply(
            &d,
            &crate::model::Snapshot {
                observations: vec![crate::model::Observation {
                    key: "fan".into(),
                    label: "Fan".into(),
                    health: crate::model::Health::Critical,
                    reading: None,
                    unit: None,
                }],
                ..Default::default()
            },
            now,
        )
        .unwrap();
        let token = s.dashboard().unwrap()["devices"][0]["alarm_statuses"]["fan"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        s.acknowledge_alarm(
            &d.id,
            1,
            "fan",
            &token,
            true,
            "Known damaged input",
            "source-admin",
            now,
        )
        .unwrap();
        let archive = s.make_archive(&v1).unwrap();
        let decoded = decrypt(
            &encrypt(&archive, "synthetic-backup-password").unwrap(),
            "synthetic-backup-password",
        )
        .unwrap();
        let mut t = Store::open(target.path()).unwrap();
        t.restore_archive(&decoded, &v2, "target-admin", 0).unwrap();
        let dashboard = t.dashboard().unwrap();
        let status = &dashboard["devices"][0]["alarm_statuses"]["fan"];
        assert_eq!(status["status"], "critical");
        assert_eq!(status["acknowledgement"]["needs_review"], true);
        assert_eq!(status["acknowledgement"]["reason"], "Known damaged input");
        assert_ne!(status["token"], token);
        let mut legacy = s.make_archive(&v1).unwrap();
        for (table, _) in crate::snmp::persistence::TABLES {
            legacy.tables.remove(*table);
        }
        legacy.format = 2;
        legacy.tables.remove("alarm_control");
        legacy.tables.remove("mail_replay");
        let decoded = decrypt(
            &encrypt(&legacy, "synthetic-backup-password").unwrap(),
            "synthetic-backup-password",
        )
        .unwrap();
        assert_eq!(decoded.format, FORMAT);
        assert!(decoded.tables["alarm_control"].is_empty());
        let cursor = t.audit_cursor().unwrap();
        t.restore_archive(&decoded, &v2, "target-admin", cursor)
            .unwrap();
        assert!(
            t.dashboard().unwrap()["devices"][0]["alarm_statuses"]["fan"]["acknowledgement"]
                .is_null()
        );
        // Invalid imported metadata rolls back the entire replacement.
        let mut invalid = s.make_archive(&v1).unwrap();
        invalid.tables.get_mut("alarm_control").unwrap()[0][3] = Cell::Integer(2);
        let cursor = t.audit_cursor().unwrap();
        assert!(t
            .restore_archive(&invalid, &v2, "target-admin", cursor)
            .is_err());
        assert_eq!(t.audit_cursor().unwrap(), cursor);
        assert!(!t.get(&d.id).unwrap().unwrap().0.enabled);
    }
    fn device() -> crate::model::Device {
        crate::model::Device {
            primary_protocol: Default::default(),
            snmp_poll: None,
            snmp_traps: None,
            id: "backup-test".into(),
            name: "Backup-Test".into(),
            endpoint: "https://bmc.example/".into(),
            username: "reader".into(),
            interval_seconds: 60,
            repeat_seconds: Some(300),
            alerts_enabled: true,
            ca_file: None,
            ca_pem: None,
            tls_profile: Default::default(),
            pinned_certificate_pem: None,
            enabled: true,
        }
    }
    #[test]
    fn encrypted_cross_key_restore_preserves_state_and_cancels_delivery_atomically() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let v1 = Vault::open(&source.path().join("master.key")).unwrap();
        let v2 = Vault::open(&target.path().join("master.key")).unwrap();
        let mut s = Store::open(source.path()).unwrap();
        let mut d = device();
        d.tls_profile = crate::model::TlsProfile::Idrac7;
        d.pinned_certificate_pem = Some(crate::legacy_tls::tests::pem());
        s.put(&d, &v1.seal(&d.id, b"device-secret-marker").unwrap())
            .unwrap();
        let settings = crate::mail::Settings {
            enabled: true,
            host: "smtp.example".into(),
            from_address: "sender@example.org".into(),
            recipients: vec!["recipient@example.org".into()],
            ..Default::default()
        };
        s.save_mail(
            &settings,
            &v1.seal("settings:smtp", b"smtp-secret-marker").unwrap(),
            0,
            "source-admin",
        )
        .unwrap();
        s.save_notifications(
            &crate::notification::Input {
                language: Default::default(),
                revision: 0,
                desktop_enabled: true,
                selection: Default::default(),
            },
            "source-admin",
        )
        .unwrap();
        let snapshot = crate::model::Snapshot {
            observations: vec![crate::model::Observation {
                key: "psu".into(),
                label: "PS1".into(),
                health: crate::model::Health::Critical,
                reading: None,
                unit: None,
            }],
            ..Default::default()
        };
        s.apply(&d, &snapshot, crate::now()).unwrap();
        let archive = s.make_archive(&v1).unwrap();
        let file = encrypt(&archive, "a sufficiently long password").unwrap();
        assert!(!file.contains("device-secret-marker") && !file.contains("smtp-secret-marker"));
        assert!(decrypt(&file, "wrong password here").is_err());
        let mut corrupt = STANDARD.decode(&file).unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(decrypt(&STANDARD.encode(corrupt), "a sufficiently long password").is_err());
        let mut legacy = decrypt(&file, "a sufficiently long password").unwrap();
        for (table, _) in crate::snmp::persistence::TABLES {
            legacy.tables.remove(*table);
        }
        legacy.format = 1;
        legacy.tables.remove("alarm_control");
        legacy.tables.remove("mail_replay");
        for table in ["mail_settings", "notification_settings"] {
            for row in legacy.tables.get_mut(table).unwrap() {
                if let Cell::Text(raw) = &mut row[1] {
                    let mut config: serde_json::Value = serde_json::from_str(raw).unwrap();
                    config.as_object_mut().unwrap().remove("language");
                    *raw = serde_json::to_string(&config).unwrap();
                }
            }
        }
        for row in legacy.tables.get_mut("events").unwrap() {
            row.pop();
        }
        let old_file = encrypt(&legacy, "a sufficiently long password").unwrap();
        let decoded = decrypt(&old_file, "a sufficiently long password").unwrap();
        assert_eq!(decoded.format, FORMAT);
        assert!(matches!(
            decoded.tables["events"][0].last(),
            Some(Cell::Null)
        ));

        let mut t = Store::open(target.path()).unwrap();
        t.put(&d, &v2.seal(&d.id, b"old-target-secret").unwrap())
            .unwrap();
        let old = t.get(&d.id).unwrap().unwrap();
        for revision in 0..3 {
            t.save_mail(&settings, b"", revision, "target-admin")
                .unwrap();
            t.save_notifications(
                &crate::notification::Input {
                    language: Default::default(),
                    revision,
                    desktop_enabled: false,
                    selection: Default::default(),
                },
                "target-admin",
            )
            .unwrap();
        }
        t.audit("target-admin", "before.restore", "application", "ok")
            .unwrap();
        let cursor = t.audit_cursor().unwrap();
        t.restore_archive(&decoded, &v2, "target-admin", cursor)
            .unwrap();
        let (restored, secret, revision) = t.get(&d.id).unwrap().unwrap();
        assert!(!restored.enabled);
        assert_eq!(restored.tls_profile, d.tls_profile);
        assert_eq!(restored.pinned_certificate_pem, d.pinned_certificate_pem);
        assert!(revision > old.2);
        assert_eq!(
            &*v2.unseal(&d.id, &secret).unwrap(),
            b"device-secret-marker"
        );
        assert!(v1.unseal(&d.id, &secret).is_err());
        let (mail, secret, _) = t.mail_settings().unwrap().unwrap();
        assert!(!mail.enabled);
        assert!(t.mail_settings().unwrap().unwrap().2 > 3);
        assert!(t.notification_settings().unwrap().1 > 3);
        assert_eq!(
            &*v2.unseal("settings:smtp", &secret).unwrap(),
            b"smtp-secret-marker"
        );
        assert!(!t.notification_settings().unwrap().0.desktop_enabled);
        assert!(t.pending_mail(crate::now()).unwrap().is_none());
        assert!(t.pending_desktop(crate::now()).unwrap().is_none());
        assert!(!t
            .apply_revision(&d, &snapshot, crate::now(), Some(old.2))
            .unwrap());
        assert_eq!(
            t.dashboard().unwrap()["events"].as_array().unwrap().len(),
            1
        );
        let audit = t.audit_entries().unwrap().to_string();
        assert!(audit.contains("before.restore") && audit.contains("backup.restore"));
        assert!(t
            .restore_archive(&decoded, &v2, "target-admin", cursor)
            .is_err());
        // Corrupt application data must roll back even after records were replaced.
        let mut invalid = decrypt(&file, "a sufficiently long password").unwrap();
        invalid.tables.get_mut("devices").unwrap()[0][1] = Cell::Text("{}".into());
        let before = t.dashboard().unwrap();
        let cursor = t.audit_cursor().unwrap();
        assert!(t
            .restore_archive(&invalid, &v2, "target-admin", cursor)
            .is_err());
        assert_eq!(t.dashboard().unwrap(), before);
        // CSV exports retained history, quoted multiline data; clear keeps alarm and audit state.
        let (csv, count) = t.events_csv(&Default::default()).unwrap();
        assert_eq!(count, 1);
        assert!(csv.starts_with("\"Ereignis-ID\";"));
        assert!(csv.contains("Backup-Test"));
        assert_eq!(t.clear_events("target-admin").unwrap(), 1);
        let view = t.dashboard().unwrap();
        assert!(view["events"].as_array().unwrap().is_empty());
        assert_eq!(view["devices"][0]["alarms"].as_array().unwrap().len(), 1);
        assert!(t
            .audit_entries()
            .unwrap()
            .to_string()
            .contains("events.clear"));
    }
}

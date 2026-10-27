use crate::model::*;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::{json, Value};
use std::path::Path;

/// Device, selected encrypted primary credential, device revision, runtime epoch.
pub type PollTarget = (Device, Vec<u8>, i64, i64);
pub struct Store(pub Connection);

fn migration_backup(conn: &Connection, dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let name = format!("pre-snmp-schema1-{:032x}", rand::random::<u128>());
    let complete = dir.join(&name);
    let destination = dir.join(format!(".{name}.partial"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination)?;
    let result = (|| -> Result<()> {
        let backup = destination.join("monitor.db");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)?;
        conn.execute(
            "VACUUM INTO ?1",
            [backup
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("backup path"))?],
        )?;
        // Keep the matching key when present; never generate a replacement key.
        if dir.join("master.key").exists() {
            use std::io::{Read, Write};
            let source = dir.join("master.key");
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let source = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(source)?;
            let meta = source.metadata()?;
            anyhow::ensure!(
                meta.is_file()
                    && meta.len() == 32
                    && meta.permissions().mode() & 0o077 == 0
                    && meta.uid() == unsafe { libc::geteuid() },
                "invalid master key backup"
            );
            let mut key = zeroize::Zeroizing::new(Vec::new());
            source.take(33).read_to_end(&mut key)?;
            anyhow::ensure!(key.len() == 32, "invalid master key backup");
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(destination.join("master.key"))?;
            out.write_all(&key)?;
            out.sync_all()?;
        }
        std::fs::File::open(&backup)?.sync_all()?;
        std::fs::File::open(&destination)?.sync_all()?;
        // Publish only a complete, synced database/key pair. An interrupted copy
        // must not look like a usable rollback backup.
        std::fs::rename(&destination, &complete)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // Only our newly created temporary files; never touch existing backups.
        let _ = std::fs::remove_file(destination.join("monitor.db"));
        let _ = std::fs::remove_file(destination.join("master.key"));
        let _ = std::fs::remove_dir(&destination);
    }
    result
}

pub struct MailJob {
    pub outbox: i64,
    pub recipient: String,
    pub message_id: String,
    pub settings: crate::mail::Settings,
    pub secret: Vec<u8>,
    pub event: crate::mail::Event,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        crate::vault::private_dir(dir)?;
        let mut database = Connection::open(dir.join("monitor.db"))?;
        // Include schema discovery and backup; runtime keeps a shorter timeout.
        database.busy_timeout(std::time::Duration::from_secs(30))?;
        let has_schema: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version')", [], |r| r.get(0))?;
        let version: i64 = if has_schema {
            let (count, version): (i64, i64) = database.query_row(
                "SELECT COUNT(*),COALESCE(MIN(version),0) FROM schema_version",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            anyhow::ensure!(count == 1, "invalid database schema marker");
            version
        } else {
            1
        };
        anyhow::ensure!(
            matches!(version, 1 | 2),
            "unsupported database schema; restore matching application version"
        );
        let existing: bool = database.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='devices')",
            [],
            |r| r.get(0),
        )?;
        if version == 1 && existing {
            eprintln!("Preparing private database/key backup before schema-1 migration");
            migration_backup(&database, dir).context("create pre-migration database/key backup")?;
            eprintln!("Private pre-migration backup complete");
        }
        database.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;",
        )?;
        let conn = database.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        conn.execute_batch("
          CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
          INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
          CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, config TEXT NOT NULL, secret BLOB NOT NULL,
            last_poll INTEGER, snapshot TEXT, logs_initialized INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS alarm_state(device TEXT NOT NULL REFERENCES devices(id), key TEXT NOT NULL,
            health TEXT NOT NULL, label TEXT NOT NULL, observed INTEGER NOT NULL, emitted INTEGER,
            PRIMARY KEY(device,key));
          CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, device TEXT NOT NULL, key TEXT NOT NULL,
            kind TEXT NOT NULL, health TEXT NOT NULL, message TEXT NOT NULL, created INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS hardware_logs(device TEXT NOT NULL, fingerprint TEXT NOT NULL,
            data TEXT NOT NULL, PRIMARY KEY(device,fingerprint));
          CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL UNIQUE REFERENCES events(id),
            delivered INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0);")?;
        let version: i64 =
            conn.query_row("SELECT version FROM schema_version", [], |r| r.get(0))?;
        anyhow::ensure!(
            matches!(version, 1 | 2),
            "unsupported database schema; restore matching application version"
        );
        // Additive migrations keep existing device records and encrypted secrets.
        for (table, column, definition) in [
            ("devices", "revision", "INTEGER NOT NULL DEFAULT 0"),
            ("outbox", "cancelled", "INTEGER NOT NULL DEFAULT 0"),
            ("events", "device_name", "TEXT"),
            ("events", "source_created", "TEXT"),
            ("events", "canonical_key", "TEXT"),
            ("outbox", "transport", "TEXT"),
            ("events", "mail_reason", "TEXT"),
            ("events", "desktop_reason", "TEXT"),
            ("events", "correlated_keys", "TEXT"),
            ("events", "message_context", "TEXT"),
        ] {
            let mut q = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let columns = q
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(q);
            if !columns.iter().any(|c| c == column) {
                conn.execute_batch(&format!(
                    "ALTER TABLE {table} ADD COLUMN {column} {definition}"
                ))?;
            }
        }
        conn.execute_batch("CREATE TABLE IF NOT EXISTS mail_settings(id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL, secret BLOB NOT NULL, revision INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS mail_recipient(outbox_id INTEGER NOT NULL REFERENCES outbox(id) ON DELETE CASCADE, recipient TEXT NOT NULL, message_id TEXT NOT NULL, revision INTEGER NOT NULL, delivered INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0, error TEXT, permanent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(outbox_id,recipient));")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS notification_settings(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT NOT NULL,revision INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS desktop_jobs(event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,recipient TEXT NOT NULL,revision INTEGER NOT NULL,delivered INTEGER,attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL DEFAULT 0,error TEXT,cancelled INTEGER NOT NULL DEFAULT 0);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, device TEXT NOT NULL, outcome TEXT NOT NULL, created INTEGER NOT NULL);
          CREATE TRIGGER IF NOT EXISTS audit_retention AFTER INSERT ON audit_log BEGIN
            DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 10000);
          END;")?;
        crate::acknowledgement::initialize(&conn)?;
        crate::mail_replay::initialize(&conn)?;
        crate::retention::initialize(&conn)?;
        crate::snmp::persistence::initialize(&conn)?;
        if version == 1 {
            let records = {
                let mut q = conn.prepare("SELECT id,config FROM devices")?;
                let rows = q
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                rows
            };
            for (id, raw) in records {
                let d: Device = serde_json::from_str(&raw)?;
                d.validate()?;
                anyhow::ensure!(
                    d.id == id
                        && d.primary_protocol == PrimaryProtocol::Redfish
                        && d.snmp_poll.is_none()
                        && d.snmp_traps.is_none(),
                    "invalid legacy device"
                );
                conn.execute(
                    "UPDATE devices SET config=?2 WHERE id=?1",
                    params![id, serde_json::to_string(&d)?],
                )?;
            }
            conn.execute("UPDATE schema_version SET version=2", [])?;
        }
        crate::log_query::reconcile_all_disabled(&conn)?;
        conn.commit()?;
        database.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Self(database))
    }

    pub fn put(&mut self, d: &Device, secret: &[u8]) -> Result<()> {
        let revision = self.get(&d.id)?.map(|(_, _, revision)| revision);
        self.save_admin(d, secret, revision, "local-cli")
    }

    pub fn devices(&self) -> Result<Vec<(Device, Vec<u8>)>> {
        let mut q = self
            .0
            .prepare("SELECT config,secret FROM devices ORDER BY id")?;
        let rows = q.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|r| {
            let (c, s) = r?;
            Ok((serde_json::from_str(&c)?, s))
        })
        .collect()
    }

    pub fn versioned_devices(&self) -> Result<Vec<(Device, Vec<u8>, i64)>> {
        let mut q = self
            .0
            .prepare("SELECT config,secret,revision FROM devices ORDER BY id")?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        rows.map(|r| {
            let (config, secret, revision) = r?;
            Ok((serde_json::from_str(&config)?, secret, revision))
        })
        .collect()
    }

    /// One SQLite read snapshot binds credentials to the target/revision that
    /// selected them, including writes from another CLI process.
    pub fn poll_targets(&self) -> Result<Vec<PollTarget>> {
        let mut q=self.0.prepare("SELECT d.config,CASE WHEN json_extract(d.config,'$.primary_protocol')='snmp' THEN COALESCE(p.secret,X'') ELSE d.secret END,d.revision,r.epoch FROM devices d CROSS JOIN snmp_runtime r LEFT JOIN protocol_secrets p ON p.device=d.id AND p.purpose='snmp_poll' WHERE r.id=1 ORDER BY d.id")?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (config, secret, revision, epoch) = row?;
            Ok((serde_json::from_str(&config)?, secret, revision, epoch))
        })
        .collect()
    }

    pub fn get(&self, id: &str) -> Result<Option<(Device, Vec<u8>, i64)>> {
        let raw: Option<(String, Vec<u8>, i64)> = self
            .0
            .query_row(
                "SELECT config,secret,revision FROM devices WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        raw.map(|(config, secret, revision)| Ok((serde_json::from_str(&config)?, secret, revision)))
            .transpose()
    }

    pub fn save_admin(
        &mut self,
        d: &Device,
        secret: &[u8],
        revision: Option<i64>,
        actor: &str,
    ) -> Result<()> {
        self.save_admin_with_snmp(d, secret, revision, actor, None)
    }

    pub fn save_admin_with_snmp(
        &mut self,
        d: &Device,
        secret: &[u8],
        revision: Option<i64>,
        actor: &str,
        credentials: Option<&[crate::snmp::persistence::SealedUpdate]>,
    ) -> Result<()> {
        d.validate()?;
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<(String, i64)> = tx
            .query_row(
                "SELECT config,revision FROM devices WHERE id=?1",
                [&d.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        anyhow::ensure!(
            existing.as_ref().map(|x| x.1) == revision,
            crate::dsm::BoundaryError("device_conflict")
        );
        let old_device = existing
            .as_ref()
            .map(|x| serde_json::from_str::<Device>(&x.0))
            .transpose()?;
        let changed_target = old_device
            .as_ref()
            .is_some_and(|old| old.primary_target_changed(d));
        use crate::snmp::{persistence, secrets::Purpose};
        anyhow::ensure!(
            revision.is_none_or(|r| (0..i64::MAX / 4).contains(&r)),
            "invalid device revision"
        );
        anyhow::ensure!(
            d.primary_protocol != PrimaryProtocol::Snmp || secret.is_empty(),
            "SNMP device must not carry a Redfish password"
        );
        if let Some(updates) = credentials {
            anyhow::ensure!(
                updates.len() == 2
                    && updates[0].0 == Purpose::SnmpPoll
                    && updates[1].0 == Purpose::SnmpTraps,
                "invalid credential update set"
            );
        }
        for purpose in [Purpose::SnmpPoll, Purpose::SnmpTraps] {
            let existing_secret: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT secret FROM protocol_secrets WHERE device=?1 AND purpose=?2",
                    params![d.id, purpose.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let cipher = match credentials {
                Some(updates) => updates.iter().find(|u| u.0 == purpose).unwrap().1.as_ref(),
                None => {
                    anyhow::ensure!(
                        existing_secret.is_none()
                            || old_device
                                .as_ref()
                                .is_some_and(|old| persistence::scope_equal(old, d, purpose)),
                        "explicit SNMP credential update required"
                    );
                    existing_secret.as_ref()
                }
            };
            anyhow::ensure!(
                cipher.is_none_or(|c| c.len() >= 28
                    && c.len() <= 8192
                    && persistence::security(d, purpose).is_some()),
                "invalid protocol credential envelope"
            );
            let required = d.enabled
                && match purpose {
                    Purpose::SnmpPoll => d.primary_protocol == PrimaryProtocol::Snmp,
                    Purpose::SnmpTraps => d.snmp_traps.as_ref().is_some_and(|c| c.enabled),
                };
            anyhow::ensure!(!required || cipher.is_some(), "SNMP credentials required");
        }
        if revision.is_some() {
            tx.execute(
                "UPDATE devices SET config=?2,secret=?3,revision=revision+1 WHERE id=?1",
                params![d.id, serde_json::to_string(d)?, secret],
            )?;
        } else {
            tx.execute(
                "INSERT INTO devices(id,config,secret,revision) VALUES(?1,?2,?3,1)",
                params![d.id, serde_json::to_string(d)?, secret],
            )?;
        }
        let changed_log_policy = existing
            .as_ref()
            .map(|x| serde_json::from_str::<Device>(&x.0))
            .transpose()?
            .is_some_and(|old| old.hardware_log != d.hardware_log);
        if changed_log_policy {
            tx.execute("UPDATE devices SET logs_initialized=0 WHERE id=?1", [&d.id])?;
        }
        if let Some(updates) = credentials {
            for (purpose, cipher) in updates {
                if let Some(cipher) = cipher {
                    tx.execute("INSERT INTO protocol_secrets(device,purpose,secret,revision) VALUES(?1,?2,?3,?4) ON CONFLICT(device,purpose) DO UPDATE SET secret=excluded.secret,revision=excluded.revision", params![d.id,purpose.as_str(),cipher,revision.unwrap_or(0)+1])?;
                } else {
                    tx.execute(
                        "DELETE FROM protocol_secrets WHERE device=?1 AND purpose=?2",
                        params![d.id, purpose.as_str()],
                    )?;
                }
            }
        }
        persistence::invalidate(&tx)?;
        if changed_target {
            tx.execute("DELETE FROM component_identity WHERE device=?1", [&d.id])?;
            tx.execute("DELETE FROM observation_evidence WHERE device=?1", [&d.id])?;
            tx.execute(
                "UPDATE devices SET last_poll=NULL,snapshot=NULL,logs_initialized=0 WHERE id=?1",
                [&d.id],
            )?;
            tx.execute("DELETE FROM alarm_state WHERE device=?1", [&d.id])?;
            tx.execute("DELETE FROM hardware_logs WHERE device=?1", [&d.id])?;
            tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1)",[&d.id])?;
            tx.execute("UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1)",[&d.id])?;
        }
        if !d.alerts_enabled || !d.enabled {
            tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1)",[&d.id])?;
            tx.execute("UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1)",[&d.id])?;
        }
        crate::log_query::disabled(&tx, d)?;
        tx.execute(
            "INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,?2,?3,'ok',?4)",
            params![
                actor,
                if revision.is_some() {
                    "device.update"
                } else {
                    "device.create"
                },
                d.id,
                crate::now()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_admin(&mut self, id: &str, revision: i64, actor: &str) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<i64> = tx
            .query_row("SELECT revision FROM devices WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        anyhow::ensure!(
            current == Some(revision),
            crate::dsm::BoundaryError("device_conflict")
        );
        tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1)",[id])?;
        tx.execute("UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1)",[id])?;
        tx.execute("DELETE FROM alarm_state WHERE device=?1", [id])?;
        tx.execute("DELETE FROM hardware_logs WHERE device=?1", [id])?;
        crate::snmp::persistence::invalidate(&tx)?;
        tx.execute("DELETE FROM devices WHERE id=?1", [id])?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'device.delete',?2,'ok',?3)",params![actor,id,crate::now()])?;
        tx.commit()?;
        Ok(())
    }

    pub fn audit(&self, actor: &str, action: &str, device: &str, outcome: &str) -> Result<()> {
        self.0.execute(
            "INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,?2,?3,?4,?5)",
            params![actor, action, device, outcome, crate::now()],
        )?;
        Ok(())
    }

    pub fn reserve_desktop_test(&self, actor: &str, now: i64) -> Result<i64> {
        let last: Option<i64> = self.0.query_row("SELECT MAX(created) FROM audit_log WHERE actor=?1 AND action='notification.desktop_test'", [actor], |r|r.get(0))?;
        anyhow::ensure!(
            last.is_none_or(|previous| now - previous >= 30),
            crate::dsm::BoundaryError("desktop_test_rate_limited")
        );
        self.audit(actor, "notification.desktop_test", "self", "started")?;
        Ok(self.0.last_insert_rowid())
    }
    pub fn finish_desktop_test(&self, id: i64, outcome: &str) -> Result<()> {
        self.0.execute(
            "UPDATE audit_log SET outcome=?2 WHERE id=?1 AND action='notification.desktop_test'",
            params![id, outcome],
        )?;
        Ok(())
    }
    pub fn audit_entries(&self) -> Result<Value> {
        let mut q = self.0.prepare(
            "SELECT actor,action,device,outcome,created FROM audit_log ORDER BY id DESC LIMIT 50",
        )?;
        let rows=q.query_map([],|r|Ok(json!({"actor":r.get::<_,String>(0)?,"action":r.get::<_,String>(1)?,"device":r.get::<_,String>(2)?,"outcome":r.get::<_,String>(3)?,"created":r.get::<_,i64>(4)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!(rows))
    }

    pub fn apply(&mut self, d: &Device, snapshot: &Snapshot, now: i64) -> Result<()> {
        self.apply_revision(d, snapshot, now, None).map(|_| ())
    }

    pub fn apply_revision(
        &mut self,
        d: &Device,
        snapshot: &Snapshot,
        now: i64,
        revision: Option<i64>,
    ) -> Result<bool> {
        self.apply_revision_epoch(d, snapshot, now, revision, None)
    }

    pub fn apply_revision_epoch(
        &mut self,
        d: &Device,
        snapshot: &Snapshot,
        now: i64,
        revision: Option<i64>,
        epoch: Option<i64>,
    ) -> Result<bool> {
        self.apply_poll(d, snapshot, now, revision, epoch, None)
    }

    pub fn apply_poll(
        &mut self,
        d: &Device,
        snapshot: &Snapshot,
        now: i64,
        revision: Option<i64>,
        epoch: Option<i64>,
        started_sequence: Option<i64>,
    ) -> Result<bool> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(expected) = epoch {
            if tx.query_row("SELECT epoch FROM snmp_runtime WHERE id=1", [], |r| {
                r.get::<_, i64>(0)
            })? != expected
            {
                return Ok(false);
            }
        }
        if let Some(expected) = revision {
            let current: Option<i64> = tx
                .query_row("SELECT revision FROM devices WHERE id=?1", [&d.id], |r| {
                    r.get(0)
                })
                .optional()?;
            if current != Some(expected) {
                return Ok(false);
            }
        }
        let (retention, _) = crate::retention::settings(&tx)?;
        crate::snmp::integration::persist_inventory(&tx, d, snapshot, revision.unwrap_or(0))?;
        let mut effective = snapshot.clone();
        crate::snmp::network::assess(&tx, d, &mut effective, revision.unwrap_or(0), now)?;
        crate::snmp::hpe::assess(&tx, d, &mut effective, revision.unwrap_or(0))?;
        crate::snmp::integration::guard_poll(
            &tx,
            d,
            &mut effective,
            revision.unwrap_or(0),
            started_sequence,
            now,
        )?;
        let snapshot = &effective;
        for (alias, canonical) in &snapshot.resource_aliases {
            if alias != canonical && snapshot.observations.iter().any(|o| &o.key == canonical) {
                merge_alarm_alias(&tx, &d.id, alias, canonical)?;
                tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT old.id FROM events old WHERE old.device=?1 AND old.key=?2 AND old.kind!='hardware_log' AND EXISTS(SELECT 1 FROM events peer WHERE peer.device=old.device AND peer.key=?3 AND peer.created=old.created AND peer.kind=old.kind AND peer.health=old.health AND peer.message=old.message))",params![d.id,alias,canonical])?;
                tx.execute("UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT old.id FROM events old WHERE old.device=?1 AND old.key=?2 AND old.kind!='hardware_log' AND EXISTS(SELECT 1 FROM events peer WHERE peer.device=old.device AND peer.key=?3 AND peer.created=old.created AND peer.kind=old.kind AND peer.health=old.health AND peer.message=old.message))",params![d.id,alias,canonical])?;
                tx.execute("UPDATE events SET canonical_key=?3 WHERE device=?1 AND key=?2 AND kind!='hardware_log'",params![d.id,alias,canonical])?;
            }
        }
        let boundary: i64 =
            tx.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |r| r.get(0))?;
        crate::log_query::fresh(&tx, d, snapshot)?;
        let groups = crate::alarm::reduce(&tx, d, snapshot, now)?;
        let new_events: Vec<i64> = {
            let mut q = tx.prepare("SELECT id FROM events WHERE device=?1 AND id>?2")?;
            let result = q
                .query_map(params![d.id, boundary], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            result
        };
        for id in new_events {
            crate::snmp::integration::annotate(
                &tx,
                id,
                if d.primary_protocol == PrimaryProtocol::Snmp {
                    "snmp_poll"
                } else {
                    "redfish"
                },
                snapshot.snmp.as_ref().is_none_or(|m| m.engine_id.is_some()),
                false,
                None,
                None,
            )?;
        }

        let mut snapshot = snapshot.clone();
        snapshot.notification_groups = groups;
        let initialized: bool = tx.query_row(
            "SELECT logs_initialized FROM devices WHERE id=?1",
            [&d.id],
            |r| r.get(0),
        )?;
        snapshot.logs.retain(|log| {
            d.hardware_log != HardwareLogRead::Disabled && retention.accepts(log, now)
        });
        for log in &snapshot.logs {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO hardware_logs VALUES(?1,?2,?3)",
                params![d.id, log.fingerprint, serde_json::to_string(log)?],
            )?;
            if inserted > 0
                && initialized
                && matches!(log.severity, Health::Warning | Health::Critical)
            {
                let event_id = event(
                    &tx,
                    d,
                    &format!("log:{}", log.fingerprint),
                    "hardware_log",
                    log.severity,
                    &log.message,
                    now,
                )?;
                crate::snmp::integration::annotate(
                    &tx,
                    event_id,
                    if d.primary_protocol == PrimaryProtocol::Snmp {
                        "snmp_poll"
                    } else {
                        "redfish"
                    },
                    snapshot.snmp.as_ref().is_none_or(|s| s.engine_id.is_some()),
                    false,
                    None,
                    log.identity.as_ref().and_then(|i| i.occurrence.as_ref()),
                )?;
                if let Some(identity) = &log.identity {
                    tx.execute("UPDATE events SET message_context=json_set(message_context,'$.log_identity',json(?2)) WHERE id=?1",params![event_id,serde_json::to_string(identity)?])?;
                }
                tx.execute(
                    "UPDATE events SET source_created=?2 WHERE id=?1",
                    params![
                        event_id,
                        log.created
                            .as_ref()
                            .map(|s| s.chars().take(128).collect::<String>())
                    ],
                )?;
            }
        }
        tx.execute("UPDATE devices SET last_poll=?2,snapshot=?3,logs_initialized=CASE WHEN ?4 THEN 1 ELSE logs_initialized END WHERE id=?1", params![d.id,now,serde_json::to_string(&snapshot)?,snapshot.logs_complete && d.hardware_log != HardwareLogRead::Disabled])?;
        tx.commit()?;
        Ok(true)
    }

    pub fn poll_error(&mut self, d: &Device, now: i64) -> Result<()> {
        self.poll_error_revision(d, now, None).map(|_| ())
    }
    pub fn poll_error_revision(
        &mut self,
        d: &Device,
        now: i64,
        revision: Option<i64>,
    ) -> Result<bool> {
        self.record_poll_error(
            d,
            now,
            revision,
            "Management-Abfrage fehlgeschlagen (Netzwerk, TLS, Anmeldung oder Zeitlimit)",
            None,
        )
    }

    pub fn poll_failure_revision(
        &mut self,
        d: &Device,
        now: i64,
        revision: Option<i64>,
        error: &anyhow::Error,
    ) -> Result<bool> {
        self.record_poll_error(
            d,
            now,
            revision,
            &crate::collector::poll_failure_label(error),
            None,
        )
    }

    pub fn poll_failure_epoch(
        &mut self,
        d: &Device,
        now: i64,
        revision: i64,
        epoch: i64,
        error: &anyhow::Error,
    ) -> Result<bool> {
        self.record_poll_error(
            d,
            now,
            Some(revision),
            &crate::collector::poll_failure_label(error),
            Some(epoch),
        )
    }

    fn record_poll_error(
        &mut self,
        d: &Device,
        now: i64,
        revision: Option<i64>,
        label: &str,
        epoch: Option<i64>,
    ) -> Result<bool> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(expected) = epoch {
            if tx.query_row("SELECT epoch FROM snmp_runtime WHERE id=1", [], |r| {
                r.get::<_, i64>(0)
            })? != expected
            {
                return Ok(false);
            }
        }
        if let Some(expected) = revision {
            let current: Option<i64> = tx
                .query_row("SELECT revision FROM devices WHERE id=?1", [&d.id], |r| {
                    r.get(0)
                })
                .optional()?;
            if current != Some(expected) {
                return Ok(false);
            }
        }
        apply_observation(
            &tx,
            d,
            &Observation {
                key: "collector".into(),
                label: label.into(),
                health: Health::Critical,
                reading: None,
                unit: None,
            },
            now,
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn dashboard(&self) -> Result<Value> {
        let mut devices = Vec::new();
        for (d, _, revision) in self.versioned_devices()? {
            let (last_poll, raw): (Option<i64>, Option<String>) = self.0.query_row(
                "SELECT last_poll,snapshot FROM devices WHERE id=?1",
                [&d.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut q = self.0.prepare("SELECT key,health,label,observed FROM alarm_state WHERE device=?1 AND health != '\"ok\"'")?;
            let mut alarms = q.query_map([&d.id], |r| Ok(json!({"key":r.get::<_,String>(0)?,"health":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"label":r.get::<_,String>(2)?,"observed":r.get::<_,i64>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let parsed: Option<Snapshot> =
                raw.as_ref().map(|s| serde_json::from_str(s)).transpose()?;
            let evaluation = crate::acknowledgement::evaluate(&self.0, &d.id, parsed.as_ref())?;
            let mut trap_health: Option<Health> = None;
            for alarm in &mut alarms {
                let key = alarm["key"].as_str().unwrap().to_owned();
                let covered = parsed
                    .as_ref()
                    .and_then(|s| s.notification_groups.get(&key))
                    .map(|keys| {
                        keys.iter()
                            .filter(|key| evaluation.statuses.contains_key(*key))
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let current = parsed
                    .as_ref()
                    .and_then(|s| s.observations.iter().find(|o| o.key == key))
                    .map(|o| o.health)
                    .unwrap_or(Health::Unknown);
                alarm["covered_by"] = json!(covered);
                alarm["current_health"] = json!(current);
                if let Some(status) = evaluation.statuses.get(&key) {
                    alarm["assessment"] = json!(status);
                }
                if let Some(e) = crate::snmp::integration::alarm_evidence(&self.0, &d.id, &key)? {
                    if d.enabled
                        && e.active
                        && e.revision == revision
                        && !e.conditions.is_empty()
                        && evaluation
                            .statuses
                            .get(&key)
                            .is_some_and(|s| matches!(s.status.as_str(), "critical" | "warning"))
                        && trap_health.is_none_or(|h| {
                            crate::identity::severity(e.health) > crate::identity::severity(h)
                        })
                    {
                        trap_health = Some(e.health);
                    }
                    alarm["evidence"] = json!(e);
                }
            }
            let stale = !d.enabled
                || last_poll.is_none_or(|p| crate::now() - p > d.stale_after_seconds() as i64);
            let mut overall_status = evaluation.overall(parsed.as_ref(), stale);
            if trap_health == Some(Health::Critical) {
                overall_status = "critical";
            } else if trap_health == Some(Health::Warning) && overall_status != "critical" {
                overall_status = "warning";
            }
            let last_trap_received: Option<i64> = self.0.query_row(
                "SELECT MAX(received) FROM snmp_receipts WHERE device=?1",
                [&d.id],
                |r| r.get(0),
            )?;

            let acknowledged_count = evaluation
                .statuses
                .values()
                .filter(|s| s.acknowledged)
                .count();
            let has_snmp_poll_secret = self
                .protocol_secret(&d.id, crate::snmp::secrets::Purpose::SnmpPoll)?
                .is_some();
            let has_snmp_traps_secret = self
                .protocol_secret(&d.id, crate::snmp::secrets::Purpose::SnmpTraps)?
                .is_some();
            devices.push(json!({"trap_health":trap_health,"last_trap_received":last_trap_received,"has_snmp_poll_secret":has_snmp_poll_secret,"has_snmp_traps_secret":has_snmp_traps_secret,"device":d,"revision":revision,"last_poll":last_poll,"poll_timeout_seconds":d.poll_timeout_seconds(),"stale":stale,"snapshot":parsed,"alarms":alarms,"overall_status":overall_status,"alarm_statuses":evaluation.statuses,"acknowledged_count":acknowledged_count}));
        }
        let events = self.event_entries(100)?;
        // The dashboard window is bounded; the retained-history count is not.
        let event_count: i64 = self
            .0
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(
            json!({"version":env!("CARGO_PKG_VERSION"),"generated":crate::now(),"devices":devices,"events":events,"event_count":event_count}),
        )
    }

    pub fn event_entries(&self, limit: i64) -> Result<Vec<Value>> {
        let mut q = self.0.prepare("SELECT e.id,e.device,e.kind,e.health,e.message,e.created,o.delivered,o.attempts,e.key,COALESCE(json_extract(d.config,'$.name'),e.device_name,'Entferntes Gerät'),e.source_created,COALESCE(o.cancelled,0),o.id IS NOT NULL,COALESCE(e.canonical_key,e.key),o.transport,(SELECT error FROM mail_recipient WHERE outbox_id=o.id AND error IS NOT NULL ORDER BY attempts DESC LIMIT 1),(SELECT COUNT(*) FROM mail_recipient WHERE outbox_id=o.id AND delivered IS NOT NULL),(SELECT COUNT(*) FROM mail_recipient WHERE outbox_id=o.id),(SELECT COUNT(*) FROM mail_recipient WHERE outbox_id=o.id AND (permanent=1 OR attempts>=8)),e.message_context,(d.id IS NULL AND e.device_name IS NULL) FROM events e LEFT JOIN outbox o ON o.event_id=e.id LEFT JOIN devices d ON d.id=e.device ORDER BY e.id DESC LIMIT ?1")?;
        let mut events = q.query_map([limit],|r| Ok(json!({"id":r.get::<_,i64>(0)?,"device":r.get::<_,String>(1)?,"kind":r.get::<_,String>(2)?,"health":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null),"message":r.get::<_,String>(4)?,"created":r.get::<_,i64>(5)?,"delivered":r.get::<_,Option<i64>>(6)?,"attempts":r.get::<_,Option<i64>>(7)?,"key":r.get::<_,String>(8)?,"device_name":r.get::<_,String>(9)?,"source_created":r.get::<_,Option<String>>(10)?,"cancelled":r.get::<_,bool>(11)?,"queued":r.get::<_,bool>(12)?,"canonical_key":r.get::<_,String>(13)?,"transport":r.get::<_,Option<String>>(14)?,"delivery_error":r.get::<_,Option<String>>(15)?,"submitted_recipients":r.get::<_,i64>(16)?,"total_recipients":r.get::<_,i64>(17)?,"failed_recipients":r.get::<_,i64>(18)?,"message_context":r.get::<_,Option<String>>(19)?.and_then(|s|serde_json::from_str::<Value>(&s).ok()),"device_name_missing":r.get::<_,bool>(20)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for e in &mut events {
            let id = e["id"].as_i64().unwrap();
            let (mail_reason, desktop_reason): (Option<String>, Option<String>) =
                self.0.query_row(
                    "SELECT mail_reason,desktop_reason FROM events WHERE id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
            let related: Option<String> = self.0.query_row(
                "SELECT correlated_keys FROM events WHERE id=?1",
                [id],
                |r| r.get(0),
            )?;
            e["correlated_keys"] = related
                .map(|s| serde_json::from_str::<Vec<String>>(&s))
                .transpose()?
                .map_or_else(|| json!([]), |keys| json!(keys));
            e["mail_reason"] = json!(mail_reason);
            e["desktop_reason"] = json!(desktop_reason);
            e["desktop"]=self.0.query_row("SELECT delivered,attempts,error,cancelled,recipient FROM desktop_jobs WHERE event_id=?1",[id],|r|Ok(json!({"delivered":r.get::<_,Option<i64>>(0)?,"attempts":r.get::<_,i64>(1)?,"error":r.get::<_,Option<String>>(2)?,"cancelled":r.get::<_,bool>(3)?,"recipient":r.get::<_,String>(4)?}))).optional()?.unwrap_or(Value::Null);
        }
        Ok(events)
    }

    pub fn notification_settings(&self) -> Result<(crate::notification::Settings, i64)> {
        let row: Option<(String, i64)> = self
            .0
            .query_row(
                "SELECT config,revision FROM notification_settings WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(raw, rev)| Ok((serde_json::from_str(&raw)?, rev)))
            .unwrap_or_else(|| Ok((crate::notification::Settings::default(), 0)))
    }
    pub fn save_notifications(
        &mut self,
        input: &crate::notification::Input,
        actor: &str,
    ) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: i64 = tx
            .query_row(
                "SELECT revision FROM notification_settings WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        anyhow::ensure!(
            input.revision == current,
            crate::dsm::BoundaryError("notification_conflict")
        );
        let settings = crate::notification::Settings {
            language: input.language,
            desktop_enabled: input.desktop_enabled,
            desktop_recipient: input.desktop_enabled.then(|| actor.to_owned()),
            selection: input.selection.clone(),
        };
        tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL", [])?;
        tx.execute(
            "UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL",
            [],
        )?;
        tx.execute("INSERT INTO notification_settings VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET config=excluded.config,revision=excluded.revision",params![serde_json::to_string(&settings)?,current+1])?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'notification.settings','notifications','ok',?2)",params![actor,crate::now()])?;
        tx.commit()?;
        Ok(())
    }
    pub fn pending_desktop(&self, now: i64) -> Result<Option<crate::notification::DesktopJob>> {
        let (settings, revision) = self.notification_settings()?;
        if !settings.desktop_enabled {
            return Ok(None);
        }
        Ok(self.0.query_row("SELECT j.event_id,j.recipient,e.kind,e.health,COALESCE(e.device_name,e.device),e.message,e.key,e.message_context FROM desktop_jobs j JOIN events e ON e.id=j.event_id WHERE j.cancelled=0 AND j.delivered IS NULL AND j.attempts<8 AND j.next_try<=?1 AND j.revision=?2 ORDER BY j.next_try,j.event_id LIMIT 1",params![now,revision],|r|Ok(crate::notification::DesktopJob{event_id:r.get(0)?,recipient:r.get(1)?,kind:r.get(2)?,health:serde_json::from_str::<String>(&r.get::<_,String>(3)?).unwrap_or_else(|_|"unknown".into()),device:r.get(4)?,message:crate::i18n::event_message(&r.get::<_,String>(4)?,&r.get::<_,String>(6)?,&r.get::<_,String>(2)?,&serde_json::from_str::<String>(&r.get::<_,String>(3)?).unwrap_or_default(),&r.get::<_,String>(5)?,r.get::<_,Option<String>>(7)?.and_then(|s|serde_json::from_str::<Value>(&s).ok()).as_ref(),settings.language),language:settings.language})).optional()?)
    }
    pub fn finish_desktop(
        &self,
        job: &crate::notification::DesktopJob,
        error: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.0.execute("UPDATE desktop_jobs SET attempts=attempts+1,delivered=CASE WHEN ?2 IS NULL THEN ?3 ELSE NULL END,error=?2,next_try=?3+MIN(3600,30*(1 << MIN(attempts,7))) WHERE event_id=?1",params![job.event_id,error,now])?;
        Ok(())
    }

    pub fn mail_settings(&self) -> Result<Option<(crate::mail::Settings, Vec<u8>, i64)>> {
        let row: Option<(String, Vec<u8>, i64)> = self
            .0
            .query_row(
                "SELECT config,secret,revision FROM mail_settings WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(raw, secret, revision)| Ok((serde_json::from_str(&raw)?, secret, revision)))
            .transpose()
    }
    pub fn mail_enabled(&self) -> bool {
        self.mail_settings()
            .ok()
            .flatten()
            .is_some_and(|(s, _, _)| s.enabled)
    }
    pub fn save_mail(
        &mut self,
        settings: &crate::mail::Settings,
        secret: &[u8],
        expected: i64,
        actor: &str,
    ) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: i64 = tx
            .query_row("SELECT revision FROM mail_settings WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(0);
        anyhow::ensure!(
            current == expected,
            crate::dsm::BoundaryError("mail_conflict")
        );
        // Explicitly discard old pending work on ANY change; never mail old local-only history.
        tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL", [])?;
        crate::mail_replay::cancel(&tx, crate::now())?;
        tx.execute("INSERT INTO mail_settings(id,config,secret,revision) VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET config=excluded.config,secret=excluded.secret,revision=excluded.revision",params![serde_json::to_string(settings)?,secret,current+1])?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'mail.settings','mail','ok',?2)",params![actor,crate::now()])?;
        tx.commit()?;
        Ok(())
    }
    pub fn reserve_mail_test(&self, actor: &str, now: i64) -> Result<i64> {
        let last: Option<i64> = self.0.query_row(
            "SELECT MAX(created) FROM audit_log WHERE actor=?1 AND action='mail.test'",
            [actor],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            last.is_none_or(|t| now - t >= 60),
            crate::dsm::BoundaryError("mail_test_rate_limited")
        );
        self.audit(actor, "mail.test", "mail", "started")?;
        Ok(self.0.last_insert_rowid())
    }
    pub fn finish_mail_test(&self, id: i64, outcome: &str) -> Result<()> {
        self.0.execute(
            "UPDATE audit_log SET outcome=?2 WHERE id=?1 AND action='mail.test'",
            params![id, outcome],
        )?;
        Ok(())
    }
    pub fn pending_mail(&self, now: i64) -> Result<Option<MailJob>> {
        let Some((settings, secret, revision)) = self.mail_settings()? else {
            return Ok(None);
        };
        if !settings.enabled {
            return Ok(None);
        }
        Ok(self.0.query_row("SELECT p.outbox_id,p.recipient,p.message_id,e.id,COALESCE(e.device_name,e.device),e.health,e.kind,e.message,e.created,e.key,e.message_context FROM mail_recipient p JOIN outbox o ON o.id=p.outbox_id JOIN events e ON e.id=o.event_id WHERE o.cancelled=0 AND o.transport='smtp' AND p.revision=?1 AND p.delivered IS NULL AND p.permanent=0 AND p.attempts<8 AND p.next_try<=?2 ORDER BY p.next_try,p.outbox_id,p.recipient LIMIT 1",params![revision,now],|r|Ok(MailJob{outbox:r.get(0)?,recipient:r.get(1)?,message_id:r.get(2)?,settings:settings.clone(),secret:secret.clone(),event:crate::mail::Event{id:r.get(3)?,device:r.get(4)?,health:serde_json::from_str::<String>(&r.get::<_,String>(5)?).unwrap_or_else(|_|"unknown".into()),kind:r.get(6)?,message:r.get(7)?,time:r.get(8)?,resource:r.get(9)?,context:r.get::<_,Option<String>>(10)?.and_then(|s|serde_json::from_str(&s).ok())}})).optional()?)
    }
    pub fn finish_mail(&mut self, job: &MailJob, error: Option<&str>, now: i64) -> Result<()> {
        let tx = self.0.transaction()?;
        tx.execute("UPDATE mail_recipient SET attempts=attempts+1,delivered=CASE WHEN ?3 IS NULL THEN ?4 ELSE NULL END,next_try=?4+MIN(3600,30*(1 << MIN(attempts,7))),error=?3,permanent=CASE WHEN ?3 IN ('mail_rejected','mail_config_invalid','mail_template_invalid') THEN 1 ELSE 0 END WHERE outbox_id=?1 AND recipient=?2",params![job.outbox,job.recipient,error,now])?;
        tx.execute("UPDATE outbox SET attempts=attempts+1,delivered=CASE WHEN NOT EXISTS(SELECT 1 FROM mail_recipient WHERE outbox_id=?1 AND delivered IS NULL) THEN ?2 ELSE NULL END WHERE id=?1",params![job.outbox,now])?;
        tx.commit()?;
        Ok(())
    }

    pub fn pending(&self, now: i64) -> Result<Vec<(i64, String, String, String)>> {
        let mut q = self.0.prepare("SELECT o.id,e.kind,e.health,e.message FROM outbox o JOIN events e ON e.id=o.event_id WHERE o.delivered IS NULL AND o.cancelled=0 AND o.transport IS NULL AND o.next_try<=?1 ORDER BY o.id LIMIT 20")?;
        let rows = q
            .query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn delivery(&self, id: i64, success: bool, now: i64) -> Result<()> {
        self.0.execute("UPDATE outbox SET attempts=attempts+1,delivered=CASE WHEN ?2 THEN ?3 ELSE NULL END,next_try=?3+MIN(3600,30*(1 << MIN(attempts,7))) WHERE id=?1",params![id,success,now])?;
        Ok(())
    }
}

pub(crate) fn group_notifications(
    tx: &Transaction<'_>,
    device: &str,
    parent: &str,
    anchors: &[String],
    boundary: i64,
) -> Result<()> {
    // Apply before transaction commit: neither worker can submit these new jobs.
    tx.execute("UPDATE events SET correlated_keys=?3 WHERE device=?1 AND key=?2 AND (id>?4 OR id IN (SELECT event_id FROM outbox WHERE delivered IS NULL AND cancelled=0) OR id IN (SELECT event_id FROM desktop_jobs WHERE delivered IS NULL AND cancelled=0))",params![device,parent,serde_json::to_string(anchors)?,boundary])?;
    tx.execute("UPDATE events SET mail_reason='aggregate' WHERE device=?1 AND key=?2 AND (id>?3 OR id IN (SELECT event_id FROM outbox WHERE delivered IS NULL AND cancelled=0))",params![device,parent,boundary])?;
    tx.execute("UPDATE events SET desktop_reason='aggregate' WHERE device=?1 AND key=?2 AND (id>?3 OR id IN (SELECT event_id FROM desktop_jobs WHERE delivered IS NULL AND cancelled=0))",params![device,parent,boundary])?;
    tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1 AND key=?2)",params![device,parent])?;
    tx.execute("UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1 AND key=?2)",params![device,parent])?;
    Ok(())
}

pub(crate) fn event(
    tx: &Transaction<'_>,
    d: &Device,
    key: &str,
    kind: &str,
    health: Health,
    message: &str,
    now: i64,
) -> Result<i64> {
    let message_source = message;
    let detail = if kind == "snmp_trap" {
        format!("SNMP-Ereignis: {message}")
    } else if kind == "hardware_log" {
        message.to_owned()
    } else if key.starts_with("coverage:") {
        format!(
            "{}: {message}",
            if kind == "recovery" {
                "Redfish-Abfrage wieder erfolgreich"
            } else {
                "Redfish-Abfrage eingeschränkt"
            }
        )
    } else if key == "collector" {
        format!(
            "{}: {message}",
            if kind == "recovery" {
                "Geräteabfrage wieder erfolgreich"
            } else {
                "Geräteabfrage fehlgeschlagen"
            }
        )
    } else {
        let state = match health {
            Health::Critical => "kritisch",
            Health::Warning => "Warnung",
            Health::Ok => "in Ordnung",
            Health::Unknown => "unbekannt",
        };
        let phase = if kind == "recovery" {
            "wieder "
        } else if kind == "repeat" {
            "weiterhin "
        } else {
            ""
        };
        format!("Hardwarezustand {phase}{state}: {message}")
    };
    let message = format!(
        "{}: {}",
        d.name,
        detail.chars().take(1200).collect::<String>()
    );
    tx.execute(
        "INSERT INTO events(id,device,key,kind,health,message,created,device_name) SELECT MAX(COALESCE(MAX(id),0),COALESCE((SELECT value FROM counters WHERE name='events'),0))+1,?1,?2,?3,?4,?5,?6,?7 FROM events",
        params![
            d.id,
            key,
            kind,
            serde_json::to_string(&health)?,
            message,
            now,
            d.name
        ],
    )?;
    let event_id = tx.last_insert_rowid();
    // Retention may remove every event; identifiers must still never be reused.
    tx.execute("INSERT INTO counters(name,value) VALUES('events',?1) ON CONFLICT(name) DO UPDATE SET value=MAX(value,excluded.value)",[event_id])?;
    tx.execute(
        "UPDATE events SET message_context=?2 WHERE id=?1",
        params![
            event_id,
            serde_json::to_string(&json!({"version":1,"label":message_source,"retained":false}))?
        ],
    )?;
    let policy: Option<(String, i64)> = tx
        .query_row(
            "SELECT config,revision FROM notification_settings WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (policy, policy_revision) = policy
        .map(|(raw, rev)| {
            Ok::<_, anyhow::Error>((
                serde_json::from_str::<crate::notification::Settings>(&raw)?,
                rev,
            ))
        })
        .transpose()?
        .unwrap_or_default();
    let selected = policy.selection.accepts(key, kind, health);
    let acknowledged: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM alarm_control WHERE device=?1 AND key=?2 AND acknowledged=1)",
        params![d.id, key],
        |r| r.get(0),
    )?;
    let gate = if acknowledged && !matches!(kind, "hardware_log" | "snmp_trap") {
        Some("acknowledged")
    } else if !d.alerts_enabled {
        Some("device_disabled")
    } else if !d.enabled {
        Some("monitoring_disabled")
    } else if !selected {
        Some("filtered")
    } else {
        None
    };
    let mail: Option<(String, i64)> = tx
        .query_row(
            "SELECT config,revision FROM mail_settings WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let mut mail_reason = gate.unwrap_or("mail_not_configured");
    if gate.is_none() {
        // Preserve the local-only legacy outbox contract. SMTP consumes only transport=smtp.
        tx.execute("INSERT INTO outbox(event_id) VALUES(?1)", [event_id])?;
        let outbox = tx.last_insert_rowid();
        if let Some((raw, revision)) = mail {
            let settings: crate::mail::Settings = serde_json::from_str(&raw)?;
            mail_reason = if settings.enabled {
                "queued"
            } else {
                "mail_disabled"
            };
            if settings.enabled {
                tx.execute("UPDATE outbox SET transport='smtp' WHERE id=?1", [outbox])?;
                for recipient in settings.recipients {
                    let id = format!(
                        "<hm-{:032x}@hardwaremonitor.invalid>",
                        rand::random::<u128>()
                    );
                    tx.execute("INSERT INTO mail_recipient(outbox_id,recipient,message_id,revision) VALUES(?1,?2,?3,?4)",params![outbox,recipient,id,revision])?;
                }
            }
        }
    }
    let mut desktop_reason = gate.unwrap_or("desktop_disabled");
    if gate.is_none() && policy.desktop_enabled {
        if let Some(recipient) = policy.desktop_recipient {
            tx.execute(
                "INSERT INTO desktop_jobs(event_id,recipient,revision) VALUES(?1,?2,?3)",
                params![event_id, recipient, policy_revision],
            )?;
            desktop_reason = "queued";
        }
    }
    tx.execute(
        "UPDATE events SET mail_reason=?2,desktop_reason=?3 WHERE id=?1",
        params![event_id, mail_reason, desktop_reason],
    )?;
    Ok(event_id)
}

fn merge_alarm_alias(
    tx: &Transaction<'_>,
    device: &str,
    alias: &str,
    canonical: &str,
) -> Result<()> {
    type State = (String, String, i64, Option<i64>);
    let get = |key: &str| -> Result<Option<State>> {
        Ok(tx
            .query_row(
                "SELECT health,label,observed,emitted FROM alarm_state WHERE device=?1 AND key=?2",
                params![device, key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?)
    };
    let Some(old) = get(alias)? else {
        return Ok(());
    };
    let existing = get(canonical)?;
    let mut merged = old.clone();
    if let Some(current) = existing {
        let old_health: Health = serde_json::from_str(&old.0)?;
        let current_health: Health = serde_json::from_str(&current.0)?;
        merged.0 =
            if crate::identity::severity(old_health) > crate::identity::severity(current_health) {
                old.0
            } else {
                current.0
            };
        merged.1 = current.1;
        merged.2 = old.2.max(current.2);
        merged.3 = old.3.into_iter().chain(current.3).max();
    }
    tx.execute("INSERT INTO alarm_state(device,key,health,label,observed,emitted) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(device,key) DO UPDATE SET health=excluded.health,label=excluded.label,observed=excluded.observed,emitted=excluded.emitted",params![device,canonical,merged.0,merged.1,merged.2,merged.3])?;
    tx.execute("INSERT OR IGNORE INTO alarm_control(device,key,token,acknowledged,actor,acknowledged_at,reason,signature,reannounce) SELECT device,?3,token,acknowledged,actor,acknowledged_at,reason,signature,reannounce FROM alarm_control WHERE device=?1 AND key=?2",params![device,alias,canonical])?;
    tx.execute("UPDATE alarm_control SET token=lower(hex(randomblob(16))),acknowledged=0,actor=NULL,acknowledged_at=NULL,reason=NULL WHERE device=?1 AND key=?3 AND EXISTS(SELECT 1 FROM alarm_control c JOIN alarm_state a ON a.device=c.device AND a.key=c.key WHERE c.device=?1 AND c.key=?2 AND c.acknowledged=0 AND a.health!='\"ok\"')",params![device,alias,canonical])?;
    tx.execute(
        "DELETE FROM alarm_state WHERE device=?1 AND key=?2",
        params![device, alias],
    )?;
    Ok(())
}

pub(crate) fn apply_observation(
    tx: &Transaction<'_>,
    d: &Device,
    o: &Observation,
    now: i64,
) -> Result<()> {
    // Unknown or missing values never resolve a known fault and never trigger reminders.
    if o.health == Health::Unknown {
        return Ok(());
    }
    let previous: Option<(String, Option<i64>)> = tx
        .query_row(
            "SELECT health,emitted FROM alarm_state WHERE device=?1 AND key=?2",
            params![d.id, o.key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let before = previous
        .as_ref()
        .map(|p| serde_json::from_str::<Health>(&p.0))
        .transpose()?;
    let last = previous.as_ref().and_then(|p| p.1);
    let changed = before != Some(o.health);
    let repeating = !changed
        && o.health != Health::Ok
        && d.repeat_seconds
            .zip(last)
            .is_some_and(|(interval, t)| now - t >= interval);
    tx.execute("INSERT INTO alarm_state(device,key,health,label,observed,emitted) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(device,key) DO UPDATE SET health=excluded.health,label=excluded.label,observed=excluded.observed",params![d.id,o.key,serde_json::to_string(&o.health)?,o.label,now,last])?;
    let reannounce = crate::acknowledgement::transition(tx, d, o, before, now)?;
    let emit = (changed && (o.health != Health::Ok || before.is_some())) || repeating || reannounce;
    if emit {
        event(
            tx,
            d,
            &o.key,
            if o.health == Health::Ok {
                "recovery"
            } else if repeating {
                "repeat"
            } else {
                "alarm"
            },
            o.health,
            &o.label,
            now,
        )?;
    }
    tx.execute(
        "UPDATE alarm_state SET emitted=?3 WHERE device=?1 AND key=?2",
        params![d.id, o.key, if emit { Some(now) } else { last }],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dashboard_counts_all_retained_events_while_loading_only_the_latest_hundred() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        assert_eq!(store.dashboard().unwrap()["event_count"], 0);
        for id in 1..=200 {
            store.0.execute(
                "INSERT INTO events(device,key,kind,health,message,created) VALUES('synthetic','fan','alarm','\"warning\"','Synthetic event',?1)",
                [id],
            ).unwrap();
            if id == 150 || id == 200 {
                let view = store.dashboard().unwrap();
                assert_eq!(view["event_count"], id);
                assert_eq!(view["events"].as_array().unwrap().len(), 100);
                assert_eq!(view["events"][0]["id"], id);
                assert_eq!(view["events"][99]["id"], id - 99);
            }
        }
        assert_eq!(store.clear_events("synthetic").unwrap(), 200);
        let view = store.dashboard().unwrap();
        assert_eq!(view["event_count"], 0);
        assert!(view["events"].as_array().unwrap().is_empty());
    }
    fn device() -> Device {
        Device {
            hardware_log: Default::default(),
            primary_protocol: Default::default(),
            snmp_poll: None,
            snmp_traps: None,
            id: "test".into(),
            name: "Test".into(),
            endpoint: "https://ilo.example/".into(),
            username: "monitor".into(),
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
    fn snap(h: Health) -> Snapshot {
        Snapshot {
            observations: vec![Observation {
                key: "fan".into(),
                label: "Fan".into(),
                health: h,
                reading: None,
                unit: None,
            }],
            ..Default::default()
        }
    }
    #[test]
    fn older_idrac_scan_budget_is_reflected_in_freshness_and_dashboard() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let mut d = device();
        d.tls_profile = crate::model::TlsProfile::Idrac7;
        d.pinned_certificate_pem = Some(crate::legacy_tls::tests::pem());
        store.put(&d, b"synthetic-ciphertext").unwrap();
        store
            .apply(&d, &snap(Health::Ok), crate::now() - 180)
            .unwrap();
        let dashboard = store.dashboard().unwrap();
        assert_eq!(dashboard["devices"][0]["poll_timeout_seconds"], 300);
        assert_eq!(dashboard["devices"][0]["stale"], false);
        store
            .apply(&d, &snap(Health::Ok), crate::now() - 430)
            .unwrap();
        assert_eq!(store.dashboard().unwrap()["devices"][0]["stale"], true);
        d.tls_profile = crate::model::TlsProfile::Standard;
        d.pinned_certificate_pem = None;
        store.put(&d, b"synthetic-ciphertext").unwrap();
        store
            .apply(&d, &snap(Health::Ok), crate::now() - 180)
            .unwrap();
        let dashboard = store.dashboard().unwrap();
        assert_eq!(dashboard["devices"][0]["poll_timeout_seconds"], 90);
        assert_eq!(dashboard["devices"][0]["stale"], true);
    }
    #[test]
    fn additive_upgrade_keeps_legacy_configuration_and_secret() {
        let dir = tempfile::tempdir().unwrap();
        let d = device();
        let mut config = serde_json::to_value(&d).unwrap();
        config.as_object_mut().unwrap().remove("enabled");
        config.as_object_mut().unwrap().remove("ca_pem");
        config.as_object_mut().unwrap().remove("tls_profile");
        config
            .as_object_mut()
            .unwrap()
            .remove("pinned_certificate_pem");
        let old = Connection::open(dir.path().join("monitor.db")).unwrap();
        old.execute_batch("CREATE TABLE devices(id TEXT PRIMARY KEY,config TEXT NOT NULL,secret BLOB NOT NULL,last_poll INTEGER,snapshot TEXT,logs_initialized INTEGER NOT NULL DEFAULT 0); CREATE TABLE outbox(id INTEGER PRIMARY KEY,event_id INTEGER NOT NULL UNIQUE,delivered INTEGER,attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL DEFAULT 0);").unwrap();
        old.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,device TEXT NOT NULL,key TEXT NOT NULL,kind TEXT NOT NULL,health TEXT NOT NULL,message TEXT NOT NULL,created INTEGER NOT NULL);").unwrap();
        old.execute(
            "INSERT INTO devices(id,config,secret,last_poll) VALUES(?1,?2,?3,123)",
            params![d.id, config.to_string(), b"unchanged-ciphertext".as_slice()],
        )
        .unwrap();
        old.execute("INSERT INTO events(device,key,kind,health,message,created) VALUES(?1,'legacy','alarm','\"warning\"','legacy event',100)",[&d.id]).unwrap();
        drop(old);
        let mut store = Store::open(dir.path()).unwrap();
        let (migrated, secret, revision) = store.get(&d.id).unwrap().unwrap();
        assert!(migrated.enabled && migrated.ca_pem.is_none());
        assert_eq!(migrated.tls_profile, crate::model::TlsProfile::Standard);
        assert!(migrated.pinned_certificate_pem.is_none());
        assert_eq!(secret, b"unchanged-ciphertext");
        assert_eq!(revision, 0);
        assert_eq!(store.dashboard().unwrap()["devices"][0]["last_poll"], 123);
        assert_eq!(
            store.dashboard().unwrap()["events"][0]["message"],
            "legacy event"
        );
        assert_eq!(
            store.dashboard().unwrap()["events"][0]["device_name"],
            d.name
        );
        assert!(store.dashboard().unwrap()["events"][0]["source_created"].is_null());
        store
            .save_admin(&migrated, &secret, Some(0), "admin")
            .unwrap();
        drop(store);
        assert_eq!(
            Store::open(dir.path())
                .unwrap()
                .get(&d.id)
                .unwrap()
                .unwrap()
                .2,
            1
        );
    }

    #[test]
    fn retarget_disable_and_delete_cancel_pending_events_but_keep_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = device();
        let mut store = Store::open(dir.path()).unwrap();
        store.save_admin(&d, b"ciphertext", None, "admin").unwrap();
        store.apply(&d, &snap(Health::Critical), 100).unwrap();
        assert_eq!(store.pending(100).unwrap().len(), 1);
        d.endpoint = "https://another-bmc.example/".into();
        store
            .save_admin(&d, b"new-ciphertext", Some(1), "admin")
            .unwrap();
        let dashboard = store.dashboard().unwrap();
        assert!(dashboard["devices"][0]["snapshot"].is_null());
        assert!(dashboard["devices"][0]["alarms"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(dashboard["events"].as_array().unwrap().len(), 1);
        assert!(store.pending(100).unwrap().is_empty());
        store.apply(&d, &snap(Health::Warning), 101).unwrap();
        assert_eq!(store.pending(101).unwrap().len(), 1);
        d.alerts_enabled = false;
        store
            .save_admin(&d, b"new-ciphertext", Some(2), "admin")
            .unwrap();
        assert!(store.pending(101).unwrap().is_empty());
        d.alerts_enabled = true;
        store
            .save_admin(&d, b"new-ciphertext", Some(3), "admin")
            .unwrap();
        assert!(store.pending(101).unwrap().is_empty()); // cancelled messages never revive
        store.apply(&d, &snap(Health::Critical), 102).unwrap();
        assert_eq!(store.pending(102).unwrap().len(), 1);
        store.delete_admin(&d.id, 4, "admin").unwrap();
        assert!(store.pending(102).unwrap().is_empty());
        assert!(store.devices().unwrap().is_empty());
        assert_eq!(
            store.dashboard().unwrap()["events"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn historical_log_time_and_device_name_survive_removal() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = device();
        d.alerts_enabled = true;
        let mut store = Store::open(dir.path()).unwrap();
        store.put(&d, b"ciphertext").unwrap();
        store
            .apply(
                &d,
                &Snapshot {
                    logs_complete: true,
                    ..Default::default()
                },
                100,
            )
            .unwrap();
        let snapshot = Snapshot {
            logs_complete: true,
            logs: vec![HardwareLog {
                identity: None,
                fingerprint: "new-log".into(),
                message: "Historical message".into(),
                severity: Health::Warning,
                created: Some("2026-10-17T12:00:00Z".into()),
            }],
            ..Default::default()
        };
        store.apply(&d, &snapshot, 101).unwrap();
        let event = &store.dashboard().unwrap()["events"][0];
        assert_eq!(event["source_created"], "2026-10-17T12:00:00Z");
        assert_eq!(event["device_name"], d.name);
        assert_eq!(event["key"], "log:new-log");
        assert_eq!(event["queued"], true);
        let old_name = d.name.clone();
        d.name = "Renamed device".into();
        store.put(&d, b"ciphertext").unwrap();
        assert_eq!(
            store.dashboard().unwrap()["events"][0]["device_name"],
            d.name
        );
        store.delete_admin(&d.id, 2, "admin").unwrap();
        let event = &store.dashboard().unwrap()["events"][0];
        assert_eq!(event["device_name"], old_name);
        assert_eq!(event["cancelled"], true);
        assert_eq!(event["source_created"], "2026-10-17T12:00:00Z");
        // Cancelled delivery records must not pin old events beyond normal retention.
        let mut other = device();
        other.id = "other-device".into();
        store.put(&other, b"ciphertext").unwrap();
        store.apply(&other, &Snapshot::default(), 10000000).unwrap();
        crate::retention::cleanup(
            &mut store.0,
            &crate::retention::Settings::default(),
            10000000,
            |_| Ok(()),
        )
        .unwrap();
        assert!(store.dashboard().unwrap()["events"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    #[test]
    fn alias_migration_merges_alarm_state_and_reminders_without_new_event_or_history_loss() {
        let dir = tempfile::tempdir().unwrap();
        let d = device();
        let mut s = Store::open(dir.path()).unwrap();
        s.put(&d, b"ciphertext").unwrap();
        let sample = |key: &str| Observation {
            key: key.into(),
            label: "PS1".into(),
            health: Health::Critical,
            reading: None,
            unit: None,
        };
        let before = Snapshot {
            observations: vec![sample("legacy"), sample("modern")],
            ..Default::default()
        };
        s.apply(&d, &before, 100).unwrap();
        assert_eq!(
            s.dashboard().unwrap()["events"].as_array().unwrap().len(),
            2
        );
        let after = Snapshot {
            resource_aliases: std::collections::BTreeMap::from([(
                "legacy".into(),
                "modern".into(),
            )]),
            observations: vec![sample("modern")],
            ..Default::default()
        };
        s.apply(&d, &after, 101).unwrap();
        let data = s.dashboard().unwrap();
        assert_eq!(s.pending(101).unwrap().len(), 1);
        assert_eq!(data["devices"][0]["alarms"].as_array().unwrap().len(), 1);
        assert_eq!(data["events"].as_array().unwrap().len(), 2);
        assert!(data["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["canonical_key"] == "modern"));
        s.apply(&d, &after, 401).unwrap();
        assert_eq!(
            s.dashboard().unwrap()["events"].as_array().unwrap().len(),
            3
        ); // one reminder
        let recovered = Snapshot {
            resource_aliases: after.resource_aliases,
            observations: vec![Observation {
                health: Health::Ok,
                ..sample("modern")
            }],
            ..Default::default()
        };
        s.apply(&d, &recovered, 402).unwrap();
        assert!(s.dashboard().unwrap()["devices"][0]["alarms"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(s.dashboard().unwrap()["events"][0]["kind"], "recovery");
    }

    #[test]
    fn ilo6_179_upgrade_keeps_retained_psu_incidents_separate_from_current_absence() {
        let dir = tempfile::tempdir().unwrap();
        let d = device();
        let mut store = Store::open(dir.path()).unwrap();
        store.put(&d, b"synthetic-ciphertext").unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/hpe-ilo6-179-power-supplies.json"
        ))
        .unwrap();
        let mut applicability = crate::assessment::Applicability::default();
        let mut observations = std::collections::BTreeMap::new();
        for resource in fixture["resources"].as_array().unwrap() {
            let uri = resource["uri"].as_str().unwrap();
            applicability.observe(uri, &resource["body"]);
            crate::collector::normalize(uri, &resource["body"], &mut observations, &mut Vec::new());
        }
        let after = Snapshot {
            assessment_exclusions: applicability.exclusions(&observations),
            observations: observations.into_values().collect(),
            ..Default::default()
        };
        assert_eq!(after.assessment_exclusions.len(), 2);
        let mut before = after.clone();
        before.assessment_exclusions.clear();
        for observation in &mut before.observations {
            observation.health = Health::Warning;
        }
        let now = crate::now();
        store.apply(&d, &before, now - 60).unwrap();
        let count = store.event_entries(-1).unwrap().len();
        store.apply(&d, &after, now).unwrap();
        store.apply(&d, &after, now + 1).unwrap();
        let dashboard = store.dashboard().unwrap();
        let device = &dashboard["devices"][0];
        assert_eq!(device["overall_status"], "warning");
        assert_eq!(device["alarms"].as_array().unwrap().len(), 2);
        for observation in &after.observations {
            assert_eq!(observation.health, Health::Unknown);
            assert_eq!(
                device["snapshot"]["assessment_exclusions"][&observation.key],
                "absent"
            );
            assert_eq!(
                device["alarm_statuses"][&observation.key]["status"],
                "warning"
            );
            assert_eq!(
                device["alarm_statuses"][&observation.key]["acknowledged"],
                false
            );
        }
        assert!(device["alarms"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["health"] == "warning" && a["current_health"] == "unknown"));
        assert_eq!(store.event_entries(-1).unwrap().len(), count);
    }

    #[test]
    fn transitions_unknown_restarts_and_durable_outbox() {
        let dir = tempfile::tempdir().unwrap();
        let d = device();
        let mut s = Store::open(dir.path()).unwrap();
        s.put(&d, b"encrypted").unwrap();
        s.apply(&d, &snap(Health::Ok), 100).unwrap();
        assert_eq!(s.pending(100).unwrap().len(), 0);
        s.apply(&d, &snap(Health::Critical), 101).unwrap();
        s.apply(&d, &snap(Health::Critical), 102).unwrap();
        let mut disabled = snap(Health::Unknown);
        disabled
            .assessment_exclusions
            .insert("fan".into(), crate::model::AssessmentExclusion::Disabled);
        s.apply(&d, &disabled, 401).unwrap();
        let data = s.dashboard().unwrap();
        assert_eq!(
            data["devices"][0]["snapshot"]["assessment_exclusions"]["fan"],
            "disabled"
        );
        assert_eq!(data["devices"][0]["alarms"][0]["health"], "critical");
        s.apply(&d, &Snapshot::default(), 402).unwrap();
        assert_eq!(s.pending(402).unwrap().len(), 1);
        drop(s);
        let mut s = Store::open(dir.path()).unwrap();
        s.apply(&d, &snap(Health::Critical), 403).unwrap(); // reminder survives restart
        s.apply(&d, &snap(Health::Ok), 404).unwrap();
        let p = s.pending(404).unwrap();
        assert_eq!(
            p.iter().map(|p| p.1.as_str()).collect::<Vec<_>>(),
            vec!["alarm", "repeat", "recovery"]
        );
        s.delivery(p[0].0, false, 404).unwrap();
        assert_eq!(s.pending(405).unwrap().len(), 2);
        s.delivery(p[1].0, true, 404).unwrap();
        assert_eq!(s.pending(435).unwrap().len(), 2);
    }
    #[test]
    fn logs_baseline_dedup_and_notification_disable() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = device();
        let mut s = Store::open(dir.path()).unwrap();
        s.put(&d, b"x").unwrap();
        let mut snapshot = Snapshot {
            logs_complete: true,
            logs: vec![HardwareLog {
                identity: None,
                fingerprint: "old".into(),
                message: "old fault".into(),
                severity: Health::Critical,
                created: None,
            }],
            ..Default::default()
        };
        s.apply(&d, &snapshot, 1).unwrap();
        assert!(s.pending(1).unwrap().is_empty());
        snapshot.logs[0].fingerprint = "new".into();
        s.apply(&d, &snapshot, 2).unwrap();
        s.apply(&d, &snapshot, 3).unwrap();
        assert_eq!(s.pending(3).unwrap().len(), 1);
        d.alerts_enabled = false;
        s.apply(&d, &snap(Health::Warning), 4).unwrap();
        assert_eq!(s.pending(4).unwrap().len(), 1);
    }
    #[test]
    fn mail_queue_preserves_recipient_progress_and_never_replays_old_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let mut d = device();
        d.alerts_enabled = true;
        store.put(&d, b"encrypted").unwrap();
        store.apply(&d, &snap(Health::Critical), 100).unwrap();
        let mut settings = crate::mail::Settings {
            enabled: true,
            host: "smtp.example.invalid".into(),
            from_address: "monitor@example.invalid".into(),
            recipients: vec!["one@example.invalid".into(), "two@example.invalid".into()],
            ..crate::mail::Settings::default()
        };
        store.save_mail(&settings, b"", 0, "test-admin").unwrap();
        assert!(store.pending_mail(100).unwrap().is_none());
        store.apply(&d, &snap(Health::Warning), 101).unwrap();
        let first = store.pending_mail(101).unwrap().unwrap();
        store.finish_mail(&first, None, 101).unwrap();
        let second = store.pending_mail(101).unwrap().unwrap();
        assert_ne!(first.recipient, second.recipient);
        let id = second.message_id.clone();
        store
            .finish_mail(&second, Some("mail_connection_failed"), 101)
            .unwrap();
        assert!(store.pending_mail(102).unwrap().is_none());
        drop(store);
        let mut store = Store::open(dir.path()).unwrap();
        let retry = store.pending_mail(131).unwrap().unwrap();
        assert_eq!(retry.recipient, second.recipient);
        assert_eq!(retry.message_id, id);
        store.finish_mail(&retry, None, 131).unwrap();
        assert!(store.pending_mail(999).unwrap().is_none());
        let view = store.dashboard().unwrap();
        let event = &view["events"][0];
        assert_eq!(event["submitted_recipients"], 2);
        assert_eq!(event["total_recipients"], 2);
        assert!(event["delivered"].is_i64());
        store.apply(&d, &snap(Health::Critical), 140).unwrap();
        let rejected = store.pending_mail(140).unwrap().unwrap();
        store
            .finish_mail(&rejected, Some("mail_rejected"), 140)
            .unwrap();
        let next = store.pending_mail(500).unwrap().unwrap();
        assert_ne!(next.recipient, rejected.recipient);
        assert!(store.save_mail(&settings, b"", 0, "test-admin").is_err());
        assert!(store.pending_mail(500).unwrap().is_some());
        settings.enabled = false;
        store.save_mail(&settings, b"", 1, "test-admin").unwrap();
        assert!(store.pending_mail(500).unwrap().is_none());
        settings.enabled = true;
        store.save_mail(&settings, b"", 2, "test-admin").unwrap();
        assert!(store.pending_mail(500).unwrap().is_none());
        store.apply(&d, &snap(Health::Ok), 501).unwrap();
        let recovery = store.pending_mail(501).unwrap().unwrap();
        assert_eq!(recovery.event.kind, "recovery");
        d.alerts_enabled = false;
        store
            .save_admin(&d, b"encrypted", Some(1), "test-admin")
            .unwrap();
        assert!(store.pending_mail(501).unwrap().is_none());
    }
    #[test]
    fn repeat_channel_selection_and_device_gate_are_independent_and_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let mut d = device();
        d.alerts_enabled = false;
        s.put(&d, b"encrypted").unwrap();
        let mail = crate::mail::Settings {
            enabled: true,
            host: "smtp.example.invalid".into(),
            from_address: "sender@example.invalid".into(),
            recipients: vec!["recipient@example.invalid".into()],
            ..Default::default()
        };
        s.save_mail(&mail, b"", 0, "admin").unwrap();
        let mut policy = crate::notification::Input {
            language: Default::default(),
            revision: 0,
            desktop_enabled: true,
            selection: Default::default(),
        };
        s.save_notifications(&policy, "verified-admin").unwrap();
        s.apply(&d, &snap(Health::Critical), 100).unwrap();
        assert!(s.pending_mail(100).unwrap().is_none());
        assert!(s.pending_desktop(100).unwrap().is_none());
        assert_eq!(
            s.dashboard().unwrap()["events"][0]["mail_reason"],
            "device_disabled"
        );
        d.alerts_enabled = true;
        s.save_admin(&d, b"encrypted", Some(1), "admin").unwrap();
        s.apply(&d, &snap(Health::Critical), 399).unwrap();
        assert!(s.pending_mail(399).unwrap().is_none());
        s.apply(&d, &snap(Health::Critical), 400).unwrap();
        let job = s.pending_mail(400).unwrap().unwrap();
        assert_eq!(job.event.kind, "repeat");
        let desktop = s.pending_desktop(400).unwrap().unwrap();
        assert_eq!(desktop.kind, "repeat");
        assert_eq!(desktop.recipient, "verified-admin");
        s.finish_mail(&job, None, 400).unwrap();
        // Mail changes must not cancel the independently queued desktop notification.
        let mut disabled = mail.clone();
        disabled.enabled = false;
        s.save_mail(&disabled, b"", 1, "admin").unwrap();
        assert!(s.pending_desktop(400).unwrap().is_some());
        s.finish_desktop(&desktop, None, 400).unwrap();
        s.apply(&d, &snap(Health::Critical), 700).unwrap();
        assert!(s.pending_mail(700).unwrap().is_none());
        assert!(s.pending_desktop(700).unwrap().is_some());
        policy.revision = 1;
        policy.selection.repeat = false;
        s.save_notifications(&policy, "verified-admin").unwrap();
        s.apply(&d, &snap(Health::Critical), 1000).unwrap();
        assert!(s.pending_desktop(1000).unwrap().is_none());
        assert_eq!(
            s.dashboard().unwrap()["events"][0]["desktop_reason"],
            "filtered"
        );
        // Recovery is independent of the severity switch and of reminder selection.
        s.apply(&d, &snap(Health::Ok), 1001).unwrap();
        let recovery = s.pending_desktop(1001).unwrap().unwrap();
        assert_eq!(recovery.kind, "recovery");
        s.finish_desktop(&recovery, Some("desktop_test_unavailable"), 1001)
            .unwrap();
        drop(s);
        let mut s = Store::open(dir.path()).unwrap();
        assert!(s.pending_desktop(1030).unwrap().is_none());
        assert!(s.pending_desktop(1031).unwrap().is_some());
        d.alerts_enabled = false;
        s.save_admin(&d, b"encrypted", Some(2), "admin").unwrap();
        assert!(s.pending_desktop(2000).unwrap().is_none());
    }
    fn correlated_store() -> (tempfile::TempDir, Store, Device) {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let d = device();
        s.put(&d, b"encrypted").unwrap();
        let mail = crate::mail::Settings {
            enabled: true,
            host: "smtp.example.invalid".into(),
            from_address: "sender@example.invalid".into(),
            recipients: vec!["recipient@example.invalid".into()],
            ..Default::default()
        };
        s.save_mail(&mail, b"", 0, "admin").unwrap();
        s.save_notifications(
            &crate::notification::Input {
                language: Default::default(),
                revision: 0,
                desktop_enabled: true,
                selection: Default::default(),
            },
            "verified-admin",
        )
        .unwrap();
        (dir, s, d)
    }
    fn fault_fixture() -> Snapshot {
        use crate::correlation::tests::{PSU, SUBSYSTEM};
        let mut snapshot = crate::correlation::tests::fixture();
        for o in &mut snapshot.observations {
            if o.key == PSU || o.key == SUBSYSTEM {
                o.health = Health::Critical;
            }
        }
        snapshot.resources.get_mut(SUBSYSTEM).unwrap().own_health = Some(Health::Critical);
        snapshot
    }
    fn acknowledge_channels(s: &mut Store, now: i64) -> (Vec<String>, Vec<String>) {
        let mut mail = Vec::new();
        while let Some(job) = s.pending_mail(now).unwrap() {
            mail.push(job.event.resource.clone());
            s.finish_mail(&job, None, now).unwrap();
        }
        let mut desktop = Vec::new();
        while let Some(job) = s.pending_desktop(now).unwrap() {
            let key: String =
                s.0.query_row("SELECT key FROM events WHERE id=?1", [job.event_id], |r| {
                    r.get(0)
                })
                .unwrap();
            desktop.push(key);
            s.finish_desktop(&job, None, now).unwrap();
        }
        (mail, desktop)
    }
    #[test]
    fn one_component_alarm_repeat_and_recovery_per_channel_keep_all_summary_states() {
        use crate::correlation::tests::{CHASSIS, PSU, SUBSYSTEM, SYSTEM};
        let (_dir, mut s, d) = correlated_store();
        let mut snapshot = fault_fixture();
        s.apply(&d, &snapshot, 100).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 100),
            (vec![PSU.into()], vec![PSU.into()])
        );
        let view = s.dashboard().unwrap();
        let alarms = view["devices"][0]["alarms"].as_array().unwrap();
        assert_eq!(alarms.len(), 4);
        assert_eq!(
            alarms
                .iter()
                .filter(|a| a["covered_by"].as_array().unwrap().is_empty())
                .count(),
            1
        );
        assert_eq!(
            view["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["mail_reason"] == "aggregate")
                .count(),
            3
        );
        // Distinct components still notify independently; no name-based deduplication.
        let mut independent = snapshot.clone();
        let mut second = independent
            .observations
            .iter()
            .find(|o| o.key == PSU)
            .unwrap()
            .clone();
        second.key = "/redfish/v1/Chassis/Test/Fans/Fan1".into();
        second.label = "Independent fan fault".into();
        independent.observations.push(second.clone());
        s.apply(&d, &independent, 101).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 101),
            (vec![second.key.clone()], vec![second.key])
        );
        s.apply(&d, &snapshot, 400).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 400),
            (vec![PSU.into()], vec![PSU.into()])
        );
        for o in &mut snapshot.observations {
            if [PSU, SYSTEM, CHASSIS, SUBSYSTEM].contains(&o.key.as_str()) {
                o.health = Health::Ok;
            }
        }
        s.apply(&d, &snapshot, 401).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 401),
            (vec![PSU.into()], vec![PSU.into()])
        );
    }
    #[test]
    fn full_history_export_filters_and_clear_cancel_jobs_keep_faults_and_ids() {
        let (_dir, mut s, d) = correlated_store();
        let now = crate::now();
        let snapshot = fault_fixture();
        s.apply(&d, &snapshot, now).unwrap();
        for i in 0..110 {
            s.0.execute("INSERT INTO events(device,key,kind,health,message,created) VALUES(?1,'log:test','hardware_log','\"warning\"',?2,?3)",params![d.id,format!("=formula; quoted \"value\"\nline {i}"),now]).unwrap();
        }
        let old_max: i64 =
            s.0.query_row("SELECT MAX(id) FROM events", [], |r| r.get(0))
                .unwrap();
        assert_eq!(
            s.dashboard().unwrap()["events"].as_array().unwrap().len(),
            100
        );
        let (csv, count) = s
            .events_csv(&crate::history::Filter {
                category: "log".into(),
                health: "warning".into(),
                device: d.id.clone(),
            })
            .unwrap();
        assert_eq!(count, 110);
        assert!(csv.contains("\"'=formula; quoted \"\"value\"\"\nline"));
        assert!(
            s.pending_mail(now).unwrap().is_some() && s.pending_desktop(now).unwrap().is_some()
        );
        s.clear_events("admin").unwrap();
        assert!(
            s.pending_mail(now).unwrap().is_none() && s.pending_desktop(now).unwrap().is_none()
        );
        assert_eq!(
            s.dashboard().unwrap()["devices"][0]["alarms"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        s.apply(&d, &snapshot, now + 1).unwrap();
        assert!(s.dashboard().unwrap()["events"]
            .as_array()
            .unwrap()
            .is_empty());
        let cleared_at: i64 =
            s.0.query_row("SELECT MAX(emitted) FROM alarm_state", [], |r| r.get(0))
                .unwrap();
        s.apply(&d, &snapshot, cleared_at + 300).unwrap();
        let view = s.dashboard().unwrap();
        assert!(view["events"][0]["id"].as_i64().unwrap() > old_max);
        assert!(s.pending_mail(cleared_at + 300).unwrap().is_some());
    }
    #[test]
    fn english_queues_and_csv_use_context_and_preserve_historical_text() {
        let (_dir, mut s, d) = correlated_store();
        let (mut mail, secret, revision) = s.mail_settings().unwrap().unwrap();
        mail.language = crate::i18n::Language::En;
        s.save_mail(&mail, &secret, revision, "admin").unwrap();
        s.save_notifications(
            &crate::notification::Input {
                language: crate::i18n::Language::En,
                revision: 1,
                desktop_enabled: true,
                selection: Default::default(),
            },
            "admin",
        )
        .unwrap();
        s.apply(&d, &fault_fixture(), crate::now()).unwrap();
        let desktop = s.pending_desktop(crate::now()).unwrap().unwrap();
        assert_eq!(desktop.language, crate::i18n::Language::En);
        assert!(desktop.message.contains("Hardware state critical"));
        let mail = s.pending_mail(crate::now()).unwrap().unwrap();
        assert!(mail
            .settings
            .preview(&mail.event)
            .unwrap()
            .1
            .contains("Hardware state critical"));
        let (csv, _) = s
            .events_csv_localized(&Default::default(), crate::i18n::Language::En)
            .unwrap();
        assert!(csv.contains("Event ID") && csv.contains("Hardware state critical"));
        s.0.execute(
            "UPDATE events SET message_context=NULL,message='Historischer Text'",
            [],
        )
        .unwrap();
        let (csv, _) = s
            .events_csv_localized(&Default::default(), crate::i18n::Language::En)
            .unwrap();
        assert!(csv.contains("Historischer Text"));
    }
    #[test]
    fn psu_and_drive_have_independent_notifications_and_partial_recovery() {
        use crate::correlation::tests::{CHASSIS, PSU, SYSTEM};
        let (_dir, mut s, d) = correlated_store();
        let mut snapshot = fault_fixture();
        let drive = "/redfish/v1/Systems/System.Embedded.1/Storage/RAID/Drives/Disk1";
        snapshot
            .resources
            .get_mut(CHASSIS)
            .unwrap()
            .children
            .insert(drive.into());
        snapshot.resources.insert(
            drive.into(),
            crate::correlation::Resource {
                kind: "#Drive.v1_0_0.Drive".into(),
                own_health: Some(Health::Critical),
                ..Default::default()
            },
        );
        snapshot.observations.push(Observation {
            key: drive.into(),
            label: "Disk1".into(),
            health: Health::Critical,
            reading: None,
            unit: None,
        });
        s.apply(&d, &snapshot, 100).unwrap();
        let (mail, desktop) = acknowledge_channels(&mut s, 100);
        for jobs in [&mail, &desktop] {
            assert_eq!(jobs.len(), 2);
            assert!(jobs.contains(&PSU.into()));
            assert!(jobs.contains(&drive.into()));
        }
        let grouped = crate::correlation::groups(
            &snapshot.resources,
            &snapshot
                .observations
                .iter()
                .map(|o| (o.key.clone(), o.health))
                .collect(),
        );
        assert_eq!(grouped[SYSTEM].len(), 2);
        // The PSU recovers while the disk keeps the chassis and system critical.
        for o in &mut snapshot.observations {
            if o.key == PSU || o.key == crate::correlation::tests::SUBSYSTEM {
                o.health = Health::Ok;
            }
        }
        s.apply(&d, &snapshot, 101).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 101),
            (vec![PSU.into()], vec![PSU.into()])
        );
        s.apply(&d, &snapshot, 400).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 400),
            (vec![drive.into()], vec![drive.into()])
        );
        for o in &mut snapshot.observations {
            o.health = Health::Ok;
        }
        s.apply(&d, &snapshot, 401).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 401),
            (vec![drive.into()], vec![drive.into()])
        );
    }
    #[test]
    fn upgrade_pending_summaries_cancel_and_offline_reminder_retains_last_confirmation() {
        use crate::correlation::tests::PSU;
        let (dir, mut s, d) = correlated_store();
        let mut old = fault_fixture();
        old.resources.clear();
        s.apply(&d, &old, 100).unwrap();
        assert_eq!(
            s.0.query_row("SELECT COUNT(*) FROM outbox WHERE cancelled=0", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            4
        );
        let offline = crate::correlation::tests::fixture();
        s.apply(&d, &offline, 101).unwrap();
        assert_eq!(
            acknowledge_channels(&mut s, 101),
            (vec![PSU.into()], vec![PSU.into()])
        );
        drop(s);
        let mut s = Store::open(dir.path()).unwrap();
        s.apply(&d, &offline, 400).unwrap();
        let job = s.pending_mail(400).unwrap().unwrap();
        assert_eq!(job.event.kind, "repeat");
        assert_eq!(job.event.resource, PSU);
        assert!(job.event.message.contains("aktuell nicht bewertbar"));
        assert!(job.event.message.contains("zuletzt kritisch"));
        let view = s.dashboard().unwrap();
        let leaf = view["devices"][0]["alarms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == PSU)
            .unwrap();
        assert_eq!(leaf["observed"], 100);
        assert_eq!(leaf["current_health"], "unknown");
        assert_eq!(
            acknowledge_channels(&mut s, 400),
            (vec![PSU.into()], vec![PSU.into()])
        );
        s.apply(&d, &offline, 401).unwrap();
        assert!(s.pending_mail(401).unwrap().is_none());
        // No fresh aggregate confirmation: unknown leaves alone never create reminders.
        let mut unavailable = offline;
        for o in &mut unavailable.observations {
            o.health = Health::Unknown;
        }
        s.apply(&d, &unavailable, 1000).unwrap();
        assert!(s.pending_mail(1000).unwrap().is_none());
    }
    #[test]
    fn still_faulty_summary_is_announced_immediately_after_component_recovery() {
        use crate::correlation::tests::{CHASSIS, PSU};
        let (_dir, mut s, d) = correlated_store();
        let mut initial = crate::correlation::tests::fixture();
        initial
            .observations
            .iter_mut()
            .find(|o| o.key == PSU)
            .unwrap()
            .health = Health::Critical;
        s.apply(&d, &initial, 100).unwrap();
        acknowledge_channels(&mut s, 100);
        let mut after = initial;
        after
            .observations
            .iter_mut()
            .find(|o| o.key == PSU)
            .unwrap()
            .health = Health::Ok;
        s.apply(&d, &after, 101).unwrap();
        let mail = acknowledge_channels(&mut s, 101).0;
        assert_eq!(mail.len(), 2);
        assert!(mail.contains(&PSU.into()));
        assert!(mail.contains(&CHASSIS.into()));
    }
    #[test]
    fn selection_preserves_local_events_and_filters_each_kind() {
        use crate::notification::Selection;
        let mut selection = Selection {
            warning: false,
            ..Default::default()
        };
        assert!(!selection.accepts("fan", "alarm", Health::Warning));
        assert!(selection.accepts("fan", "alarm", Health::Critical));
        assert!(!selection.accepts("log", "hardware_log", Health::Warning));
        selection.hardware_log = false;
        assert!(!selection.accepts("log", "hardware_log", Health::Critical));
        selection.repeat = false;
        assert!(!selection.accepts("fan", "repeat", Health::Critical));
        assert!(selection.accepts("fan", "recovery", Health::Ok));
        selection.recovery = false;
        assert!(!selection.accepts("fan", "recovery", Health::Ok));
    }
    #[test]
    fn query_filter_controls_both_channels_and_keeps_filtered_events_in_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let d = device();
        store.put(&d, b"encrypted").unwrap();
        store
            .save_mail(
                &crate::mail::Settings {
                    enabled: true,
                    host: "smtp.example.invalid".into(),
                    from_address: "sender@example.invalid".into(),
                    recipients: vec!["recipient@example.invalid".into()],
                    ..Default::default()
                },
                b"",
                0,
                "admin",
            )
            .unwrap();
        let mut policy = crate::notification::Input {
            language: Default::default(),
            revision: 0,
            desktop_enabled: true,
            selection: crate::notification::Selection {
                critical: false,
                warning: false,
                monitoring: Some(true),
                ..Default::default()
            },
        };
        store.save_notifications(&policy, "verified-admin").unwrap();
        let sample = |key: &str, health: Health| {
            let mut snapshot = snap(health);
            snapshot.observations[0].key = key.into();
            snapshot
        };
        store
            .apply(
                &d,
                &sample("coverage:/redfish/v1/Systems", Health::Warning),
                100,
            )
            .unwrap();
        assert!(store.pending_mail(100).unwrap().is_some());
        assert!(store.pending_desktop(100).unwrap().is_some());
        assert_eq!(
            store.dashboard().unwrap()["events"][0]["mail_reason"],
            "queued"
        );
        // Saving the explicit exclusion cancels earlier jobs on both channels.
        policy.revision = 1;
        policy.selection.monitoring = Some(false);
        policy.selection.critical = true;
        policy.selection.warning = true;
        store.save_notifications(&policy, "verified-admin").unwrap();
        store
            .apply(&d, &sample("collector", Health::Critical), 101)
            .unwrap();
        store
            .apply(&d, &sample("collector", Health::Ok), 102)
            .unwrap();
        assert!(store.pending_mail(102).unwrap().is_none());
        assert!(store.pending_desktop(102).unwrap().is_none());
        let data = store.dashboard().unwrap();
        let query_events: Vec<_> = data["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["key"] == "collector")
            .collect();
        assert_eq!(query_events.len(), 2);
        assert!(query_events
            .iter()
            .all(|e| e["mail_reason"] == "filtered" && e["desktop_reason"] == "filtered"));
        drop(store);
        let mut store = Store::open(dir.path()).unwrap();
        assert_eq!(
            store
                .notification_settings()
                .unwrap()
                .0
                .selection
                .monitoring,
            Some(false)
        );
        store
            .apply(&d, &sample("fan", Health::Warning), 103)
            .unwrap();
        assert!(store.pending_mail(103).unwrap().is_some());
        assert!(store.pending_desktop(103).unwrap().is_some());
    }
    #[test]
    fn terminal_mail_retention_cascades_but_keeps_pending_recipients() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let d = device();
        s.put(&d, b"secret").unwrap();
        let settings = crate::mail::Settings {
            enabled: true,
            host: "smtp.example.invalid".into(),
            from_address: "m@example.invalid".into(),
            recipients: vec!["r@example.invalid".into()],
            ..crate::mail::Settings::default()
        };
        s.save_mail(&settings, b"", 0, "test-admin").unwrap();
        let mut d = d;
        d.alerts_enabled = true;
        s.apply(&d, &snap(Health::Critical), 100).unwrap();
        let job = s.pending_mail(100).unwrap().unwrap();
        s.finish_mail(&job, Some("mail_rejected"), 100).unwrap();
        s.apply(&d, &snap(Health::Warning), 101).unwrap();
        let pending = s.pending_mail(101).unwrap().unwrap();
        s.apply(&d, &snap(Health::Warning), 100 + 91 * 86400)
            .unwrap();
        crate::retention::cleanup(
            &mut s.0,
            &crate::retention::Settings::default(),
            100 + 91 * 86400,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            s.0.query_row(
                "SELECT COUNT(*) FROM mail_recipient WHERE outbox_id=?1",
                [job.outbox],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            s.pending_mail(100 + 91 * 86400).unwrap().unwrap().outbox,
            pending.outbox
        );
    }
    #[test]
    fn incomplete_migration_backup_is_not_published_and_retry_keeps_existing_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let database = Connection::open(dir.path().join("monitor.db")).unwrap();
        database.execute_batch("CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(1); CREATE TABLE marker(value INTEGER); INSERT INTO marker VALUES(42);").unwrap();
        let key = dir.path().join("master.key");
        std::fs::write(&key, [7u8; 31]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let existing = dir.path().join("pre-snmp-schema1-existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("keep"), b"existing backup").unwrap();
        assert!(migration_backup(&database, dir.path()).is_err());
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")));
        assert_eq!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("pre-snmp-schema1-"))
                .count(),
            1
        );
        assert_eq!(
            std::fs::read(existing.join("keep")).unwrap(),
            b"existing backup"
        );
        std::fs::write(&key, [7u8; 32]).unwrap();
        migration_backup(&database, dir.path()).unwrap();
        let backup = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir() && *path != existing)
            .unwrap();
        assert_eq!(std::fs::read(backup.join("master.key")).unwrap(), [7u8; 32]);
        let copy = Connection::open(backup.join("monitor.db")).unwrap();
        assert_eq!(
            copy.query_row("SELECT value FROM marker", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            42
        );
        assert_eq!(
            database
                .query_row("SELECT version FROM schema_version", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            std::fs::metadata(backup.join("monitor.db"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}

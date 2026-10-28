use super::*;
use crate::{
    model::{Device, Health},
    store::Store,
    vault::Vault,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
pub const TABLES:&[(&str,&str)]=&[
    ("webhook_endpoints","id,config,secret,revision,next_send"),
    ("webhook_jobs","id,event_id,endpoint,revision,name,delivered,attempts,next_try,error,permanent,cancelled,http_status,created"),
];
pub fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS webhook_endpoints(id TEXT PRIMARY KEY,config TEXT NOT NULL,secret BLOB NOT NULL,revision INTEGER NOT NULL,next_send INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS webhook_jobs(id TEXT PRIMARY KEY,event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,endpoint TEXT NOT NULL,revision INTEGER NOT NULL,name TEXT NOT NULL,delivered INTEGER,attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL DEFAULT 0,error TEXT,permanent INTEGER NOT NULL DEFAULT 0,cancelled INTEGER NOT NULL DEFAULT 0,http_status INTEGER,created INTEGER NOT NULL,claimed_until INTEGER NOT NULL DEFAULT 0,UNIQUE(event_id,endpoint));
    CREATE INDEX IF NOT EXISTS webhook_due ON webhook_jobs(cancelled,permanent,delivered,next_try);
    CREATE INDEX IF NOT EXISTS webhook_events ON webhook_jobs(event_id);
    CREATE INDEX IF NOT EXISTS webhook_targets ON webhook_jobs(endpoint,event_id);")?;
    Ok(())
}
pub struct Endpoint {
    pub id: String,
    pub settings: Settings,
    pub secrets: Secrets,
    pub revision: i64,
}
pub struct Job {
    pub id: String,
    pub endpoint: Endpoint,
    pub event: Event,
}
impl Store {
    pub fn webhook_endpoint(&self, id: &str, vault: &Vault) -> Result<Option<Endpoint>> {
        let row: Option<(String, Vec<u8>, i64)> = self
            .0
            .query_row(
                "SELECT config,secret,revision FROM webhook_endpoints WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(raw, secret, revision)| {
            Ok(Endpoint {
                id: id.into(),
                settings: serde_json::from_str(&raw)?,
                secrets: serde_json::from_slice(&vault.unseal(&aad(id), &secret)?)?,
                revision,
            })
        })
        .transpose()
    }
    pub fn prepare_webhook(&self, input: &Input, vault: &Vault) -> Result<Endpoint> {
        let old = if let Some(id) = &input.id {
            anyhow::ensure!(valid_id(id), BoundaryError("webhook_conflict"));
            Some(
                self.webhook_endpoint(id, vault)?
                    .context(BoundaryError("webhook_conflict"))?,
            )
        } else {
            None
        };
        anyhow::ensure!(
            old.as_ref().map_or(0, |e| e.revision) == input.revision,
            BoundaryError("webhook_conflict")
        );
        let id = input.id.clone().unwrap_or_else(new_id);
        let mut secrets = old.as_ref().map(|e| e.secrets.clone()).unwrap_or_default();
        if let Some(value) = input.url.as_ref().filter(|v| !v.is_empty()) {
            secrets.url = value.clone();
        }
        url(&secrets.url)?;
        let changed = old.as_ref().is_some_and(|e| {
            e.secrets.url != secrets.url
                || e.settings.auth != input.settings.auth
                || e.settings.username != input.settings.username
        });
        if changed {
            secrets.credential.clear();
            secrets.values.clear();
        }
        if let Some(value) = input.credential.as_ref().filter(|v| !v.is_empty()) {
            secrets.credential = value.clone();
        }
        anyhow::ensure!(
            secrets.credential.len() <= 4096,
            BoundaryError("webhook_config_invalid")
        );
        if input.settings.auth != Auth::None {
            anyhow::ensure!(
                !secrets.credential.is_empty(),
                BoundaryError("webhook_secret_required")
            );
        }
        if input.settings.auth == Auth::Bearer {
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", secrets.credential))
                .context(BoundaryError("webhook_config_invalid"))?;
        }
        if input.settings.auth == Auth::Basic {
            anyhow::ensure!(
                !input.settings.username.contains(':')
                    && !input.settings.username.chars().any(char::is_control),
                BoundaryError("webhook_config_invalid")
            );
        }
        if input.settings.auth == Auth::None {
            secrets.credential.zeroize();
        }
        let mut settings = input.settings.clone();
        settings.validate()?;
        let mut keep = BTreeSet::new();
        for field in settings
            .fields
            .iter_mut()
            .chain(settings.headers.iter_mut())
        {
            if field.secret {
                if !field.value.is_empty() {
                    secrets.values.insert(field.id.clone(), field.value.clone());
                } else {
                    // A blank secret can only retain the same saved field and name.
                    let same = old.as_ref().is_some_and(|e| {
                        e.settings
                            .fields
                            .iter()
                            .chain(e.settings.headers.iter())
                            .any(|f| f.id == field.id && f.name == field.name && f.secret)
                    });
                    anyhow::ensure!(
                        same && secrets.values.contains_key(&field.id),
                        BoundaryError("webhook_secret_required")
                    );
                }
                keep.insert(field.id.clone());
                field.value.zeroize();
                field.value.clear();
            }
        }
        secrets.values.retain(|key, _| keep.contains(key));
        let hydrated = settings.hydrate(&secrets)?;
        for field in &hydrated.headers {
            reqwest::header::HeaderValue::from_str(&field.value)
                .context(BoundaryError("webhook_config_invalid"))?;
        }
        render(
            &hydrated,
            &Event::sample_for(settings.language),
            "sample",
            false,
        )?;
        Ok(Endpoint {
            id,
            settings,
            secrets,
            revision: input.revision,
        })
    }
    pub fn save_webhook(&mut self, endpoint: &Endpoint, vault: &Vault, actor: &str) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<i64> = tx
            .query_row(
                "SELECT revision FROM webhook_endpoints WHERE id=?1",
                [&endpoint.id],
                |r| r.get(0),
            )
            .optional()?;
        anyhow::ensure!(
            current.unwrap_or(0) == endpoint.revision,
            BoundaryError("webhook_conflict")
        );
        let count: i64 =
            tx.query_row("SELECT COUNT(*) FROM webhook_endpoints", [], |r| r.get(0))?;
        anyhow::ensure!(
            current.is_some() || count < MAX_TARGETS as i64,
            BoundaryError("webhook_limit")
        );
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&endpoint.secrets)?);
        let secret = vault.seal(&aad(&endpoint.id), &plain)?;
        tx.execute("UPDATE webhook_jobs SET cancelled=1,error='configuration_changed' WHERE endpoint=?1 AND delivered IS NULL AND permanent=0 AND cancelled=0",[&endpoint.id])?;
        tx.execute("INSERT INTO webhook_endpoints(id,config,secret,revision) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET config=excluded.config,secret=excluded.secret,revision=excluded.revision,next_send=0",params![endpoint.id,serde_json::to_string(&endpoint.settings)?,secret,endpoint.revision+1])?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'webhook.settings',?2,'ok',?3)",params![actor,endpoint.id,crate::now()])?;
        tx.commit()?;
        Ok(())
    }
    pub fn delete_webhook(&mut self, id: &str, revision: i64, actor: &str) -> Result<()> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        anyhow::ensure!(
            tx.execute(
                "DELETE FROM webhook_endpoints WHERE id=?1 AND revision=?2",
                params![id, revision]
            )? == 1,
            BoundaryError("webhook_conflict")
        );
        tx.execute("UPDATE webhook_jobs SET cancelled=1,error='target_deleted' WHERE endpoint=?1 AND delivered IS NULL AND permanent=0 AND cancelled=0",[id])?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'webhook.delete',?2,'ok',?3)",params![actor,id,crate::now()])?;
        tx.commit()?;
        Ok(())
    }
    pub fn webhook_views(&self, vault: &Vault) -> Result<Vec<Value>> {
        let mut q = self
            .0
            .prepare("SELECT id FROM webhook_endpoints ORDER BY id")?;
        let ids = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut views = vec![];
        for id in ids {
            let e = self
                .webhook_endpoint(&id, vault)?
                .context("webhook missing")?;
            let origin = url(&e.secrets.url)?.origin().ascii_serialization();
            let status=self.0.query_row("SELECT delivered,attempts,error,permanent,cancelled,http_status,created FROM webhook_jobs WHERE endpoint=?1 AND NOT(cancelled=1 AND COALESCE(error,'') IN ('filtered','device_filtered')) ORDER BY created DESC,event_id DESC LIMIT 1",[&id],|r|Ok(json!({"delivered":r.get::<_,Option<i64>>(0)?,"attempts":r.get::<_,i64>(1)?,"error":r.get::<_,Option<String>>(2)?,"permanent":r.get::<_,bool>(3)?,"cancelled":r.get::<_,bool>(4)?,"http_status":r.get::<_,Option<i64>>(5)?,"created":r.get::<_,i64>(6)?}))).optional()?;
            let pending:i64=self.0.query_row("SELECT COUNT(*) FROM webhook_jobs WHERE endpoint=?1 AND delivered IS NULL AND permanent=0 AND cancelled=0",[&id],|r|r.get(0))?;
            views.push(json!({"id":id,"revision":e.revision,"settings":e.settings,"url_origin":origin,"has_url":true,"has_credential":!e.secrets.credential.is_empty(),"status":status,"pending":pending}));
        }
        Ok(views)
    }
    pub fn webhook_event_status(&self, event: i64) -> Result<Vec<Value>> {
        let mut q=self.0.prepare("SELECT endpoint,name,delivered,attempts,next_try,error,permanent,cancelled,http_status,id FROM webhook_jobs WHERE event_id=?1 ORDER BY endpoint")?;
        let rows=q.query_map([event],|r|Ok(json!({"endpoint":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"delivered":r.get::<_,Option<i64>>(2)?,"attempts":r.get::<_,i64>(3)?,"next_try":r.get::<_,i64>(4)?,"error":r.get::<_,Option<String>>(5)?,"permanent":r.get::<_,bool>(6)?,"cancelled":r.get::<_,bool>(7)?,"http_status":r.get::<_,Option<i64>>(8)?,"delivery_id":r.get::<_,String>(9)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
    pub fn reserve_webhook_test(&self, actor: &str, now: i64) -> Result<i64> {
        let last: Option<i64> = self.0.query_row(
            "SELECT MAX(created) FROM audit_log WHERE actor=?1 AND action='webhook.test'",
            [actor],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            last.is_none_or(|t| now - t >= 30),
            BoundaryError("webhook_test_rate_limited")
        );
        self.audit(actor, "webhook.test", "webhooks", "started")?;
        Ok(self.0.last_insert_rowid())
    }
    pub fn claim_webhook(&mut self, vault: &Vault, now: i64) -> Result<Option<Job>> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("UPDATE webhook_jobs SET permanent=1,error='expired' WHERE delivered IS NULL AND permanent=0 AND cancelled=0 AND created<=?1",[now-MAX_AGE])?;
        let candidate:Option<(String,String,i64)>=tx.query_row("SELECT j.id,j.endpoint,j.event_id FROM webhook_jobs j JOIN webhook_endpoints p ON p.id=j.endpoint AND p.revision=j.revision JOIN events e ON e.id=j.event_id WHERE json_extract(p.config,'$.enabled')=1 AND p.next_send<=?1 AND j.delivered IS NULL AND j.cancelled=0 AND j.permanent=0 AND j.attempts<8 AND j.next_try<=?1 AND j.claimed_until<=?1 AND NOT EXISTS(SELECT 1 FROM webhook_jobs l WHERE l.endpoint=j.endpoint AND l.delivered IS NULL AND l.cancelled=0 AND l.permanent=0 AND l.claimed_until>?1) AND NOT EXISTS(SELECT 1 FROM webhook_jobs o JOIN events older ON older.id=o.event_id WHERE o.endpoint=j.endpoint AND o.delivered IS NULL AND o.cancelled=0 AND o.permanent=0 AND older.device=e.device AND COALESCE(older.canonical_key,older.key)=COALESCE(e.canonical_key,e.key) AND o.event_id<j.event_id) ORDER BY j.next_try,j.event_id,j.endpoint LIMIT 1",[now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((id, endpoint, event)) = candidate else {
            tx.commit()?;
            return Ok(None);
        };
        let event=tx.query_row("SELECT id,device,COALESCE(device_name,device),COALESCE(canonical_key,key),kind,health,message,created,message_context FROM events WHERE id=?1",[event],|r|Ok(Event{id:r.get(0)?,device_id:r.get(1)?,device:r.get(2)?,resource:r.get(3)?,kind:r.get(4)?,health:serde_json::from_str(&r.get::<_,String>(5)?).unwrap_or_else(|_|"unknown".into()),message:r.get(6)?,created:r.get(7)?,context:r.get::<_,Option<String>>(8)?.and_then(|s|serde_json::from_str(&s).ok())}))?;
        tx.execute(
            "UPDATE webhook_jobs SET claimed_until=?2 WHERE id=?1",
            params![id, now + 30],
        )?;
        tx.commit()?;
        let endpoint = self
            .webhook_endpoint(&endpoint, vault)?
            .context("webhook missing")?;
        let mut event = event;
        event.message = crate::i18n::event_message(
            &event.device,
            &event.resource,
            &event.kind,
            &event.health,
            &event.message,
            event.context.as_ref(),
            endpoint.settings.language,
        );
        Ok(Some(Job {
            id,
            endpoint,
            event,
        }))
    }
    pub fn webhook_current(&self, job: &Job) -> Result<bool> {
        Ok(self.0.query_row("SELECT EXISTS(SELECT 1 FROM webhook_jobs j JOIN webhook_endpoints p ON p.id=j.endpoint AND p.revision=j.revision WHERE j.id=?1 AND j.delivered IS NULL AND j.cancelled=0 AND j.permanent=0 AND json_extract(p.config,'$.enabled')=1)",[&job.id],|r|r.get(0))?)
    }
    pub fn finish_webhook(&mut self, job: &Job, outcome: &Outcome, now: i64) -> Result<()> {
        let tx = self.0.transaction()?;
        let delay = outcome.retry_after.unwrap_or(0).max(1);
        tx.execute("UPDATE webhook_jobs SET claimed_until=0,attempts=attempts+1,delivered=CASE WHEN ?2 IS NULL THEN ?3 ELSE NULL END,permanent=CASE WHEN ?4 OR attempts>=7 THEN 1 ELSE 0 END,error=?2,http_status=?5,next_try=?3+MAX(?6,MIN(3600,30*(1 << MIN(attempts,7)))+?7) WHERE id=?1 AND delivered IS NULL AND cancelled=0 AND permanent=0",params![job.id,outcome.code,now,outcome.permanent,outcome.status,delay,(rand::random::<u8>()%10) as i64])?;
        tx.execute(
            "UPDATE webhook_endpoints SET next_send=MAX(next_send,?2) WHERE id=?1 AND revision=?3",
            params![job.endpoint.id, now + delay, job.endpoint.revision],
        )?;
        tx.commit()?;
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
pub fn enqueue(
    conn: &Connection,
    d: &Device,
    event: i64,
    key: &str,
    kind: &str,
    health: Health,
    acknowledged: bool,
    now: i64,
) -> Result<()> {
    if !d.enabled
        || !d.alerts_enabled
        || acknowledged && !matches!(kind, "hardware_log" | "snmp_trap")
    {
        return Ok(());
    }
    let mut q = conn.prepare("SELECT id,config,revision FROM webhook_endpoints")?;
    let rows = q
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM webhook_jobs WHERE delivered IS NULL AND cancelled=0 AND permanent=0",
        [],
        |r| r.get(0),
    )?;
    for (id, raw, revision) in rows {
        let settings: Settings = serde_json::from_str(&raw)?;
        if !settings.enabled {
            continue;
        }
        // Retain the event-time selection decision as an inactive history row.
        // It must never consume queue capacity or change later with the settings.
        let exclusion = if !settings.devices.is_empty() && !settings.devices.contains(&d.id) {
            Some("device_filtered")
        } else if !settings.selection.accepts(key, kind, health) {
            Some("filtered")
        } else {
            None
        };
        if let Some(reason) = exclusion {
            conn.execute("INSERT INTO webhook_jobs(id,event_id,endpoint,revision,name,created,next_try,cancelled,error) VALUES(?1,?2,?3,?4,?5,?6,?6,1,?7)",params![new_id(),event,id,revision,settings.name,now,reason])?;
            continue;
        }
        let full = pending >= MAX_PENDING;
        conn.execute("INSERT INTO webhook_jobs(id,event_id,endpoint,revision,name,created,next_try,permanent,error) VALUES(?1,?2,?3,?4,?5,?6,?6,?7,?8)",params![new_id(),event,id,revision,settings.name,now,full,full.then_some("queue_full")])?;
        if !full {
            pending += 1;
        }
    }
    Ok(())
}
/// Validate imported endpoints, invalidate optimistic revisions and pause automatic delivery.
pub fn restore(conn: &Connection, vault: &Vault, revision_floor: i64) -> Result<()> {
    let mut q = conn.prepare("SELECT id,config,secret,revision FROM webhook_endpoints")?;
    let rows = q
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    anyhow::ensure!(rows.len() <= MAX_TARGETS, "webhook target limit");
    for (id, raw, secret, revision) in rows {
        anyhow::ensure!(valid_id(&id) && revision >= 0, "webhook identity");
        let mut settings: Settings = serde_json::from_str(&raw)?;
        settings.validate()?;
        let secrets: Secrets = serde_json::from_slice(&vault.unseal(&aad(&id), &secret)?)?;
        url(&secrets.url)?;
        anyhow::ensure!(secret.len() <= 1024 * 1024, "webhook secret size");
        anyhow::ensure!(
            secrets.credential.len() <= 4096
                && (settings.auth == Auth::None || !secrets.credential.is_empty()),
            "webhook credential"
        );
        let hydrated = settings.hydrate(&secrets)?;
        for field in hydrated.fields.iter().chain(hydrated.headers.iter()) {
            anyhow::ensure!(field.value.len() <= 8192, "webhook field size");
        }
        for field in &hydrated.headers {
            reqwest::header::HeaderValue::from_str(&field.value)?;
        }
        render(
            &hydrated,
            &Event::sample_for(settings.language),
            "sample",
            false,
        )?;
        settings.enabled = false;
        conn.execute(
            "UPDATE webhook_endpoints SET config=?2,revision=?3,next_send=0 WHERE id=?1",
            params![
                id,
                serde_json::to_string(&settings)?,
                revision
                    .max(revision_floor)
                    .checked_add(1)
                    .context("revision overflow")?
            ],
        )?;
    }
    let mut q = conn.prepare("SELECT id,endpoint,name,attempts,http_status FROM webhook_jobs")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Option<i64>>(4)?,
        ))
    })? {
        let (id, endpoint, name, attempts, status) = row?;
        anyhow::ensure!(
            valid_id(&id)
                && valid_id(&endpoint)
                && name.len() <= 120
                && (0..=8).contains(&attempts)
                && status.is_none_or(|s| (100..=599).contains(&s)),
            "webhook delivery record"
        );
    }
    conn.execute("UPDATE webhook_jobs SET cancelled=1,error=COALESCE(error,'restored'),claimed_until=0 WHERE delivered IS NULL",[])?;
    Ok(())
}

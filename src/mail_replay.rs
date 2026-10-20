//! Explicit, operator-owned email jobs; automatic alarm/acknowledgement policy
//! never mutates these jobs or the original event's delivery state.
use crate::{dsm::BoundaryError, mail, store::Store};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

pub(crate) const COLUMNS: &str = "id,event_id,actor,revision,recipient,subject,body,message_id,state,created,queued,updated,submitted,attempts,next_try,error";
pub(crate) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mail_replay(
        id TEXT PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        actor TEXT NOT NULL, revision INTEGER NOT NULL, recipient TEXT NOT NULL,
        subject TEXT NOT NULL, body TEXT NOT NULL, message_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK(state IN ('preview','queued','submitted','failed','cancelled')),
        created INTEGER NOT NULL, queued INTEGER, updated INTEGER NOT NULL, submitted INTEGER,
        attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0, error TEXT);
        CREATE INDEX IF NOT EXISTS mail_replay_due ON mail_replay(state,next_try);
        CREATE INDEX IF NOT EXISTS mail_replay_event ON mail_replay(event_id,queued);",
    )?;
    Ok(())
}

pub struct Job {
    pub id: String,
    pub recipient: String,
    pub message_id: String,
    pub subject: String,
    pub body: String,
    pub settings: mail::Settings,
    pub secret: Vec<u8>,
}

pub(crate) fn cancel(conn: &Connection, now: i64) -> Result<()> {
    conn.execute("DELETE FROM mail_replay WHERE state='preview'", [])?;
    conn.execute("UPDATE mail_replay SET state='cancelled',updated=?1,error='mail_conflict' WHERE state='queued'", [now])?;
    Ok(())
}

impl Store {
    pub fn preview_mail_replay(
        &mut self,
        event_id: i64,
        recipient: &str,
        actor: &str,
        now: i64,
    ) -> Result<Value> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (raw, revision): (String, i64) = tx
            .query_row(
                "SELECT config,revision FROM mail_settings WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .context(BoundaryError("mail_replay_not_configured"))?;
        let settings: mail::Settings = serde_json::from_str(&raw)?;
        settings.validate()?;
        anyhow::ensure!(
            settings.recipients.iter().any(|r| r == recipient),
            BoundaryError("mail_replay_recipient_invalid")
        );
        let event = tx.query_row("SELECT id,COALESCE(device_name,device),health,kind,message,created,key,message_context FROM events WHERE id=?1", [event_id], |r| Ok(mail::Event {
            id:r.get(0)?, device:r.get(1)?, health:serde_json::from_str::<String>(&r.get::<_,String>(2)?).unwrap_or_else(|_|"unknown".into()),
            kind:r.get(3)?, message:r.get(4)?, time:r.get(5)?, resource:r.get(6)?, context:r.get::<_,Option<String>>(7)?.and_then(|s|serde_json::from_str(&s).ok()),
        })).optional()?.context(BoundaryError("mail_replay_event_missing"))?;
        let (subject, body) = settings.preview(&event)?;
        anyhow::ensure!(
            subject.len() <= 4096 && body.len() <= 128 * 1024,
            BoundaryError("mail_template_invalid")
        );
        // Expired drafts have never been submitted and are safe to discard.
        tx.execute(
            "DELETE FROM mail_replay WHERE state='preview' AND created<?1",
            [now - 600],
        )?;
        let drafts: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mail_replay WHERE state='preview' AND actor=?1",
            [actor],
            |r| r.get(0),
        )?;
        anyhow::ensure!(drafts < 50, BoundaryError("mail_replay_busy"));
        let id = format!("{:032x}", rand::random::<u128>());
        let message_id = format!("<hm-replay-{id}@hardwaremonitor.invalid>");
        tx.execute("INSERT INTO mail_replay(id,event_id,actor,revision,recipient,subject,body,message_id,state,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'preview',?9,?9)", params![id,event_id,actor,revision,recipient,subject,body,message_id,now])?;
        tx.commit()?;
        Ok(
            json!({"id":id,"event_id":event_id,"event_created":event.time,"recipient":recipient,"subject":subject,"body":body,"revision":revision,"expires":now+600}),
        )
    }

    pub fn enqueue_mail_replay(&mut self, id: &str, actor: &str, now: i64) -> Result<Value> {
        anyhow::ensure!(
            id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()),
            BoundaryError("mail_replay_conflict")
        );
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (event_id, owner, revision, recipient, state, created): (i64,String,i64,String,String,i64) = tx.query_row(
            "SELECT event_id,actor,revision,recipient,state,created FROM mail_replay WHERE id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))
            .optional()?.context(BoundaryError("mail_replay_conflict"))?;
        anyhow::ensure!(owner == actor, BoundaryError("mail_replay_conflict"));
        // The preview ID is an idempotency key, including after a lost response,
        // an SMTP failure or a process restart. Only a new preview creates a job.
        if matches!(state.as_str(), "queued" | "submitted" | "failed") {
            return Ok(json!({"id":id,"state":state}));
        }
        anyhow::ensure!(
            state == "preview" && (0..=600).contains(&(now - created)),
            BoundaryError("mail_replay_conflict")
        );
        let (raw, current): (String, i64) = tx.query_row(
            "SELECT config,revision FROM mail_settings WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let settings: mail::Settings = serde_json::from_str(&raw)?;
        anyhow::ensure!(
            current == revision && settings.recipients.contains(&recipient),
            BoundaryError("mail_replay_conflict")
        );
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mail_replay WHERE state='queued'",
            [],
            |r| r.get(0),
        )?;
        anyhow::ensure!(pending < 50, BoundaryError("mail_replay_busy"));
        tx.execute(
            "UPDATE mail_replay SET state='queued',queued=?2,updated=?2,next_try=?2 WHERE id=?1",
            params![id, now],
        )?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'mail.replay','events',?2,?3)",params![actor,format!("#{event_id} · {recipient} · {id}"),now])?;
        tx.commit()?;
        Ok(json!({"id":id,"state":"queued"}))
    }

    pub fn mail_replay_history(&self, event_id: i64) -> Result<Vec<Value>> {
        let mut q = self.0.prepare("SELECT id,actor,recipient,state,queued,updated,submitted,attempts,error,message_id FROM mail_replay WHERE event_id=?1 AND queued IS NOT NULL ORDER BY queued DESC,id DESC LIMIT 50")?;
        let rows = q.query_map([event_id], |r| Ok(json!({"id":r.get::<_,String>(0)?,"actor":r.get::<_,String>(1)?,"recipient":r.get::<_,String>(2)?,"state":r.get::<_,String>(3)?,"queued":r.get::<_,i64>(4)?,"updated":r.get::<_,i64>(5)?,"submitted":r.get::<_,Option<i64>>(6)?,"attempts":r.get::<_,i64>(7)?,"error":r.get::<_,Option<String>>(8)?,"message_id":r.get::<_,String>(9)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn pending_mail_replay(&self, now: i64) -> Result<Option<Job>> {
        let Some((settings, secret, revision)) = self.mail_settings()? else {
            return Ok(None);
        };
        // Settings.enabled controls automatic delivery only. An administrator
        // explicitly queues each manual submission, including historical faults.
        Ok(self.0.query_row("SELECT id,recipient,message_id,subject,body FROM mail_replay WHERE state='queued' AND revision=?1 AND attempts<8 AND next_try<=?2 ORDER BY next_try,queued,id LIMIT 1",params![revision,now],|r|Ok(Job{id:r.get(0)?,recipient:r.get(1)?,message_id:r.get(2)?,subject:r.get(3)?,body:r.get(4)?,settings,secret})).optional()?)
    }

    pub fn finish_mail_replay(&mut self, job: &Job, error: Option<&str>, now: i64) -> Result<()> {
        let tx = self.0.transaction()?;
        let error = error.map(|e| match e {
            "mail_rejected" => "mail_rejected",
            "mail_config_invalid" => "mail_config_invalid",
            "mail_template_invalid" => "mail_template_invalid",
            "mail_timeout" => "mail_timeout",
            _ => "mail_connection_failed",
        });
        let changed = tx.execute("UPDATE mail_replay SET attempts=attempts+1,updated=?3,submitted=CASE WHEN ?2 IS NULL THEN ?3 ELSE NULL END,state=CASE WHEN ?2 IS NULL THEN 'submitted' WHEN ?2 IN ('mail_rejected','mail_config_invalid','mail_template_invalid') OR attempts>=7 THEN 'failed' ELSE 'queued' END,next_try=?3+MIN(3600,30*(1 << MIN(attempts,7))),error=?2 WHERE id=?1 AND state='queued'",params![job.id,error,now])?;
        if changed != 0 {
            tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) SELECT actor,'mail.replay.result','events',?2,?3 FROM mail_replay WHERE id=?1",params![job.id,format!("{} · {}",job.id,error.unwrap_or("smtp_accepted")),now])?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const RECIPIENT: &str = "alarms@example.invalid";
    #[test]
    fn historical_recovery_hardware_log_and_monitoring_events_can_each_be_selected() {
        let (_dir, mut s) = setup();
        for (id, kind, key, health) in [
            (2, "recovery", "drive", "ok"),
            (3, "hardware_log", "log:1", "critical"),
            (4, "repeat", "collector", "warning"),
        ] {
            s.0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(?1,'removed',?2,?3,?4,'Historical text',100)",params![id,key,kind,serde_json::to_string(health).unwrap()]).unwrap();
            let p = s.preview_mail_replay(id, RECIPIENT, "admin", 200).unwrap();
            assert_eq!(p["event_id"], id);
            assert!(p["body"].as_str().unwrap().contains("Historical text"));
            s.enqueue_mail_replay(p["id"].as_str().unwrap(), "admin", 200)
                .unwrap();
            assert_eq!(s.mail_replay_history(id).unwrap().len(), 1);
        }
    }
    fn setup() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let settings = mail::Settings {
            enabled: false,
            host: "smtp.example.invalid".into(),
            from_address: "nas@example.invalid".into(),
            recipients: vec![RECIPIENT.into(), "other@example.invalid".into()],
            body_template: "{{event_id}}|{{time_utc}}|{{message}}|{{resource}}".into(),
            ..Default::default()
        };
        store.save_mail(&settings, b"", 0, "admin").unwrap();
        store.0.execute("INSERT INTO events(id,device,device_name,key,kind,health,message,created,mail_reason) VALUES(1,'removed-server','Original name','drive','alarm','\"critical\"','Literal {{device}} text',100,'acknowledged')",[]).unwrap();
        (dir, store)
    }
    fn preview(store: &mut Store, now: i64) -> Value {
        store
            .preview_mail_replay(1, RECIPIENT, "admin", now)
            .unwrap()
    }
    #[test]
    fn manual_jobs_use_real_event_and_saved_template_without_rewriting_original_delivery() {
        let (_dir, mut s) = setup();
        let original = s.event_entries(-1).unwrap();
        let p = preview(&mut s, 200);
        assert_eq!(
            p["body"],
            "1|1970-01-01T00:01:40Z|Literal {{device}} text|drive"
        );
        assert_eq!(p["subject"], "[Hardware Monitor] Kritisch – Original name");
        assert_eq!(p["event_created"], 100);
        assert!(s.pending_mail_replay(200).unwrap().is_none());
        let id = p["id"].as_str().unwrap();
        s.enqueue_mail_replay(id, "admin", 201).unwrap();
        s.enqueue_mail_replay(id, "admin", 201).unwrap();
        let job = s.pending_mail_replay(201).unwrap().unwrap();
        assert_eq!(job.recipient, RECIPIENT);
        assert_eq!(job.body, p["body"]);
        s.finish_mail_replay(&job, None, 202).unwrap();
        assert_eq!(s.event_entries(-1).unwrap(), original);
        assert!(s.pending_mail(202).unwrap().is_none());
        assert!(s.pending_desktop(202).unwrap().is_none());
        assert!(s.pending_mail_replay(202).unwrap().is_none());
        let history = s.mail_replay_history(1).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0]["state"], "submitted");
        assert_eq!(history[0]["submitted"], 202);
        assert_eq!(history[0]["queued"], 201);
        assert_eq!(
            s.enqueue_mail_replay(id, "admin", 300).unwrap()["state"],
            "submitted"
        );
    }
    #[test]
    fn retries_and_restarts_keep_content_and_id_but_intentional_new_jobs_get_new_ids() {
        let (dir, mut s) = setup();
        let p = preview(&mut s, 200);
        let id = p["id"].as_str().unwrap().to_owned();
        s.enqueue_mail_replay(&id, "admin", 200).unwrap();
        let first = s.pending_mail_replay(200).unwrap().unwrap();
        s.finish_mail_replay(&first, Some("mail_timeout"), 201)
            .unwrap();
        assert!(s.pending_mail_replay(230).unwrap().is_none());
        drop(s);
        let mut s = Store::open(dir.path()).unwrap();
        let retry = s.pending_mail_replay(231).unwrap().unwrap();
        assert_eq!(retry.message_id, first.message_id);
        assert_eq!(retry.body, first.body);
        assert_eq!(retry.subject, first.subject);
        s.finish_mail_replay(&retry, None, 232).unwrap();
        let next = preview(&mut s, 233);
        s.enqueue_mail_replay(next["id"].as_str().unwrap(), "admin", 233)
            .unwrap();
        let second = s.pending_mail_replay(233).unwrap().unwrap();
        assert_ne!(second.message_id, first.message_id);
        assert_eq!(second.body, first.body);
        assert_eq!(s.mail_replay_history(1).unwrap().len(), 2);
    }
    #[test]
    fn preview_is_owner_bound_expires_and_rejects_foreign_recipients_or_missing_events() {
        let (_dir, mut s) = setup();
        assert!(s
            .preview_mail_replay(1, "arbitrary@example.invalid", "admin", 200)
            .is_err());
        assert!(s.preview_mail_replay(99, RECIPIENT, "admin", 200).is_err());
        let p = preview(&mut s, 200);
        let id = p["id"].as_str().unwrap();
        assert!(s.enqueue_mail_replay(id, "other-admin", 201).is_err());
        assert!(s.enqueue_mail_replay(id, "admin", 801).is_err());
        assert!(s.mail_replay_history(1).unwrap().is_empty());
        assert!(s.pending_mail_replay(801).unwrap().is_none());
    }
    #[test]
    fn settings_changes_cancel_jobs_and_drafts_and_clearing_events_discards_pending_replays() {
        let (_dir, mut s) = setup();
        let p = preview(&mut s, 200);
        s.enqueue_mail_replay(p["id"].as_str().unwrap(), "admin", 200)
            .unwrap();
        let draft = preview(&mut s, 201);
        let (mut settings, secret, revision) = s.mail_settings().unwrap().unwrap();
        settings.body_template = "New {{message}}".into();
        s.save_mail(&settings, &secret, revision, "admin").unwrap();
        assert!(s.pending_mail_replay(300).unwrap().is_none());
        assert_eq!(s.mail_replay_history(1).unwrap()[0]["state"], "cancelled");
        assert!(s
            .enqueue_mail_replay(draft["id"].as_str().unwrap(), "admin", 300)
            .is_err());
        let next = preview(&mut s, 301);
        assert_eq!(next["body"], "New Literal {{device}} text");
        s.enqueue_mail_replay(next["id"].as_str().unwrap(), "admin", 301)
            .unwrap();
        s.clear_events("admin").unwrap();
        assert!(s.pending_mail_replay(302).unwrap().is_none());
        assert!(s.mail_replay_history(1).unwrap().is_empty());
        assert!(s
            .enqueue_mail_replay(next["id"].as_str().unwrap(), "admin", 302)
            .is_err());
    }
    #[test]
    fn permanent_errors_and_exhausted_retries_are_terminal_without_revealing_smtp_responses() {
        let (_dir, mut s) = setup();
        let p = preview(&mut s, 200);
        s.enqueue_mail_replay(p["id"].as_str().unwrap(), "admin", 200)
            .unwrap();
        let job = s.pending_mail_replay(200).unwrap().unwrap();
        s.finish_mail_replay(&job, Some("sensitive remote response"), 201)
            .unwrap();
        assert_eq!(
            s.mail_replay_history(1).unwrap()[0]["error"],
            "mail_connection_failed"
        );
        s.0.execute("UPDATE mail_replay SET attempts=7,next_try=0", [])
            .unwrap();
        s.finish_mail_replay(&job, Some("mail_connection_failed"), 202)
            .unwrap();
        assert_eq!(s.mail_replay_history(1).unwrap()[0]["state"], "failed");
        assert!(s.pending_mail_replay(99999).unwrap().is_none());
        let p = preview(&mut s, 203);
        s.enqueue_mail_replay(p["id"].as_str().unwrap(), "admin", 203)
            .unwrap();
        let job = s.pending_mail_replay(203).unwrap().unwrap();
        s.finish_mail_replay(&job, Some("mail_rejected"), 204)
            .unwrap();
        assert_eq!(s.mail_replay_history(1).unwrap()[0]["state"], "failed");
        assert!(s.pending_mail_replay(99999).unwrap().is_none());
    }
}

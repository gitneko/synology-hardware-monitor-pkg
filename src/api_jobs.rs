//! Actions enter here only after administrator, native session, origin and CSRF checks.
use crate::{
    api::{validate_backup_password, Api, Operation},
    dsm::BoundaryError,
    jobs::Kind,
    store::Store,
};
use anyhow::Result;
use serde_json::{json, Value};
impl Api {
    pub(crate) fn job_operation(
        &self,
        operation: &Operation,
        owner: &str,
        actor: &str,
    ) -> Option<Result<Value>> {
        if !matches!(
            operation,
            Operation::RetentionSave { .. }
                | Operation::CleanupPreview
                | Operation::CleanupRun { .. }
                | Operation::BackupExportStart { .. }
                | Operation::BackupUploadStart
                | Operation::BackupUploadPart { .. }
                | Operation::BackupInspectStart { .. }
                | Operation::BackupRestoreStart { .. }
        ) {
            return None;
        }
        Some((|| match operation {
            Operation::RetentionSave { settings, revision } => {
                anyhow::ensure!(!self.jobs.restoring(), BoundaryError("backup_busy"));
                let mut store = self.store.lock().unwrap();
                anyhow::ensure!(!self.jobs.restoring(), BoundaryError("backup_busy"));
                store.save_retention(settings, *revision, actor)?;
                Ok(json!({"ok":true,"revision":revision+1}))
            }
            Operation::CleanupPreview => {
                let job = self.jobs.create(owner, Kind::Cleanup)?;
                let path = self.state_path();
                self.jobs.run(job.clone(), "cleanup_preview", move |job| {
                    let database = Store::open(&path)?;
                    job.watch_sql(&database.0);
                    let (settings, revision) = database.retention_settings()?;
                    let at = crate::now();
                    let counts = crate::retention::preview(&database.0, &settings, at)?;
                    job.check()?;
                    Ok(json!({"settings":settings,"revision":revision,"at":at,"counts":counts}))
                })?;
                Ok(json!({"ok":true,"job":job.id}))
            }
            Operation::CleanupRun { id, confirm } => {
                anyhow::ensure!(*confirm, BoundaryError("maintenance_confirmation_required"));
                let job = self.jobs.get(id, owner)?;
                anyhow::ensure!(
                    job.kind == Kind::Cleanup && job.ready("cleanup_preview"),
                    BoundaryError("job_invalid")
                );
                let preview = job.result();
                let settings: crate::retention::Settings =
                    serde_json::from_value(preview["settings"].clone())
                        .map_err(|_| BoundaryError("job_invalid"))?;
                let revision = preview["revision"]
                    .as_i64()
                    .ok_or(BoundaryError("job_invalid"))?;
                let at = preview["at"].as_i64().ok_or(BoundaryError("job_invalid"))?;
                anyhow::ensure!(
                    crate::now() - at <= 900
                        && self.store.lock().unwrap().retention_settings()?.1 == revision,
                    BoundaryError("retention_conflict")
                );
                let path = self.state_path();
                let actor = actor.to_owned();
                self.jobs.run(job.clone(), "cleanup", move |job| {
                    let mut database = Store::open(&path)?;
                    job.watch_sql(&database.0);
                    anyhow::ensure!(
                        database.retention_settings()?.1 == revision,
                        BoundaryError("retention_conflict")
                    );
                    database.audit(&actor, "history.cleanup", "application", "started")?;
                    let result = crate::retention::cleanup_at_revision(
                        &mut database.0,
                        &settings,
                        at,
                        revision,
                        |n| job.progress(n, 0),
                    );
                    crate::jobs::Job::unwatch_sql(&database.0);
                    database.audit(
                        &actor,
                        "history.cleanup.result",
                        "application",
                        &match &result {
                            Ok(c) => serde_json::to_string(c)?,
                            Err(e) => crate::dsm::error_code(e).into(),
                        },
                    )?;
                    Ok(json!({"counts":result?}))
                })?;
                Ok(json!({"ok":true,"job":job.id}))
            }
            Operation::BackupExportStart { password } => {
                validate_backup_password(password)?;
                let job = self.jobs.create(owner, Kind::Export)?;
                let path = self.state_path();
                let vault = self.vault.clone();
                let store = self.store.clone();
                let actor = actor.to_owned();
                let password = zeroize::Zeroizing::new(password.clone());
                self.jobs.run(job.clone(), "export", move |job| {
                    let snap = job.dir.join("snapshot.db");
                    crate::stream_archive::snapshot(
                        &path.join("monitor.db"),
                        &snap,
                        &mut |r, b| job.progress(r, b),
                    )?;
                    let result = crate::stream_archive::export(
                        &snap,
                        &job.file(),
                        &vault,
                        &password,
                        &mut |r, b| job.progress(r, b),
                    );
                    let _ = std::fs::remove_file(snap);
                    let result = result?;
                    store
                        .lock()
                        .unwrap()
                        .audit(&actor, "backup.export", "application", "ok")?;
                    Ok(result)
                })?;
                Ok(json!({"ok":true,"job":job.id}))
            }
            Operation::BackupUploadStart => {
                let job = self.jobs.create(owner, Kind::Upload)?;
                Ok(json!({"ok":true,"job":job.id}))
            }
            Operation::BackupUploadPart { id, offset, data } => {
                let bytes = self.jobs.upload(id, owner, *offset, data)?;
                Ok(json!({"ok":true,"bytes":bytes}))
            }
            Operation::BackupInspectStart {
                id,
                bytes,
                password,
            } => {
                validate_backup_password(password)?;
                let job = self.jobs.uploaded(id, owner, *bytes)?;
                let vault = self.vault.clone();
                let store = self.store.clone();
                let password = zeroize::Zeroizing::new(password.clone());
                self.jobs.run(job.clone(), "inspect", move |job| {
                    let stage = job.dir.join("stage");
                    if stage.exists() {
                        std::fs::remove_dir_all(&stage)?;
                    }
                    let mut summary = crate::stream_archive::inspect(
                        &job.file(),
                        &stage,
                        &vault,
                        &password,
                        &mut |r, b| job.progress(r, b),
                    )
                    .map_err(|e| {
                        if crate::dsm::error_code(&e) == "internal_error" {
                            e.context(BoundaryError("backup_invalid"))
                        } else {
                            e
                        }
                    })?;
                    summary["expected_audit"] = json!(store.lock().unwrap().audit_cursor()?);
                    Ok(summary)
                })?;
                Ok(json!({"ok":true,"job":job.id}))
            }
            Operation::BackupRestoreStart {
                id,
                expected_audit,
                confirm,
            } => {
                anyhow::ensure!(*confirm, BoundaryError("maintenance_confirmation_required"));
                let job = self.jobs.get(id, owner)?;
                anyhow::ensure!(
                    job.kind == Kind::Upload
                        && job.ready("inspect")
                        && job.result()["expected_audit"].as_i64() == Some(*expected_audit),
                    BoundaryError("job_invalid")
                );
                let target_path = self.state_path();
                let shared_store = self.store.clone();
                let vault = self.vault.clone();
                let mail = self.mail_gate.clone();
                let receiver = self.snmp_receiver.clone();
                let actor = actor.to_owned();
                let expected = *expected_audit;
                self.jobs.run(job.clone(), "restore", move |job| {
                    let _submission = mail.blocking_lock_owned();
                    let _ingestion =
                        receiver.map(|receiver| receiver.ingestion_gate().blocking_lock_owned());
                    job.check()?;
                    // Drain a poll already writing before the restore phase was announced.
                    // Later polls check the phase again while holding this same mutex.
                    drop(shared_store.lock().unwrap());
                    let source = rusqlite::Connection::open_with_flags(
                        job.dir.join("stage/monitor.db"),
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                    )?;
                    let mut target = Store::open(&target_path)?;
                    let mut rows = 0u64;
                    job.watch_sql(&target.0);
                    let restored =
                        target.restore_staged(&source, &vault, &actor, expected, &mut || {
                            rows += 1;
                            if rows.is_multiple_of(256) {
                                job.progress(rows, 0)?;
                                crate::stream_archive::free_space(&job.dir, 0)?;
                            }
                            job.check()
                        });
                    crate::jobs::Job::unwatch_sql(&target.0);
                    restored?;
                    Ok(json!({"restored":true}))
                })?;
                Ok(json!({"ok":true,"job":job.id}))
            }
            _ => unreachable!(),
        })())
    }
}

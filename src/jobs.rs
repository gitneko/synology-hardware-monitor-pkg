//! Session-bound background jobs. Only opaque IDs cross the API boundary.
use crate::{dsm::BoundaryError, stream_archive};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex,
    },
};

pub const UPLOAD_CHUNK: usize = 512 * 1024;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Export,
    Upload,
    Cleanup,
}
#[derive(Clone, Serialize)]
pub struct Status {
    pub state: &'static str,
    pub phase: String,
    pub rows: u64,
    pub bytes: u64,
    pub result: Value,
    pub code: &'static str,
}
pub struct Job {
    pub id: String,
    pub dir: PathBuf,
    pub kind: Kind,
    owner: String,
    created: i64,
    touched: AtomicI64,
    pub cancel: Arc<AtomicBool>,
    status: Mutex<Status>,
}
impl Job {
    pub fn watch_sql(&self, conn: &rusqlite::Connection) {
        let cancel = self.cancel.clone();
        conn.progress_handler(10000, Some(move || cancel.load(Ordering::Relaxed)));
    }
    pub fn unwatch_sql(conn: &rusqlite::Connection) {
        conn.progress_handler(0, None::<fn() -> bool>);
    }
    pub fn check(&self) -> Result<()> {
        anyhow::ensure!(
            !self.cancel.load(Ordering::Relaxed),
            BoundaryError("job_cancelled")
        );
        Ok(())
    }
    pub fn progress(&self, rows: u64, bytes: u64) -> Result<()> {
        self.check()?;
        self.touched.store(crate::now(), Ordering::Relaxed);
        let mut s = self.status.lock().unwrap();
        s.rows = rows;
        if bytes > 0 {
            s.bytes = bytes;
        }
        Ok(())
    }
    pub fn file(&self) -> PathBuf {
        self.dir.join("archive.hmbackup")
    }
    pub fn ready(&self, phase: &str) -> bool {
        let s = self.status.lock().unwrap();
        s.state == "ready" && s.phase == phase && !self.cancel.load(Ordering::Relaxed)
    }
    pub fn result(&self) -> Value {
        self.status.lock().unwrap().result.clone()
    }
}
pub struct Manager {
    root: PathBuf,
    entries: Mutex<BTreeMap<String, Arc<Job>>>,
    active: AtomicBool,
    restoring: AtomicBool,
}
impl Manager {
    pub fn new(state: &Path) -> Self {
        Self {
            root: state.join("jobs"),
            entries: Mutex::new(BTreeMap::new()),
            active: AtomicBool::new(false),
            restoring: AtomicBool::new(false),
        }
    }
    pub fn reap(&self) -> Result<()> {
        self.collect()
    }
    fn collect(&self) -> Result<()> {
        crate::vault::private_dir(&self.root)?;
        let mut entries = self.entries.lock().unwrap();
        let expired = entries
            .iter()
            .filter(|(_, j)| {
                let state = j.status.lock().unwrap().state;
                matches!(state, "cancelled" | "failed")
                    || (crate::now() - j.touched.load(Ordering::Relaxed) > 3600
                        && state != "running")
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(job) = entries.remove(&id) {
                job.cancel.store(true, Ordering::Relaxed);
                let _ = std::fs::remove_dir_all(&job.dir);
            }
        }
        // A restart loses job credentials/status. Remove only our own orphan job directories.
        for child in std::fs::read_dir(&self.root)? {
            let child = child?;
            let name = child.file_name().to_string_lossy().into_owned();
            if valid_id(&name) && !entries.contains_key(&name) && child.file_type()?.is_dir() {
                let _ = std::fs::remove_dir_all(child.path());
            }
        }
        Ok(())
    }
    pub fn create(&self, owner: &str, kind: Kind) -> Result<Arc<Job>> {
        self.collect()?;
        let mut entries = self.entries.lock().unwrap();
        let superseded = entries
            .iter()
            .filter(|(_, j)| {
                j.owner == owner
                    && kind == Kind::Cleanup
                    && j.kind == Kind::Cleanup
                    && j.status.lock().unwrap().state == "ready"
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in superseded {
            if let Some(job) = entries.remove(&id) {
                let _ = std::fs::remove_dir_all(&job.dir);
            }
        }
        anyhow::ensure!(entries.len() < 8, BoundaryError("jobs_full"));
        let id = format!("{:032x}", rand::random::<u128>());
        let dir = self.root.join(&id);
        crate::vault::private_dir(&dir)?;
        let job = Arc::new(Job {
            id: id.clone(),
            dir,
            kind,
            owner: owner.into(),
            created: crate::now(),
            touched: AtomicI64::new(crate::now()),
            cancel: Arc::new(AtomicBool::new(false)),
            status: Mutex::new(Status {
                state: "new",
                phase: String::new(),
                rows: 0,
                bytes: 0,
                result: Value::Null,
                code: "ok",
            }),
        });
        entries.insert(id, job.clone());
        Ok(job)
    }
    pub fn get(&self, id: &str, owner: &str) -> Result<Arc<Job>> {
        anyhow::ensure!(valid_id(id), BoundaryError("job_invalid"));
        let entries = self.entries.lock().unwrap();
        let job = entries
            .get(id)
            .filter(|j| {
                j.owner == owner
                    && (crate::now() - j.touched.load(Ordering::Relaxed) <= 3600
                        || j.status.lock().unwrap().state == "running")
            })
            .ok_or(BoundaryError("job_invalid"))?;
        Ok(job.clone())
    }
    pub fn status(&self, id: &str, owner: &str) -> Result<Value> {
        let job = self.get(id, owner)?;
        let s = job.status.lock().unwrap().clone();
        Ok(json!({"ok":true,"job":id,"status":s}))
    }
    pub fn list(&self, owner: &str) -> Vec<Value> {
        self.entries.lock().unwrap().values().filter(|j|j.owner==owner && (crate::now()-j.touched.load(Ordering::Relaxed)<=3600||j.status.lock().unwrap().state=="running")).map(|j|json!({"id":j.id,"created":j.created,"kind":match j.kind{Kind::Export=>"export",Kind::Upload=>"upload",Kind::Cleanup=>"cleanup"},"status":j.status.lock().unwrap().clone()})).collect()
    }
    pub fn shutdown(&self) {
        for job in self.entries.lock().unwrap().values() {
            job.cancel.store(true, Ordering::Relaxed);
        }
    }
    pub fn restoring(&self) -> bool {
        self.restoring.load(Ordering::SeqCst)
    }
    pub fn busy(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
    pub fn run(
        self: &Arc<Self>,
        job: Arc<Job>,
        phase: &str,
        work: impl FnOnce(&Job) -> Result<Value> + Send + 'static,
    ) -> Result<()> {
        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            let unused = job.status.lock().unwrap().state == "new" && job.kind != Kind::Upload;
            if unused {
                self.entries.lock().unwrap().remove(&job.id);
                let _ = std::fs::remove_dir_all(&job.dir);
            }
            anyhow::bail!(BoundaryError("backup_busy"));
        }
        {
            let entries = self.entries.lock().unwrap();
            if !entries
                .get(&job.id)
                .is_some_and(|registered| Arc::ptr_eq(registered, &job))
            {
                self.active.store(false, Ordering::SeqCst);
                anyhow::bail!(BoundaryError("job_invalid"));
            }
            let mut s = job.status.lock().unwrap();
            let allowed = match phase {
                "cleanup_preview" | "export" | "automatic_cleanup" => s.state == "new",
                "cleanup" => s.state == "ready" && s.phase == "cleanup_preview",
                "inspect" => s.state == "sealed",
                "restore" => s.state == "ready" && s.phase == "inspect",
                _ => false,
            };
            if !allowed || job.cancel.load(Ordering::Relaxed) {
                self.active.store(false, Ordering::SeqCst);
                anyhow::bail!(BoundaryError("backup_busy"));
            }
            job.cancel.store(false, Ordering::Relaxed);
            s.state = "running";
            s.phase = phase.into();
            s.rows = 0;
            s.code = "ok";
            s.result = Value::Null;
            self.restoring.store(phase == "restore", Ordering::SeqCst);
        }
        let manager = self.clone();
        tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                job.check()?;
                work(&job)
            }));
            job.touched.store(crate::now(), Ordering::Relaxed);
            let mut status = job.status.lock().unwrap();
            match result {
                Ok(Ok(result)) => {
                    job.cancel.store(false, Ordering::Relaxed);
                    status.state = "ready";
                    status.result = result;
                }
                other => {
                    let code = if job.cancel.load(Ordering::Relaxed) {
                        "job_cancelled"
                    } else {
                        match other {
                            Ok(Err(e)) => crate::dsm::error_code(&e),
                            _ => "internal_error",
                        }
                    };
                    status.state = if code == "job_cancelled" {
                        "cancelled"
                    } else {
                        "failed"
                    };
                    status.code = if code == "internal_error" {
                        "job_failed"
                    } else {
                        code
                    };
                    if job.kind == Kind::Export {
                        let _ = std::fs::remove_file(job.file());
                    }
                    // A failed authentication or cancelled import never leaves a usable staging DB.
                    let _ = std::fs::remove_dir_all(job.dir.join("stage"));
                }
            }
            let _ = std::fs::remove_file(job.dir.join("snapshot.db"));
            manager.restoring.store(false, Ordering::SeqCst);
            manager.active.store(false, Ordering::SeqCst);
        });
        Ok(())
    }
    pub fn cancel(&self, id: &str, owner: &str) -> Result<()> {
        let job = self.get(id, owner)?;
        job.cancel.store(true, Ordering::Relaxed);
        let mut s = job.status.lock().unwrap();
        if s.state != "running" {
            s.state = "cancelled";
            s.result = Value::Null;
            s.code = "job_cancelled";
            let _ = std::fs::remove_dir_all(&job.dir);
        }
        Ok(())
    }
    pub fn upload(&self, id: &str, owner: &str, offset: u64, encoded: &str) -> Result<u64> {
        anyhow::ensure!(
            encoded.len() <= UPLOAD_CHUNK.div_ceil(3) * 4,
            BoundaryError("upload_invalid")
        );
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| BoundaryError("upload_invalid"))?;
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() <= UPLOAD_CHUNK,
            BoundaryError("upload_invalid")
        );
        let job = self.get(id, owner)?;
        job.check()?;
        let mut state = job.status.lock().unwrap();
        anyhow::ensure!(
            job.kind == Kind::Upload && matches!(state.state, "new" | "uploading"),
            BoundaryError("upload_invalid")
        );
        let path = job.file();
        let mut file = if path.exists() {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
        } else {
            stream_archive::private_file(&path)?
        };
        let length = file.metadata()?.len();
        if offset < length {
            // Idempotent retransmission after a lost response; no duplicate append.
            anyhow::ensure!(
                offset
                    .checked_add(bytes.len() as u64)
                    .is_some_and(|end| end <= length),
                BoundaryError("upload_invalid")
            );
            file.seek(SeekFrom::Start(offset))?;
            let mut old = vec![0; bytes.len()];
            file.read_exact(&mut old)?;
            anyhow::ensure!(old == bytes, BoundaryError("upload_invalid"));
            return Ok(length);
        }
        anyhow::ensure!(
            offset == length && length.checked_add(bytes.len() as u64).is_some(),
            BoundaryError("upload_invalid")
        );
        stream_archive::free_space(&job.dir, bytes.len() as u64)?;
        file.seek(SeekFrom::End(0))?;
        file.write_all(&bytes)?;
        job.touched.store(crate::now(), Ordering::Relaxed);
        state.state = "uploading";
        state.bytes = length + bytes.len() as u64;
        Ok(state.bytes)
    }
    pub fn uploaded(&self, id: &str, owner: &str, bytes: u64) -> Result<Arc<Job>> {
        let job = self.get(id, owner)?;
        {
            let mut state = job.status.lock().unwrap();
            anyhow::ensure!(
                job.kind == Kind::Upload
                    && matches!(state.state, "uploading" | "sealed" | "failed" | "ready")
                    && job.file().metadata()?.len() == bytes,
                BoundaryError("upload_invalid")
            );
            File::open(job.file())?.sync_all()?;
            state.state = "sealed";
            job.touched.store(crate::now(), Ordering::Relaxed);
        }
        Ok(job)
    }
    pub fn open_download(&self, id: &str) -> Result<(File, u64, Arc<AtomicBool>)> {
        let entries = self.entries.lock().unwrap();
        let job = entries.get(id).ok_or(BoundaryError("job_invalid"))?;
        job.check()?;
        anyhow::ensure!(
            job.kind == Kind::Export && job.status.lock().unwrap().state == "ready",
            BoundaryError("job_invalid")
        );
        let file = File::open(job.file())?;
        let length = file.metadata()?.len();
        Ok((file, length, job.cancel.clone()))
    }
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn jobs_bind_sessions_validate_chunks_and_never_revive_cancelled_work() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Arc::new(Manager::new(dir.path()));
        let job = manager.create("session-a", Kind::Upload).unwrap();
        assert!(manager.get(&job.id, "session-b").is_err());
        assert!(manager.get("../monitor.db", "session-a").is_err());
        let encoded = STANDARD.encode(b"synthetic archive bytes");
        assert!(manager.upload(&job.id, "session-a", 1, &encoded).is_err());
        assert_eq!(
            manager.upload(&job.id, "session-a", 0, &encoded).unwrap(),
            23
        );
        assert_eq!(
            manager.upload(&job.id, "session-a", 0, &encoded).unwrap(),
            23
        );
        assert!(manager
            .upload(
                &job.id,
                "session-a",
                0,
                &STANDARD.encode(b"different bytes")
            )
            .is_err());
        assert!(manager
            .upload(
                &job.id,
                "session-a",
                23,
                &STANDARD.encode(vec![0; UPLOAD_CHUNK + 1])
            )
            .is_err());
        assert!(manager.uploaded(&job.id, "session-a", 24).is_err());
        manager.uploaded(&job.id, "session-a", 23).unwrap();
        assert!(manager.upload(&job.id, "session-a", 23, &encoded).is_err());
        manager
            .run(job.clone(), "inspect", |_| Ok(json!({"expected_audit":0})))
            .unwrap();
        while manager.busy() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(job.ready("inspect"));
        manager.cancel(&job.id, "session-a").unwrap();
        assert!(!job.ready("inspect"));
        assert_eq!(job.result(), Value::Null);
        assert!(!job.dir.exists());
        assert!(manager
            .run(job, "restore", |_| panic!("cancelled job must not run"))
            .is_err());
        assert!(!manager.busy());
    }
    #[tokio::test]
    async fn cancellation_busy_failures_and_expiry_release_private_resources() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Arc::new(Manager::new(dir.path()));
        let job = manager.create("session-a", Kind::Export).unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        manager
            .run(job.clone(), "export", move |job| {
                std::fs::write(job.file(), b"partial archive")?;
                started.send(()).unwrap();
                while job.check().is_ok() {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                job.check()?;
                Ok(Value::Null)
            })
            .unwrap();
        ready
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let busy = manager.create("session-a", Kind::Export).unwrap();
        assert!(manager
            .run(busy.clone(), "export", |_| unreachable!())
            .is_err());
        assert!(!busy.dir.exists());
        assert!(manager.get(&busy.id, "session-a").is_err());
        manager.shutdown();
        while manager.busy() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(!job.file().exists());
        assert_eq!(
            manager.status(&job.id, "session-a").unwrap()["status"]["code"],
            "job_cancelled"
        );
        job.touched.store(crate::now() - 3601, Ordering::Relaxed);
        assert!(manager.get(&job.id, "session-a").is_err());
        manager.create("session-a", Kind::Cleanup).unwrap();
        assert!(!job.dir.exists());
        // Cancelled jobs must not consume capacity for another hour.
        for _ in 0..12 {
            let cancelled = manager.create("session-a", Kind::Upload).unwrap();
            manager.cancel(&cancelled.id, "session-a").unwrap();
        }
        for _ in 0..12 {
            let preview = manager.create("session-a", Kind::Cleanup).unwrap();
            preview.status.lock().unwrap().state = "ready";
        }
        let orphan = manager.root.join("f".repeat(32));
        std::fs::create_dir(&orphan).unwrap();
        std::fs::write(orphan.join("archive.hmbackup"), b"orphan").unwrap();
        manager.create("session-a", Kind::Cleanup).unwrap();
        assert!(!orphan.exists());
    }
}

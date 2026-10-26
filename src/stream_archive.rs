//! File-backed, gzip-compressed logical records in sequenced authenticated AES-GCM frames.
//! Imported SQL is never executed. A staging database is disposable until final authentication.
use crate::{
    archive::{Cell, TABLES},
    dsm::BoundaryError,
    store::Store,
    vault::Vault,
};
use anyhow::{Context, Result};
use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore;
use rusqlite::{
    types::{Value, ValueRef},
    Connection, OpenFlags,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const HEADER: &[u8] = b"HWMON-STREAM-1\n";
pub const MAX_RECORD: usize = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
pub type Progress<'a> = dyn FnMut(u64, u64) -> Result<()> + 'a;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub format: u32,
    pub version: String,
    pub created: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Header { metadata: Metadata },
    Table { name: String },
    Row { cells: Vec<Cell> },
    End { rows: u64 },
}

pub fn free_space(path: &Path, needed: u64) -> Result<()> {
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    anyhow::ensure!(
        unsafe { libc::statvfs(name.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs"
    );
    let stat = unsafe { stat.assume_init() };
    let free = stat.f_bavail.saturating_mul(stat.f_frsize);
    anyhow::ensure!(
        free > needed.saturating_add(32 * 1024 * 1024),
        BoundaryError("storage_full")
    );
    Ok(())
}
pub fn private_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
pub fn snapshot(source: &Path, destination: &Path, progress: &mut Progress<'_>) -> Result<()> {
    free_space(
        destination.parent().context("snapshot directory")?,
        std::fs::metadata(source)?.len(),
    )?;
    private_file(destination)?;
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut target = Connection::open(destination)?;
    target.execute_batch("PRAGMA cache_size=-4096;")?;
    let page_size: u64 = source.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
    loop {
        let pages = backup.progress();
        progress(
            0,
            (pages.pagecount - pages.remaining).max(0) as u64 * page_size,
        )?;
        use rusqlite::backup::StepResult;
        match backup.step(256)? {
            StepResult::Done => break,
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            _ => anyhow::bail!("snapshot state"),
        }
        free_space(destination.parent().unwrap(), 0)?;
    }
    drop(backup);
    drop(target);
    File::open(destination)?.sync_all()?;
    Ok(())
}

// Each frame has its own GCM nonce. Length and envelope are authenticated;
// implicit monotonic sequence numbers prevent insertion, deletion and reordering.
// A separately authenticated empty final frame is mandatory, followed by physical EOF.
fn frame_cipher(
    mode: Mode,
    key: &[u8],
    envelope: &[u8],
    sequence: u64,
    length: u32,
) -> Result<Crypter> {
    let mut nonce: [u8; 12] = envelope[envelope.len() - 12..].try_into()?;
    for (byte, counter) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *byte ^= counter;
    }
    let mut cipher = Crypter::new(Cipher::aes_256_gcm(), mode, key, Some(&nonce))?;
    cipher.aad_update(envelope)?;
    cipher.aad_update(&sequence.to_be_bytes())?;
    cipher.aad_update(&length.to_be_bytes())?;
    Ok(cipher)
}
struct Encrypt<W: Write> {
    output: W,
    key: Zeroizing<[u8; 32]>,
    envelope: Vec<u8>,
    sequence: u64,
    buffer: Zeroizing<Vec<u8>>,
    failed: bool,
}
impl<W: Write> Encrypt<W> {
    fn new(mut output: W, password: &str) -> Result<Self> {
        let mut salt = [0; 16];
        let mut nonce = [0; 12];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let key = crate::archive::key(password, &salt)?;
        let envelope = [HEADER, &salt, &nonce].concat();
        output.write_all(&envelope)?;
        Ok(Self {
            output,
            key,
            envelope,
            sequence: 0,
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK)),
            failed: false,
        })
    }
    fn frame(&mut self) -> Result<()> {
        let next = self
            .sequence
            .checked_add(1)
            .context("archive sequence exhausted")?;
        let length = self.buffer.len() as u32;
        let mut cipher = frame_cipher(
            Mode::Encrypt,
            self.key.as_ref(),
            &self.envelope,
            self.sequence,
            length,
        )?;
        let mut encrypted = vec![0; self.buffer.len() + 16];
        let mut written = cipher.update(&self.buffer, &mut encrypted)?;
        written += cipher.finalize(&mut encrypted[written..])?;
        anyhow::ensure!(written == length as usize, "GCM frame length");
        let mut tag = [0; 16];
        cipher.get_tag(&mut tag)?;
        self.output.write_all(&length.to_be_bytes())?;
        self.output.write_all(&encrypted[..written])?;
        self.output.write_all(&tag)?;
        self.buffer.zeroize();
        self.buffer.clear();
        self.sequence = next;
        Ok(())
    }
    fn finish(mut self) -> Result<W> {
        anyhow::ensure!(!self.failed, "archive writer failed");
        if !self.buffer.is_empty() {
            self.frame()?;
        }
        self.frame()?; // authenticated end marker, with its own nonce
        self.output.flush()?;
        Ok(self.output)
    }
}
impl<W: Write> Write for Encrypt<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("archive writer failed"));
        }
        let count = data.len();
        while !data.is_empty() {
            let n = data.len().min(CHUNK - self.buffer.len());
            self.buffer.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.buffer.len() == CHUNK {
                if let Err(error) = self.frame() {
                    self.failed = true;
                    self.buffer.zeroize();
                    return Err(io::Error::other(error));
                }
            }
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
struct Decrypt {
    input: File,
    key: Zeroizing<[u8; 32]>,
    envelope: Vec<u8>,
    sequence: u64,
    buffer: Zeroizing<Vec<u8>>,
    offset: usize,
    verified: bool,
    failed: bool,
}
impl Decrypt {
    fn new(mut input: File, password: &str) -> Result<Self> {
        let prefix = HEADER.len() + 28;
        anyhow::ensure!(
            input.metadata()?.len() >= prefix as u64 + 20,
            BoundaryError("backup_invalid")
        );
        let mut envelope = vec![0; prefix];
        input.read_exact(&mut envelope)?;
        anyhow::ensure!(
            envelope.starts_with(HEADER),
            BoundaryError("backup_invalid")
        );
        let key = crate::archive::key(password, &envelope[HEADER.len()..HEADER.len() + 16])?;
        Ok(Self {
            input,
            key,
            envelope,
            sequence: 0,
            buffer: Zeroizing::new(Vec::new()),
            offset: 0,
            verified: false,
            failed: false,
        })
    }
    fn frame(&mut self) -> Result<()> {
        let next = self
            .sequence
            .checked_add(1)
            .context("archive sequence exhausted")?;
        let mut size = [0; 4];
        self.input.read_exact(&mut size)?;
        let length = u32::from_be_bytes(size);
        anyhow::ensure!(length as usize <= CHUNK, "archive frame length");
        let mut encrypted = vec![0; length as usize];
        self.input.read_exact(&mut encrypted)?;
        let mut tag = [0; 16];
        self.input.read_exact(&mut tag)?;
        let mut cipher = frame_cipher(
            Mode::Decrypt,
            self.key.as_ref(),
            &self.envelope,
            self.sequence,
            length,
        )?;
        self.buffer.zeroize();
        self.buffer.resize(length as usize + 16, 0);
        self.offset = 0;
        let mut written = cipher.update(&encrypted, &mut self.buffer)?;
        cipher.set_tag(&tag)?;
        written += cipher
            .finalize(&mut self.buffer[written..])
            .context("archive frame authentication failed")?;
        anyhow::ensure!(written == length as usize, "GCM frame length");
        self.buffer.truncate(written);
        self.sequence = next;
        if length == 0 {
            let mut trailing = [0; 1];
            anyhow::ensure!(
                self.input.read(&mut trailing)? == 0,
                "archive trailing bytes"
            );
            self.verified = true;
        }
        Ok(())
    }
}
impl Read for Decrypt {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("archive reader failed"));
        }
        if out.is_empty() || self.verified {
            return Ok(0);
        }
        if self.offset == self.buffer.len() {
            if let Err(error) = self.frame() {
                self.failed = true;
                self.buffer.zeroize();
                return Err(io::Error::other(error));
            }
        }
        if self.verified {
            return Ok(0);
        }
        let n = out.len().min(self.buffer.len() - self.offset);
        out[..n].copy_from_slice(&self.buffer[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

fn write_record(out: &mut impl Write, record: &Record) -> Result<usize> {
    let bytes = Zeroizing::new(serde_json::to_vec(record)?);
    anyhow::ensure!(
        bytes.len() <= MAX_RECORD,
        BoundaryError("backup_record_large")
    );
    out.write_all(&bytes)?;
    out.write_all(b"\n")?;
    Ok(bytes.len() + 1)
}
pub fn export(
    source: &Path,
    destination: &Path,
    vault: &Vault,
    password: &str,
    progress: &mut Progress<'_>,
) -> Result<serde_json::Value> {
    let conn = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.execute_batch("PRAGMA cache_size=-4096;")?;
    let metadata = Metadata {
        format: 6,
        version: env!("CARGO_PKG_VERSION").into(),
        created: crate::now(),
    };
    let file = private_file(destination)?;
    let mut out = GzEncoder::new(
        Encrypt::new(BufWriter::new(file), password)?,
        Compression::fast(),
    );
    let mut bytes = write_record(
        &mut out,
        &Record::Header {
            metadata: metadata.clone(),
        },
    )? as u64;
    let mut count = 0u64;
    for (table, columns) in TABLES {
        bytes += write_record(
            &mut out,
            &Record::Table {
                name: (*table).into(),
            },
        )? as u64;
        let mut q = conn.prepare(&format!("SELECT {columns} FROM {table}"))?;
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            let mut cells = Vec::new();
            for i in 0..columns.split(',').count() {
                let value = row.get_ref(i)?;
                // Reject huge individual records before copying their contents into application memory.
                if let ValueRef::Text(v) | ValueRef::Blob(v) = value {
                    anyhow::ensure!(v.len() <= MAX_RECORD, BoundaryError("backup_record_large"));
                }
                cells.push(match value {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(n) => Cell::Integer(n),
                    ValueRef::Text(v) => Cell::Text(std::str::from_utf8(v)?.into()),
                    ValueRef::Blob(v) => Cell::Blob(base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        v,
                    )),
                    _ => anyhow::bail!("unsupported cell"),
                });
            }
            if *table == "devices" || *table == "mail_settings" {
                let id = if *table == "devices" {
                    match &cells[0] {
                        Cell::Text(s) => s.clone(),
                        _ => anyhow::bail!("device id"),
                    }
                } else {
                    "settings:smtp".into()
                };
                if let Cell::Blob(blob) = &mut cells[2] {
                    if !blob.is_empty() {
                        let sealed = base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            &*blob,
                        )?;
                        let secret = vault.unseal(&id, &sealed)?;
                        blob.zeroize();
                        *blob = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &*secret,
                        );
                    }
                }
                if *table == "devices" {
                    let Cell::Text(raw) = &mut cells[1] else {
                        anyhow::bail!("device config")
                    };
                    let mut device: crate::model::Device = serde_json::from_str(raw)?;
                    if let Some(path) = device.ca_file.take() {
                        let mut pem = String::new();
                        File::open(path)?.take(65537).read_to_string(&mut pem)?;
                        crate::model::validate_certificates(&pem)?;
                        device.ca_pem = Some(pem);
                        *raw = serde_json::to_string(&device)?;
                    }
                }
            }
            bytes += write_record(&mut out, &Record::Row { cells })? as u64;
            count += 1;
            if count.is_multiple_of(256) {
                progress(count, bytes)?;
                free_space(destination.parent().unwrap(), 0)?;
            }
        }
    }
    progress(count, bytes)?;
    write_record(&mut out, &Record::End { rows: count })?;
    let mut file = out.finish()?.finish()?;
    file.flush()?;
    file.get_ref().sync_all()?;
    Ok(
        serde_json::json!({"format":6,"version":metadata.version,"created":metadata.created,"rows":count,"logical_bytes":bytes,"file_bytes":file.get_ref().metadata()?.len()}),
    )
}

fn read_record(reader: &mut impl BufRead) -> Result<Option<Record>> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            anyhow::ensure!(bytes.is_empty(), "incomplete archive record");
            return Ok(None);
        }
        let take = buf
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(buf.len());
        anyhow::ensure!(
            bytes.len() + take <= MAX_RECORD + 1,
            BoundaryError("backup_record_large")
        );
        let ended = buf[take - 1] == b'\n';
        bytes.extend_from_slice(&buf[..take]);
        reader.consume(take);
        if ended {
            return Ok(Some(serde_json::from_slice(&bytes)?));
        }
    }
}
/// Staged values contain locally re-encrypted credentials, never imported SQL or a master key.
pub fn inspect(
    source: &Path,
    stage: &Path,
    vault: &Vault,
    password: &str,
    progress: &mut Progress<'_>,
) -> Result<serde_json::Value> {
    let mut probe = File::open(source)?;
    let mut header = vec![0; HEADER.len()];
    let n = probe.read(&mut header)?;
    drop(probe);
    if n != HEADER.len() || header != HEADER {
        anyhow::ensure!(
            std::fs::metadata(source)?.len() <= crate::archive::MAX_FILE as u64,
            BoundaryError("backup_too_large")
        );
        let file = Zeroizing::new(std::fs::read_to_string(source)?);
        let archive = crate::archive::decrypt(&file, password)?;
        let mut store = Store::open(stage)?;
        store.restore_archive(&archive, vault, "archive-validation", 0)?;
        let mut summary = archive.summary();
        summary["legacy"] = serde_json::json!(true);
        return Ok(summary);
    }
    let store = Store::open(stage)?;
    store.0.execute_batch("PRAGMA cache_size=-4096;")?;
    for (table, _) in TABLES {
        store.0.execute(&format!("DELETE FROM {table}"), [])?;
    }
    let decrypt = Decrypt::new(File::open(source)?, password)?;
    let compressed = GzDecoder::new(BufReader::new(decrypt));
    let mut reader = BufReader::new(compressed);
    let Some(Record::Header { metadata }) = read_record(&mut reader)? else {
        anyhow::bail!("archive metadata")
    };
    anyhow::ensure!(
        metadata.format == 6 && metadata.version.len() <= 80 && metadata.created >= 0,
        "archive version"
    );
    let mut total = 0u64;
    let mut counts = std::collections::BTreeMap::<String, u64>::new();
    let mut marker = read_record(&mut reader)?.context("archive table marker")?;
    for (table, columns) in TABLES.iter().copied() {
        anyhow::ensure!(
            matches!(&marker,Record::Table{name} if name==table),
            "archive table/order"
        );
        let sql = format!(
            "INSERT INTO {table}({columns}) VALUES({})",
            vec!["?"; columns.split(',').count()].join(",")
        );
        let mut rows = 0u64;
        store.0.execute_batch("BEGIN IMMEDIATE")?;
        loop {
            let record = read_record(&mut reader)?.context("archive truncated")?;
            let Record::Row { cells } = record else {
                marker = record;
                break;
            };
            anyhow::ensure!(cells.len() == columns.split(',').count(), "archive columns");
            let mut values = cells.iter().map(Cell::sql).collect::<Result<Vec<_>>>()?;
            anyhow::ensure!(
                values
                    .iter()
                    .all(|v| !matches!(v,Value::Integer(n) if *n<0 || *n>i64::MAX/4)),
                "archive integer"
            );
            if table == "devices" || table == "mail_settings" {
                let id = if table == "devices" {
                    match &values[0] {
                        Value::Text(s) => s.clone(),
                        _ => anyhow::bail!("device id"),
                    }
                } else {
                    "settings:smtp".into()
                };
                if let Value::Blob(secret) = &mut values[2] {
                    anyhow::ensure!(secret.len() <= 4096, "archive credential size");
                    if !secret.is_empty() {
                        let sealed = vault.seal(&id, secret)?;
                        secret.zeroize();
                        *secret = sealed;
                    }
                }
            }
            store.0.execute(&sql, rusqlite::params_from_iter(values))?;
            rows += 1;
            total += 1;
            if total.is_multiple_of(256) {
                progress(total, 0)?;
                free_space(stage, 0)?;
            }
            if total.is_multiple_of(2000) {
                store.0.execute_batch("COMMIT; BEGIN IMMEDIATE")?;
            }
        }
        store.0.execute_batch("COMMIT")?;
        counts.insert(table.into(), rows);
    }
    anyhow::ensure!(
        matches!(marker,Record::End{rows} if rows==total),
        "archive end/count"
    );
    anyhow::ensure!(
        read_record(&mut reader)?.is_none(),
        "archive trailing records"
    );
    let gzip = reader.into_inner();
    let mut compressed = gzip.into_inner();
    // Gzip EOF alone is not authentication: require no trailing compressed bytes
    // and explicitly verify the authenticated final frame and physical EOF.
    anyhow::ensure!(
        compressed.fill_buf()?.is_empty(),
        "archive trailing compressed data"
    );
    anyhow::ensure!(
        compressed.get_ref().verified,
        "archive authentication incomplete"
    );
    progress(total, 0)?;
    anyhow::ensure!(
        !store.0.prepare("PRAGMA foreign_key_check")?.exists([])?,
        "archive foreign keys"
    );
    Ok(
        serde_json::json!({"format":6,"version":metadata.version,"created":metadata.created,"rows":total,"devices":counts.get("devices").copied().unwrap_or(0),"alarms":counts.get("alarm_state").copied().unwrap_or(0),"events":counts.get("events").copied().unwrap_or(0),"hardware_logs":counts.get("hardware_logs").copied().unwrap_or(0)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_archive_roundtrips_secrets_history_and_rejects_damage() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let vault = Vault::open(&{
            crate::vault::private_dir(&source).unwrap();
            source.join("master.key")
        })
        .unwrap();
        let store = Store::open(&source).unwrap();
        store.0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(1,'removed','fan','alarm','\"critical\"','Preserved history',100)",[]).unwrap();
        let snap = dir.path().join("snapshot.db");
        let file = dir.path().join("archive.hmbackup");
        snapshot(&source.join("monitor.db"), &snap, &mut |_, _| Ok(())).unwrap();
        export(
            &snap,
            &file,
            &vault,
            "synthetic-backup-password",
            &mut |_, _| Ok(()),
        )
        .unwrap();
        let stage = dir.path().join("stage");
        let summary = inspect(
            &file,
            &stage,
            &vault,
            "synthetic-backup-password",
            &mut |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(summary["events"], 1);
        let stage = Store::open(&stage).unwrap();
        let mut target = Store::open(&dir.path().join("target")).unwrap();
        target
            .restore_staged(&stage.0, &vault, "admin", 0, &mut || Ok(()))
            .unwrap();
        assert_eq!(
            target
                .0
                .query_row("SELECT message FROM events", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "Preserved history"
        );
        assert!(inspect(
            &file,
            &dir.path().join("wrong"),
            &vault,
            "wrong-backup-password",
            &mut |_, _| Ok(())
        )
        .is_err());
        let mut damaged = std::fs::read(&file).unwrap();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let bad = dir.path().join("damaged.hmbackup");
        std::fs::write(&bad, damaged).unwrap();
        assert!(inspect(
            &bad,
            &dir.path().join("bad"),
            &vault,
            "synthetic-backup-password",
            &mut |_, _| Ok(())
        )
        .is_err());
        assert_eq!(
            target
                .0
                .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn truncated_trailing_oversized_and_cancelled_archives_cannot_replace_live_data() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let mut store = Store::open(&source).unwrap();
        let vault = Vault::open(&source.join("master.key")).unwrap();
        store.0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(1,'removed','fan','alarm','\"critical\"','Keep me',100)",[]).unwrap();
        let snap = dir.path().join("snapshot.db");
        snapshot(&source.join("monitor.db"), &snap, &mut |_, _| Ok(())).unwrap();
        let file = dir.path().join("archive.hmbackup");
        export(
            &snap,
            &file,
            &vault,
            "synthetic-backup-password",
            &mut |_, _| Ok(()),
        )
        .unwrap();
        let bytes = std::fs::read(&file).unwrap();
        for (index, damaged) in [
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), b"trailing"].concat(),
            bytes[..HEADER.len() + 10].to_vec(),
        ]
        .iter()
        .enumerate()
        {
            let bad = dir.path().join(format!("bad-{index}.hmbackup"));
            std::fs::write(&bad, damaged).unwrap();
            assert!(inspect(
                &bad,
                &dir.path().join(format!("stage-{index}")),
                &vault,
                "synthetic-backup-password",
                &mut |_, _| Ok(())
            )
            .is_err());
        }
        let stage_path = dir.path().join("stage");
        inspect(
            &file,
            &stage_path,
            &vault,
            "synthetic-backup-password",
            &mut |_, _| Ok(()),
        )
        .unwrap();
        let stage = Store::open(&stage_path).unwrap();
        // Failure after rows have been inserted must roll back both deletions and inserts.
        let mut calls = 0;
        assert!(store
            .restore_staged(&stage.0, &vault, "admin", 0, &mut || {
                calls += 1;
                anyhow::ensure!(calls < 3, "cancelled");
                Ok(())
            })
            .is_err());
        assert!(calls >= 3);
        assert_eq!(
            store
                .0
                .query_row("SELECT message FROM events", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "Keep me"
        );
        stage
            .0
            .execute("UPDATE history_settings SET config='{}invalid'", [])
            .unwrap();
        assert!(store
            .restore_staged(&stage.0, &vault, "admin", 0, &mut || Ok(()))
            .is_err());
        assert_eq!(
            store
                .0
                .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        // SQLite's real SQLITE_FULL path during final activation must roll back too.
        stage
            .0
            .execute(
                "UPDATE history_settings SET config=?1",
                [serde_json::to_string(&crate::retention::Settings::default()).unwrap()],
            )
            .unwrap();
        for id in 2..300 {
            stage.0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(?1,'removed','fan','alarm','\"critical\"',?2,100)",rusqlite::params![id,"Synthetic disk-full history. ".repeat(500)]).unwrap();
        }
        let pages: u64 = store
            .0
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        store
            .0
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let full = store
            .restore_staged(&stage.0, &vault, "admin", 0, &mut || Ok(()))
            .unwrap_err();
        assert!(
            matches!(full.downcast_ref::<rusqlite::Error>(),Some(rusqlite::Error::SqliteFailure(error,_)) if error.code==rusqlite::ErrorCode::DiskFull),
            "{full:?}"
        );
        assert_eq!(
            store
                .0
                .query_row("SELECT message FROM events", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "Keep me"
        );
        assert!(snapshot(
            &source.join("monitor.db"),
            &dir.path().join("cancel.db"),
            &mut |_, _| anyhow::bail!("cancelled")
        )
        .is_err());
        assert!(export(
            &snap,
            &dir.path().join("cancel.hmbackup"),
            &vault,
            "synthetic-backup-password",
            &mut |_, _| anyhow::bail!("cancelled")
        )
        .is_err());
        assert!(inspect(
            &file,
            &dir.path().join("cancel-stage"),
            &vault,
            "synthetic-backup-password",
            &mut |_, _| anyhow::bail!("cancelled")
        )
        .is_err());
        assert_eq!(
            crate::dsm::error_code(&free_space(dir.path(), u64::MAX).unwrap_err()),
            "storage_full"
        );
        let oversized = vec![b'x'; MAX_RECORD + 2];
        assert_eq!(
            crate::dsm::error_code(&read_record(&mut oversized.as_slice()).err().unwrap()),
            "backup_record_large"
        );
        // The disk-backed reader also accepts the previous encrypted JSON envelope.
        let archive = store.make_archive(&vault).unwrap();
        let legacy = dir.path().join("legacy.hmbackup");
        std::fs::write(
            &legacy,
            crate::archive::encrypt(&archive, "synthetic-backup-password").unwrap(),
        )
        .unwrap();
        assert_eq!(
            inspect(
                &legacy,
                &dir.path().join("legacy-stage"),
                &vault,
                "synthetic-backup-password",
                &mut |_, _| Ok(())
            )
            .unwrap()["legacy"],
            true
        );
    }

    #[test]
    fn online_snapshot_is_consistent_when_source_changes_between_steps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let mut source = Store::open(&path).unwrap();
        {
            let tx = source.0.transaction().unwrap();
            for id in 1..=2200 {
                tx.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(?1,'removed','fan','alarm','\"critical\"',?2,100)",rusqlite::params![id,"Synthetic snapshot padding. ".repeat(150)]).unwrap();
            }
            tx.commit().unwrap();
        }
        let file = dir.path().join("snapshot.db");
        let mut changed = false;
        snapshot(&path.join("monitor.db"), &file, &mut |_, bytes| {
            if bytes > 0 && !changed {
                let tx = source.0.transaction().unwrap();
                tx.execute(
                    "UPDATE events SET message='new consistent value' WHERE id IN(1,2200)",
                    [],
                )
                .unwrap();
                tx.commit().unwrap();
                changed = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(changed);
        let copied = Connection::open(file).unwrap();
        assert_eq!(copied.query_row("SELECT count(*) FROM events WHERE id IN(1,2200) AND message='new consistent value'",[],|r|r.get::<_,i64>(0)).unwrap(),2);
        assert_eq!(
            copied
                .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn authenticated_frames_reject_reordering_dropping_duplication_and_missing_final_marker() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("frames");
        let data = (0..CHUNK * 2 + 123)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let mut writer =
            Encrypt::new(private_file(&file).unwrap(), "synthetic-backup-password").unwrap();
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();
        let mut reader =
            Decrypt::new(File::open(&file).unwrap(), "synthetic-backup-password").unwrap();
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, data);
        assert!(reader.verified);
        let bytes = std::fs::read(&file).unwrap();
        let prefix = HEADER.len() + 28;
        let frame = CHUNK + 20;
        let mut reordered = bytes.clone();
        reordered[prefix..prefix + frame]
            .copy_from_slice(&bytes[prefix + frame..prefix + frame * 2]);
        reordered[prefix + frame..prefix + frame * 2]
            .copy_from_slice(&bytes[prefix..prefix + frame]);
        let dropped = [&bytes[..prefix], &bytes[prefix + frame..]].concat();
        let duplicate = [&bytes[..prefix + frame], &bytes[prefix..]].concat();
        let mut length = bytes.clone();
        length[prefix..prefix + 4].copy_from_slice(&((CHUNK + 1) as u32).to_be_bytes());
        let mut header = bytes.clone();
        header[HEADER.len()] ^= 1;
        let mut damaged = bytes.clone();
        damaged[prefix + 4] ^= 1;
        for (i, bad) in [
            reordered,
            dropped,
            duplicate,
            length,
            header,
            damaged,
            bytes[..bytes.len() - 20].to_vec(),
            [bytes.as_slice(), b"tail"].concat(),
        ]
        .iter()
        .enumerate()
        {
            let path = dir.path().join(format!("bad-frames-{i}"));
            std::fs::write(&path, bad).unwrap();
            let mut reader =
                Decrypt::new(File::open(path).unwrap(), "synthetic-backup-password").unwrap();
            assert!(reader.read_to_end(&mut Vec::new()).is_err());
            assert!(!reader.verified);
            assert!(
                reader.read(&mut [0; 1]).is_err(),
                "failed reader must never release unverified plaintext on retry"
            );
        }
    }

    #[test]
    #[ignore = "large on-disk acceptance test; run explicitly in release mode"]
    fn multi_gib_history_roundtrip_with_bounded_memory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".build");
        std::fs::create_dir_all(&root).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("large-archive-")
            .tempdir_in(root)
            .unwrap();
        let source = dir.path().join("source");
        let mut store = Store::open(&source).unwrap();
        let source_vault = Vault::open(&source.join("master.key")).unwrap();
        let d:crate::model::Device=serde_json::from_value(serde_json::json!({"id":"large-history","name":"Synthetic server","endpoint":"https://bmc.example/","username":"reader","interval_seconds":60,"repeat_seconds":null,"alerts_enabled":false,"ca_file":null})).unwrap();
        store
            .put(
                &d,
                &source_vault
                    .seal(&d.id, b"large-backup-device-password")
                    .unwrap(),
            )
            .unwrap();
        store
            .save_retention(
                &crate::retention::Settings {
                    events_days: 0,
                    hardware_logs_days: 0,
                },
                0,
                "admin",
            )
            .unwrap();
        store
            .0
            .execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=OFF; PRAGMA cache_size=-4096;",
            )
            .unwrap();
        let total = 1_800_000u64;
        let message = "Synthetic controller hardware history. ".repeat(25);
        {
            let tx = store.0.transaction().unwrap();
            let mut insert = tx
                .prepare("INSERT INTO hardware_logs VALUES(?1,?2,?3)")
                .unwrap();
            for i in 0..total {
                let fingerprint = format!("{i:064x}");
                let log = crate::model::HardwareLog {
                    fingerprint: fingerprint.clone(),
                    message: message.clone(),
                    severity: crate::model::Health::Ok,
                    created: Some("2021-07-23T04:46:34Z".into()),
                };
                insert
                    .execute(rusqlite::params![
                        d.id,
                        fingerprint,
                        serde_json::to_string(&log).unwrap()
                    ])
                    .unwrap();
            }
            drop(insert);
            tx.commit().unwrap();
        }
        println!(
            "fixture_rows={total} database_bytes={}",
            source.join("monitor.db").metadata().unwrap().len()
        );
        let snap = dir.path().join("snapshot.db");
        let file = dir.path().join("archive.hmbackup");
        snapshot(&source.join("monitor.db"), &snap, &mut |_, _| Ok(())).unwrap();
        let exported = export(
            &snap,
            &file,
            &source_vault,
            "synthetic-large-backup-password",
            &mut |_, _| Ok(()),
        )
        .unwrap();
        println!("export={exported}");
        assert!(exported["logical_bytes"].as_u64().unwrap() > 2 * 1024 * 1024 * 1024);
        drop(store);
        std::fs::remove_file(snap).unwrap();
        let target_path = dir.path().join("target");
        let mut target = Store::open(&target_path).unwrap();
        let target_vault = Vault::open(&target_path.join("master.key")).unwrap();
        let stage_path = dir.path().join("stage");
        let inspected = inspect(
            &file,
            &stage_path,
            &target_vault,
            "synthetic-large-backup-password",
            &mut |_, _| Ok(()),
        )
        .unwrap();
        println!("inspect={inspected}");
        assert_eq!(inspected["hardware_logs"], total);
        let stage = Store::open(&stage_path).unwrap();
        target
            .restore_staged(&stage.0, &target_vault, "admin", 0, &mut || Ok(()))
            .unwrap();
        assert_eq!(
            target
                .0
                .query_row("SELECT count(*) FROM hardware_logs", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            total
        );
        let (restored, secret, _) = target.get(&d.id).unwrap().unwrap();
        assert!(!restored.enabled);
        assert_eq!(
            &*target_vault.unseal(&d.id, &secret).unwrap(),
            b"large-backup-device-password"
        );
        assert!(source_vault.unseal(&d.id, &secret).is_err());
        assert_eq!(
            target.retention_settings().unwrap().0,
            crate::retention::Settings {
                events_days: 0,
                hardware_logs_days: 0
            }
        );
        println!("PASS full multi-GiB restore; all {total} hardware logs and re-encrypted device credential preserved");
    }
}

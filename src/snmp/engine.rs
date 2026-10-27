//! Local authoritative identity is runtime state, deliberately absent from app archives.
use anyhow::{ensure, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEngine {
    version: u8,
    pub engine_id: String,
    pub boots: u32,
}
fn private_file(file: &std::fs::File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.permissions().mode() & 0o077 == 0,
        "SNMP engine state must be owned and private"
    );
    Ok(())
}
impl LocalEngine {
    /// Call once per daemon start, then share this running identity on rebinds.
    /// Missing state creates a NEW identity; invalid existing state fails closed.
    pub fn start(dir: &Path) -> Result<Self> {
        crate::vault::private_dir(dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join("snmp-engine.lock"))?;
        private_file(&lock)?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
            "SNMP engine lock failed"
        );
        let path = dir.join("snmp-engine.json");
        let mut state = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                private_file(&file)?;
                let mut raw = Vec::new();
                file.take(4097).read_to_end(&mut raw)?;
                ensure!(raw.len() <= 4096, "SNMP engine state size");
                let state: Self = serde_json::from_slice(&raw)?;
                ensure!(
                    state.version == 1 && state.boots > 0 && state.boots < i32::MAX as u32 - 1,
                    "SNMP engine exhausted or unsupported"
                );
                super::config::validate_engine_id(&state.engine_id)?;
                state
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Opaque administratively unique ID, matching the evaluated
                // library's approach; no claim to an assigned enterprise number.
                let mut random = [0u8; 17];
                rand::rngs::OsRng.try_fill_bytes(&mut random)?;
                if random.iter().all(|b| *b == 0) {
                    random[16] = 1;
                }
                if random.iter().all(|b| *b == 0xff) {
                    random[16] = 0xfe;
                }
                Self {
                    version: 1,
                    engine_id: random.iter().map(|b| format!("{b:02x}")).collect(),
                    boots: 0,
                }
            }
            Err(e) => return Err(e.into()),
        };
        state.boots += 1;
        let temp = dir.join(format!("snmp-engine-{:032x}.new", rand::random::<u128>()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(&state)?)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(state)
    }
}

/// The app has durably incremented boots before constructing the library's
/// running clock. Its callback verifies that exact persisted transition; a
/// future rollover fails closed rather than pretending it was persisted.
pub fn authoritative(dir: &Path) -> Result<async_snmp::AuthoritativeEngine> {
    let local = LocalEngine::start(dir)?;
    let id = decode_id(&local.engine_id)?;
    let boots = local.boots;
    let expected = id.clone();
    let persist = move |state: &async_snmp::PersistedAuthoritativeEngine| {
        if state.engine_id() == expected.as_ref() && state.engine_boots() == boots {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "authoritative rollover requires durable restart",
            ))
        }
    };
    Ok(if boots == 1 {
        async_snmp::AuthoritativeEngine::install(id, persist)?
    } else {
        async_snmp::AuthoritativeEngine::restart(
            async_snmp::PersistedAuthoritativeEngine::new(id, boots - 1)?,
            persist,
        )?
    })
}
pub(crate) fn decode_id(value: &str) -> Result<bytes::Bytes> {
    super::config::validate_engine_id(value)?;
    Ok(bytes::Bytes::from(
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn library_clock_matches_already_persisted_first_start_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let first = authoritative(dir.path()).unwrap();
        assert_eq!(first.engine_boots(), 1);
        let second = authoritative(dir.path()).unwrap();
        assert_eq!(second.engine_boots(), 2);
        assert_eq!(first.engine_id(), second.engine_id());
        let raw: LocalEngine =
            serde_json::from_slice(&std::fs::read(dir.path().join("snmp-engine.json")).unwrap())
                .unwrap();
        assert_eq!(raw.boots, second.engine_boots());
    }
}

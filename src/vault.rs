use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

pub struct Vault {
    key: Zeroizing<[u8; 32]>,
}

impl Vault {
    pub fn open(path: &Path) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        let read = || {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
        };
        let mut file = match read() {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                rand::rngs::OsRng.fill_bytes(key.as_mut());
                // A complete key is written before it becomes visible to another process.
                let temp = path.with_extension(format!("new-{}", std::process::id()));
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temp)?;
                f.write_all(key.as_ref())?;
                f.sync_all()?;
                let result = std::fs::hard_link(&temp, path);
                std::fs::remove_file(&temp)?;
                if let Err(e) = result {
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(e.into());
                    }
                }
                read()?
            }
            Err(e) => return Err(e.into()),
        };
        let m = file.metadata()?;
        anyhow::ensure!(
            m.is_file()
                && m.len() == 32
                && m.permissions().mode() & 0o077 == 0
                && m.uid() == unsafe { libc::geteuid() },
            "master key must be an owned, private 32-byte regular file"
        );
        file.read_exact(key.as_mut())?;
        Ok(Self { key })
    }

    pub fn seal(&self, device: &str, secret: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).expect("key size");
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: device.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
        Ok([&nonce[..], &encrypted[..]].concat())
    }

    pub fn unseal(&self, device: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        anyhow::ensure!(blob.len() >= 28, "invalid credential envelope");
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).expect("key size");
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&blob[..12]),
                Payload {
                    msg: &blob[12..],
                    aad: device.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("credential authentication failed"))?;
        Ok(Zeroizing::new(plain))
    }
}

pub fn private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    let m = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() },
        "state directory must be owned by this user"
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .context("protect state directory")?;
    Ok(())
}

pub fn read_secret() -> Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::new());
    std::io::stdin().take(4097).read_to_end(&mut value)?;
    anyhow::ensure!(
        value.len() <= 4096 && !value.is_empty(),
        "password on stdin must contain 1..4096 bytes"
    );
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    anyhow::ensure!(
        !value.is_empty() && std::str::from_utf8(&value).is_ok(),
        "password must be nonempty UTF-8"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_encryption_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master.key");
        let v = Vault::open(&key).unwrap();
        let a = v.seal("a", b"sensitive").unwrap();
        assert_ne!(a, v.seal("a", b"sensitive").unwrap());
        assert_eq!(v.unseal("a", &a).unwrap().as_slice(), b"sensitive");
        assert!(v.unseal("b", &a).is_err());
        let mut corrupt = a;
        corrupt[14] ^= 1;
        assert!(v.unseal("a", &corrupt).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Vault::open(&key).is_err());
    }
}

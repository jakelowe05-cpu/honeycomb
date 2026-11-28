use anyhow::{bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::{Path, PathBuf}};
use zeroize::Zeroize;

const IDENTITY_FILE: &str = "device-identity.hny";
const PUBLIC_FILE: &str = "device.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub public_key: String,
}

pub struct DeviceIdentity {
    secret: [u8; 32],
    pub info: DeviceInfo,
}

impl DeviceIdentity {
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        SigningKey::from_bytes(&self.secret).sign(message).to_bytes()
    }
}

impl Drop for DeviceIdentity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

fn config_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let base = env::var_os("APPDATA").context("Windows APPDATA is unavailable")?;
        return Ok(PathBuf::from(base).join("Honeycomb"));
    }

    #[cfg(not(windows))]
    {
        if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(xdg).join("Honeycomb"));
        }
        let home = env::var_os("HOME").context("HOME is unavailable")?;
        Ok(PathBuf::from(home).join(".config").join("Honeycomb"))
    }
}

fn identity_paths() -> Result<(PathBuf, PathBuf)> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)?;
    Ok((dir.join(IDENTITY_FILE), dir.join(PUBLIC_FILE)))
}

fn info_from_secret(secret: &[u8; 32]) -> DeviceInfo {
    let signing = SigningKey::from_bytes(secret);
    let public = signing.verifying_key().to_bytes();
    let digest = Sha256::digest(public);
    DeviceInfo {
        device_id: hex::encode(&digest[..16]),
        public_key: hex::encode(public),
    }
}

fn write_encrypted_secret(path: &Path, secret: &[u8; 32], passphrase: &str) -> Result<()> {
    let temp = path.with_extension("tmp");
    fs::write(&temp, secret)?;
    let result = crate::vault::encrypt_file(&temp, path, passphrase);
    let _ = fs::remove_file(&temp);
    result
}

fn read_encrypted_secret(path: &Path, passphrase: &str) -> Result<[u8; 32]> {
    let temp = path.with_extension("restore.tmp");
    crate::vault::decrypt_file(path, &temp, passphrase)
        .context("Could not unlock this device identity")?;
    let result = (|| {
        let bytes = fs::read(&temp)?;
        if bytes.len() != 32 {
            bail!("Device identity is damaged or incompatible.");
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Ok(secret)
    })();
    let _ = fs::remove_file(&temp);
    result
}

pub fn exists() -> Result<bool> {
    let (secret, public) = identity_paths()?;
    Ok(secret.exists() && public.exists())
}

pub fn create(passphrase: &str) -> Result<DeviceInfo> {
    if passphrase.len() < 12 {
        bail!("Use a device passphrase of at least 12 characters.");
    }
    let (secret_path, public_path) = identity_paths()?;
    if secret_path.exists() || public_path.exists() {
        bail!("A Honeycomb device identity already exists on this computer.");
    }

    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let info = info_from_secret(&secret);

    let result = (|| {
        write_encrypted_secret(&secret_path, &secret, passphrase)?;
        fs::write(&public_path, serde_json::to_vec_pretty(&info)?)?;
        Ok(info)
    })();

    secret.zeroize();
    if result.is_err() {
        let _ = fs::remove_file(secret_path);
        let _ = fs::remove_file(public_path);
    }
    result
}

pub fn unlock(passphrase: &str) -> Result<DeviceIdentity> {
    let (secret_path, public_path) = identity_paths()?;
    if !secret_path.exists() || !public_path.exists() {
        bail!("This computer does not have a Honeycomb device identity yet.");
    }
    let secret = read_encrypted_secret(&secret_path, passphrase)?;
    let info: DeviceInfo = serde_json::from_slice(&fs::read(public_path)?)
        .context("Device identity metadata is damaged or incompatible")?;
    let calculated = info_from_secret(&secret);
    if calculated.public_key != info.public_key || calculated.device_id != info.device_id {
        bail!("Device identity verification failed.");
    }
    Ok(DeviceIdentity { secret, info })
}

pub fn identity_status() -> Result<Option<DeviceInfo>> {
    let (_, public_path) = identity_paths()?;
    if !public_path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(public_path)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_stable_for_same_key() {
        let mut secret = [0u8; 32];
        secret[0] = 42;
        let a = info_from_secret(&secret);
        let b = info_from_secret(&secret);
        assert_eq!(a.device_id, b.device_id);
        assert_eq!(a.public_key, b.public_key);
    }

    #[test]
    fn device_id_is_128_bit_hex() {
        let secret = [7u8; 32];
        let info = info_from_secret(&secret);
        assert_eq!(info.device_id.len(), 32);
    }
}

use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

const MAGIC: &[u8; 8] = b"HNYB002\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(64 * 1024, 3, 1, Some(32))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .context("Key derivation failed")?;
    Ok(key)
}

fn create_new(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
        .with_context(|| format!("Cannot create {}", path.display()))
}

pub fn encrypt_file(input: &Path, output: &Path, passphrase: &str) -> Result<()> {
    if passphrase.len() < 12 { bail!("Passphrase must be at least 12 characters."); }
    let metadata = fs::metadata(input)?;
    if !metadata.is_file() { bail!("Input must be a regular file."); }
    if metadata.len() > MAX_INPUT_BYTES { bail!("Prototype limit is 512 MiB per file."); }
    let plaintext = fs::read(input).context("Could not read input file")?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let mut file = create_new(output)?;
    file.write_all(MAGIC)?;
    file.write_all(&salt)?;
    file.write_all(&nonce)?;
    file.write_all(&ciphertext)?;
    file.sync_all()?;
    Ok(())
}

pub fn decrypt_file(input: &Path, output: &Path, passphrase: &str) -> Result<()> {
    let container = fs::read(input).context("Could not read encrypted file")?;
    let header_len = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if container.len() < header_len + 16 || &container[..MAGIC.len()] != MAGIC {
        bail!("Not a valid Honeycomb 0.2 encrypted file.");
    }
    let salt_start = MAGIC.len();
    let nonce_start = salt_start + SALT_LEN;
    let body_start = nonce_start + NONCE_LEN;
    let key = derive_key(passphrase, &container[salt_start..nonce_start])?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let plaintext = cipher.decrypt(
        XNonce::from_slice(&container[nonce_start..body_start]),
        &container[body_start..],
    ).map_err(|_| anyhow::anyhow!("Wrong passphrase or damaged file"))?;

    let mut file = create_new(output)?;
    file.write_all(&plaintext)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("honeycomb-{name}-{stamp}"))
    }

    #[test]
    fn encrypts_and_restores_exact_bytes() {
        let source = temp_path("source");
        let encrypted = temp_path("encrypted");
        let restored = temp_path("restored");
        let original = b"Honeycomb local vault test data\0\\x01\\xff";
        fs::write(&source, original).unwrap();
        encrypt_file(&source, &encrypted, "a long test passphrase").unwrap();
        decrypt_file(&encrypted, &restored, "a long test passphrase").unwrap();
        assert_eq!(fs::read(&restored).unwrap(), original);
        let _ = fs::remove_file(source);
        let _ = fs::remove_file(encrypted);
        let _ = fs::remove_file(restored);
    }

    #[test]
    fn wrong_passphrase_does_not_restore() {
        let source = temp_path("source");
        let encrypted = temp_path("encrypted");
        let restored = temp_path("restored");
        fs::write(&source, b"secret").unwrap();
        encrypt_file(&source, &encrypted, "a long test passphrase").unwrap();
        assert!(decrypt_file(&encrypted, &restored, "a different long passphrase").is_err());
        assert!(!restored.exists());
        let _ = fs::remove_file(source);
        let _ = fs::remove_file(encrypted);
    }
}

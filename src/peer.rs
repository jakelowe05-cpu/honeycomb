use anyhow::{bail, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    time::Duration,
};

const MAGIC: &[u8; 8] = b"HNYB002\0";
const MAX_ENCRYPTED_BYTES: u64 = 512 * 1024 * 1024 + 8 + 16 + 24 + 16;

fn is_honeycomb_container(bytes: &[u8]) -> bool {
    bytes.len() >= 8 + 16 + 24 + 16 && &bytes[..8] == MAGIC
}

/// Sends only a Honeycomb-encrypted container. The passphrase is never sent.
pub fn send_encrypted_file(input: &Path, address: &str) -> Result<()> {
    let address: SocketAddr = address.trim().parse().context("Enter an address such as 192.168.1.20:45820")?;
    let metadata = fs::metadata(input).context("Cannot read selected file")?;
    if !metadata.is_file() || metadata.len() > MAX_ENCRYPTED_BYTES {
        bail!("Selected file is not a supported size.");
    }
    let bytes = fs::read(input).context("Cannot read selected file")?;
    if !is_honeycomb_container(&bytes) {
        bail!("Choose a Honeycomb .hny encrypted file. Plain files are not sent.");
    }

    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .context("Could not connect. Check the address, firewall, and that the other computer is listening.")?;
    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    stream.write_all(&(bytes.len() as u64).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// Receives one encrypted container and creates a new file without overwriting.
pub fn receive_one(bind_address: &str, output: &Path) -> Result<()> {
    let listener = TcpListener::bind(bind_address.trim())
        .context("Could not start receiving. Check the port and Windows firewall.")?;
    let (mut stream, _) = listener.accept().context("Could not accept incoming transfer")?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;

    let mut length = [0u8; 8];
    stream.read_exact(&mut length).context("Transfer ended before its header arrived")?;
    let length = u64::from_be_bytes(length);
    if length < (8 + 16 + 24 + 16) as u64 || length > MAX_ENCRYPTED_BYTES {
        bail!("Incoming file has an invalid or unsupported size.");
    }

    let mut bytes = vec![0u8; length as usize];
    stream.read_exact(&mut bytes).context("Transfer was interrupted")?;
    if !is_honeycomb_container(&bytes) {
        bail!("Incoming data is not a valid Honeycomb encrypted-file container.");
    }

    let mut file = OpenOptions::new().write(true).create_new(true).open(output)
        .with_context(|| format!("Cannot create {} (it may already exist)", output.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plaintext_and_accepts_container_header() {
        assert!(!is_honeycomb_container(b"plain text"));
        let mut data = vec![0u8; 8 + 16 + 24 + 16];
        data[..8].copy_from_slice(MAGIC);
        assert!(is_honeycomb_container(&data));
    }
}

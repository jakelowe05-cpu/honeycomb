use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::Builder;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const PAIRING_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME: usize = 64 * 1024;
const PAIRING_CONTEXT: &[u8] = b"HONEYCOMB-PAIRING-V1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub device_id: String,
    pub public_key: String,
    pub address: String,
    pub paired_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PairHello {
    device_id: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PairConfirm {
    code: String,
}

fn config_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("APPDATA").context("Windows APPDATA is unavailable")?;
        return Ok(PathBuf::from(base).join("Honeycomb"));
    }

    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(xdg).join("Honeycomb"));
        }
        let home = std::env::var_os("HOME").context("HOME is unavailable")?;
        Ok(PathBuf::from(home).join(".config").join("Honeycomb"))
    }
}

fn peers_path() -> Result<PathBuf> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)?;
    Ok(dir.join("peers.json"))
}

fn send_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME {
        bail!("Pairing message is too large.");
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn receive_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).context("Pairing connection ended before its message length arrived")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        bail!("Pairing message has an invalid size.");
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).context("Pairing connection ended during a message")?;
    Ok(bytes)
}

fn binding(handshake_hash: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PAIRING_CONTEXT);
    hasher.update(handshake_hash);
    hasher.finalize().into()
}

pub fn verification_code(binding: &[u8; 32]) -> String {
    let value = u32::from_be_bytes([binding[0], binding[1], binding[2], binding[3]]) % 1_000_000;
    format!("{value:06}")
}

fn hello(identity: &crate::identity::DeviceIdentity, binding: &[u8; 32]) -> Result<Vec<u8>> {
    let mut signed = Vec::with_capacity(PAIRING_CONTEXT.len() + binding.len());
    signed.extend_from_slice(PAIRING_CONTEXT);
    signed.extend_from_slice(binding);
    let message = PairHello {
        device_id: identity.info.device_id.clone(),
        public_key: identity.info.public_key.clone(),
        signature: hex::encode(identity.sign(&signed)),
    };
    Ok(serde_json::to_vec(&message)?)
}

fn verify_hello(bytes: &[u8], binding: &[u8; 32]) -> Result<PairHello> {
    let hello: PairHello = serde_json::from_slice(bytes).context("Invalid pairing identity message")?;
    let public_bytes = hex::decode(&hello.public_key).context("Peer public key is not valid hex")?;
    if public_bytes.len() != 32 {
        bail!("Peer public key is not 32 bytes.");
    }
    let public_array: [u8; 32] = public_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid peer public key"))?;
    let key = VerifyingKey::from_bytes(&public_array).context("Peer public key is invalid")?;

    let digest = Sha256::digest(public_array);
    let expected_id = hex::encode(&digest[..16]);
    if hello.device_id != expected_id {
        bail!("Peer device ID does not match its public key.");
    }

    let signature_bytes = hex::decode(&hello.signature).context("Peer signature is not valid hex")?;
    let signature = Signature::from_slice(&signature_bytes).context("Peer signature is invalid")?;
    let mut signed = Vec::with_capacity(PAIRING_CONTEXT.len() + binding.len());
    signed.extend_from_slice(PAIRING_CONTEXT);
    signed.extend_from_slice(binding);
    key.verify(&signed, &signature).context("Peer identity signature verification failed")?;
    Ok(hello)
}

fn save_peer(peer: PeerInfo) -> Result<()> {
    let path = peers_path()?;
    let mut peers = if path.exists() {
        serde_json::from_slice(&fs::read(&path)?).context("Paired-device list is damaged")?
    } else {
        Vec::<PeerInfo>::new()
    };
    peers.retain(|existing: &PeerInfo| existing.device_id != peer.device_id);
    peers.push(peer);
    let temp = path.with_extension("tmp");
    fs::write(&temp, serde_json::to_vec_pretty(&peers)?)?;
    let file = fs::OpenOptions::new().read(true).write(true).open(&temp)?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    Ok(())
}

pub fn list_peers() -> Result<Vec<PeerInfo>> {
    let path = peers_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn pair_with_peer(address: &str, passphrase: &str, expected_code: &str) -> Result<PeerInfo> {
    let identity = crate::identity::unlock(passphrase)?;
    let mut stream = TcpStream::connect(address.trim())
        .context("Could not connect to the Honeycomb peer. Check its address and firewall.")?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let mut noise = Builder::new(PAIRING_PATTERN.parse()?).build_initiator()?;
    let mut message = vec![0u8; MAX_FRAME];
    let mut payload = vec![0u8; MAX_FRAME];

    let length = noise.write_message(&[], &mut message)?;
    send_frame(&mut stream, &message[..length])?;
    let incoming = receive_frame(&mut stream)?;
    noise.read_message(&incoming, &mut payload)?;

    if !noise.is_handshake_finished() {
        bail!("Pairing handshake did not finish.");
    }
    let binding = binding(noise.get_handshake_hash());
    let code = verification_code(&binding);
    if expected_code.trim() != code {
        bail!("Verification code does not match the peer. Pairing cancelled.");
    }

    let mut transport = noise.into_transport_mode()?;
    let hello = hello(&identity, &binding)?;
    let length = transport.write_message(&hello, &mut message)?;
    send_frame(&mut stream, &message[..length])?;

    let incoming = receive_frame(&mut stream)?;
    let received = transport.read_message(&incoming, &mut payload)?;
    let peer = verify_hello(&payload[..received], &binding)?;

    let confirm = serde_json::to_vec(&PairConfirm { code })?;
    let length = transport.write_message(&confirm, &mut message)?;
    send_frame(&mut stream, &message[..length])?;

    let paired_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let peer = PeerInfo {
        device_id: peer.device_id,
        public_key: peer.public_key,
        address: address.trim().to_owned(),
        paired_unix,
    };
    save_peer(peer.clone())?;
    Ok(peer)
}

pub fn accept_pairing(bind_address: &str, passphrase: &str, expected_code: &str) -> Result<PeerInfo> {
    let identity = crate::identity::unlock(passphrase)?;
    let listener = TcpListener::bind(bind_address.trim())
        .context("Could not listen for Honeycomb pairing. Check the address, port, and firewall.")?;
    let (mut stream, remote_address) = listener.accept().context("Could not accept pairing connection")?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let mut noise = Builder::new(PAIRING_PATTERN.parse()?).build_responder()?;
    let mut message = vec![0u8; MAX_FRAME];
    let mut payload = vec![0u8; MAX_FRAME];

    let incoming = receive_frame(&mut stream)?;
    noise.read_message(&incoming, &mut payload)?;
    let length = noise.write_message(&[], &mut message)?;
    send_frame(&mut stream, &message[..length])?;

    if !noise.is_handshake_finished() {
        bail!("Pairing handshake did not finish.");
    }
    let binding = binding(noise.get_handshake_hash());
    let code = verification_code(&binding);
    if expected_code.trim() != code {
        bail!("Verification code does not match the peer. Pairing cancelled.");
    }

    let mut transport = noise.into_transport_mode()?;
    let incoming = receive_frame(&mut stream)?;
    let received = transport.read_message(&incoming, &mut payload)?;
    let peer = verify_hello(&payload[..received], &binding)?;

    let confirm = serde_json::to_vec(&PairConfirm { code: code.clone() })?;
    let length = transport.write_message(&confirm, &mut message)?;
    send_frame(&mut stream, &message[..length])?;

    let incoming = receive_frame(&mut stream)?;
    let received = transport.read_message(&incoming, &mut payload)?;
    let received_confirm: PairConfirm = serde_json::from_slice(&payload[..received])
        .context("Invalid pairing confirmation")?;
    if received_confirm.code != code {
        bail!("Peer confirmation code did not match.");
    }

    let paired_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let peer = PeerInfo {
        device_id: peer.device_id,
        public_key: peer.public_key,
        address: remote_address.to_string(),
        paired_unix,
    };
    save_peer(peer.clone())?;
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_code_is_six_digits_and_stable() {
        let binding = [7u8; 32];
        assert_eq!(verification_code(&binding), "117901");
        assert_eq!(verification_code(&binding), verification_code(&binding));
    }

    #[test]
    fn different_bindings_produce_different_codes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 1;
        b[0] = 2;
        assert_ne!(verification_code(&a), verification_code(&b));
    }
}

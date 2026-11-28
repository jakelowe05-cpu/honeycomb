use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;

const MANIFEST_NAME: &str = "manifest.hny";
const SNAPSHOTS_DIR: &str = "snapshots";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub created_unix: u64,
    pub files: Vec<SnapshotFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub relative_path: String,
    pub encrypted_path: String,
    pub size: u64,
    pub modified_unix: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default)]
pub struct BackupSummary {
    pub scanned: usize,
    pub encrypted: usize,
    pub reused: usize,
    pub errors: usize,
}

fn unix_seconds(metadata: &fs::Metadata) -> u64 {
    metadata.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn file_hash(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn safe_relative(path: &Path, root: &Path) -> Result<String> {
    let rel = path.strip_prefix(root)
        .with_context(|| format!("Cannot make {} relative to {}", path.display(), root.display()))?;
    Ok(rel.to_string_lossy().replace('\\', "/"))
}

fn snapshot_id() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}-{}", now.as_secs(), now.subsec_nanos())
}

fn manifest_path(repo: &Path) -> PathBuf {
    repo.join(MANIFEST_NAME)
}

fn snapshots_path(repo: &Path) -> PathBuf {
    repo.join(SNAPSHOTS_DIR)
}

fn read_snapshots(repo: &Path, passphrase: &str) -> Result<Vec<Snapshot>> {
    let path = manifest_path(repo);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let temp = repo.join(".manifest-restore.json");
    if temp.exists() { fs::remove_file(&temp).ok(); }
    crate::vault::decrypt_file(&path, &temp, passphrase)
        .context("Could not unlock the backup manifest")?;
    let bytes = fs::read(&temp)?;
    fs::remove_file(&temp).ok();
    Ok(serde_json::from_slice(&bytes).context("Backup manifest is damaged or incompatible")?)
}

fn write_snapshots(repo: &Path, snapshots: &[Snapshot], passphrase: &str) -> Result<()> {
    let temp = repo.join(".manifest-new.json");
    fs::write(&temp, serde_json::to_vec_pretty(snapshots)?)?;
    if manifest_path(repo).exists() { fs::remove_file(manifest_path(repo)).ok(); }
    crate::vault::encrypt_file(&temp, &manifest_path(repo), passphrase)?;
    fs::remove_file(temp).ok();
    Ok(())
}

pub fn initialize(repo: &Path) -> Result<()> {
    fs::create_dir_all(snapshots_path(repo))?;
    Ok(())
}

pub fn create_snapshot(source: &Path, repo: &Path, passphrase: &str) -> Result<(Snapshot, BackupSummary)> {
    if !source.is_dir() { bail!("Backup source must be a folder."); }
    initialize(repo)?;
    let mut snapshots = read_snapshots(repo, passphrase)?;
    let id = snapshot_id();
    let snapshot_dir = snapshots_path(repo).join(&id).join("files");
    fs::create_dir_all(&snapshot_dir)?;

    let previous = snapshots.last();
    let mut previous_by_path: HashMap<&str, &SnapshotFile> = HashMap::new();
    if let Some(prev) = previous {
        for f in &prev.files { previous_by_path.insert(&f.relative_path, f); }
    }

    let mut result = Snapshot { id: id.clone(), created_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(), files: Vec::new() };
    let mut summary = BackupSummary::default();

    for entry in WalkDir::new(source).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() { continue; }
        let relative = match safe_relative(path, source) { Ok(v) => v, Err(_) => { summary.errors += 1; continue; } };
        let metadata = match fs::metadata(path) { Ok(v) => v, Err(_) => { summary.errors += 1; continue; } };
        let hash = match file_hash(path) { Ok(v) => v, Err(_) => { summary.errors += 1; continue; } };
        summary.scanned += 1;

        let name = format!("{}.hny", hex::encode(Sha256::digest(relative.as_bytes())));
        let encrypted_rel = format!("files/{}", name);
        let destination = snapshot_dir.join(&name);

        let reused = previous_by_path.get(relative.as_str())
            .filter(|old| old.sha256 == hash)
            .map(|old| snapshots_path(repo).join(&snapshots.last().unwrap().id).join(&old.encrypted_path));

        if let Some(old_path) = reused {
            fs::copy(old_path, &destination).with_context(|| format!("Cannot reuse backup for {}", relative))?;
            summary.reused += 1;
        } else {
            crate::vault::encrypt_file(path, &destination, passphrase)
                .with_context(|| format!("Could not encrypt {}", relative))?;
            summary.encrypted += 1;
        }

        result.files.push(SnapshotFile {
            relative_path: relative,
            encrypted_path: encrypted_rel,
            size: metadata.len(),
            modified_unix: unix_seconds(&metadata),
            sha256: hash,
        });
    }

    snapshots.push(result.clone());
    write_snapshots(repo, &snapshots, passphrase)?;
    Ok((result, summary))
}

pub fn restore_snapshot(repo: &Path, destination: &Path, passphrase: &str, snapshot_id: &str) -> Result<usize> {
    let snapshots = read_snapshots(repo, passphrase)?;
    let snapshot = snapshots.iter().find(|s| s.id == snapshot_id)
        .context("Snapshot not found")?;
    fs::create_dir_all(destination)?;
    let mut restored = 0;
    for file in &snapshot.files {
        let target = destination.join(Path::new(&file.relative_path));
        if let Some(parent) = target.parent() { fs::create_dir_all(parent)?; }
        let encrypted = snapshots_path(repo).join(snapshot_id).join(&file.encrypted_path);
        crate::vault::decrypt_file(&encrypted, &target, passphrase)?;
        restored += 1;
    }
    Ok(restored)
}

pub fn list_snapshots(repo: &Path, passphrase: &str) -> Result<Vec<Snapshot>> {
    read_snapshots(repo, passphrase)
}

pub fn start_auto_backup(source: PathBuf, repo: PathBuf, passphrase: String, stop: Arc<AtomicBool>, tx: mpsc::Sender<String>) {
    thread::spawn(move || {
        let mut last_fingerprint = String::new();
        while !stop.load(Ordering::Relaxed) {
            let fingerprint = match directory_fingerprint(&source) {
                Ok(v) => v,
                Err(e) => { let _ = tx.send(format!("Backup scan failed: {e:#}")); break; }
            };
            if fingerprint != last_fingerprint {
                match create_snapshot(&source, &repo, &passphrase) {
                    Ok((snapshot, summary)) => {
                        last_fingerprint = fingerprint;
                        let _ = tx.send(format!("Snapshot {} created: {} files, {} encrypted, {} reused.", snapshot.id, summary.scanned, summary.encrypted, summary.reused));
                    }
                    Err(e) => { let _ = tx.send(format!("Backup failed: {e:#}")); }
                }
            }
            for _ in 0..60 {
                if stop.load(Ordering::Relaxed) { return; }
                thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    });
}

fn directory_fingerprint(root: &Path) -> Result<String> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file() {
            let m = fs::metadata(entry.path())?;
            entries.push(format!("{}:{}:{}", safe_relative(entry.path(), root)?, m.len(), unix_seconds(&m)));
        }
    }
    entries.sort();
    Ok(hex::encode(Sha256::digest(entries.join("\n").as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("honeycomb-backup-test-{}-{}", name, std::process::id()))
    }

    #[test]
    fn snapshot_and_restore_round_trip() {
        let root = temp_dir("root");
        let repo = temp_dir("repo");
        let restore = temp_dir("restore");
        fs::remove_dir_all(&root).ok(); fs::remove_dir_all(&repo).ok(); fs::remove_dir_all(&restore).ok();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::write(root.join("docs/hello.txt"), b"hello honeycomb").unwrap();

        let (first, _) = create_snapshot(&root, &repo, "a long test passphrase").unwrap();
        fs::write(root.join("docs/hello.txt"), b"changed").unwrap();
        let (second, summary) = create_snapshot(&root, &repo, "a long test passphrase").unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(summary.encrypted, 1);
        assert_eq!(restore_snapshot(&repo, &restore, "a long test passphrase", &first.id).unwrap(), 1);
        assert_eq!(fs::read(restore.join("docs/hello.txt")).unwrap(), b"hello honeycomb");

        fs::remove_dir_all(root).ok(); fs::remove_dir_all(repo).ok(); fs::remove_dir_all(restore).ok();
    }

    #[test]
    fn unchanged_files_are_reused() {
        let root = temp_dir("reuse-root");
        let repo = temp_dir("reuse-repo");
        fs::remove_dir_all(&root).ok(); fs::remove_dir_all(&repo).ok();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), b"same").unwrap();
        create_snapshot(&root, &repo, "a long test passphrase").unwrap();
        let (_, summary) = create_snapshot(&root, &repo, "a long test passphrase").unwrap();
        assert_eq!(summary.reused, 1);
        fs::remove_dir_all(root).ok(); fs::remove_dir_all(repo).ok();
    }
}

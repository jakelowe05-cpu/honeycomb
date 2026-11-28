mod backup;
mod identity;
mod pairing;
mod peer;
mod vault;

use eframe::egui;
use std::{path::PathBuf, sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}}};
use zeroize::Zeroize;

#[derive(Default)]
struct HoneycombApp {
    backup_source: String,
    backup_repo: String,
    backup_passphrase: String,
    backup_confirm: String,
    backup_status: String,
    snapshots: Vec<backup::Snapshot>,
    selected_snapshot: usize,
    auto_running: bool,
    auto_stop: Option<Arc<AtomicBool>>,
    auto_rx: Option<mpsc::Receiver<String>>,
    auto_status: String,
    device_status: String,
    device_id: String,
    peer_address: String,
    pair_bind_address: String,
    pairing_code: String,
    pairing_status: String,
    paired_peers: Vec<pairing::PeerInfo>,
}

impl eframe::App for HoneycombApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.auto_rx {
            while let Ok(message) = rx.try_recv() {
                self.auto_status = message;
            }
        }

        if self.device_status.is_empty() {
            match identity::identity_status() {
                Ok(Some(info)) => {
                    self.device_id = info.device_id;
                    self.device_status = "Device identity is ready.".into();
                }
                Ok(None) => self.device_status = "No device identity created yet.".into(),
                Err(e) => self.device_status = format!("Device identity status unavailable: {e:#}"),
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("HONEYCOMB");
                ui.label("Your data. Your devices. Your people.");
                ui.label("Encrypted backup • snapshots • recovery");
                ui.add_space(12.0);
            });

            ui.group(|ui| {
                ui.heading("BACK UP A FOLDER");
                ui.label("Honeycomb watches this folder and creates encrypted snapshots.");
                ui.horizontal(|ui| {
                    ui.label("Folder to protect");
                    ui.text_edit_singleline(&mut self.backup_source);
                    if ui.button("Browse…").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.backup_source = path.to_string_lossy().to_string();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Honeycomb repository");
                    ui.text_edit_singleline(&mut self.backup_repo);
                    if ui.button("Browse…").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.backup_repo = path.to_string_lossy().to_string();
                        }
                    }
                });
                ui.label("Backup passphrase");
                ui.add(egui::TextEdit::singleline(&mut self.backup_passphrase).password(true));
                ui.label("Confirm passphrase");
                ui.add(egui::TextEdit::singleline(&mut self.backup_confirm).password(true));

                ui.horizontal(|ui| {
                    if ui.button("CREATE SNAPSHOT NOW").clicked() {
                        self.create_snapshot();
                    }
                    if !self.auto_running {
                        if ui.button("START AUTOMATIC BACKUP").clicked() {
                            self.start_automatic_backup();
                        }
                    } else if ui.button("STOP AUTOMATIC BACKUP").clicked() {
                        self.stop_automatic_backup();
                    }
                });

                if !self.backup_status.is_empty() {
                    ui.label(&self.backup_status);
                }
                if !self.auto_status.is_empty() {
                    ui.small(&self.auto_status);
                }
                ui.small("Automatic backup checks for changes about once per minute. The repository should be on a different location from the folder being protected.");
            });

            ui.add_space(10.0);
            ui.group(|ui| {
                ui.heading("THIS DEVICE");
                ui.label(&self.device_status);
                if !self.device_id.is_empty() {
                    ui.label(format!("Device ID: {}", self.device_id));
                    ui.small("This identifier is derived from this device's public cryptographic key.");
                } else if ui.button("CREATE DEVICE IDENTITY").clicked() {
                    if self.backup_passphrase.len() < 12 {
                        self.device_status = "Enter a passphrase of at least 12 characters first.".into();
                    } else {
                        match identity::create(&self.backup_passphrase) {
                            Ok(info) => {
                                self.device_id = info.device_id;
                                self.device_status = "Device identity created and encrypted on this computer.".into();
                            }
                            Err(e) => self.device_status = format!("Could not create device identity: {e:#}"),
                        }
                        self.backup_passphrase.zeroize();
                        self.backup_confirm.zeroize();
                    }
                }
                ui.small("The private device key stays encrypted locally. It is not uploaded to the backup repository.");
            });

            ui.add_space(10.0);
            ui.group(|ui| {
                ui.heading("TRUSTED DEVICES");
                ui.label("Pair directly with another Honeycomb device. Both devices must enter the same one-time pairing code.");
                ui.horizontal(|ui| {
                    ui.label("Pairing code");
                    ui.text_edit_singleline(&mut self.pairing_code);
                    if ui.button("GENERATE CODE").clicked() {
                        self.pairing_code = pairing::generate_pairing_code();
                        self.pairing_status = "Share this code with the other device, then enter the same code there.".into();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Peer address");
                    ui.text_edit_singleline(&mut self.peer_address);
                    if ui.button("PAIR WITH DEVICE").clicked() {
                        if self.pairing_code.trim().len() < 8 {
                            self.pairing_status = "Generate or enter a pairing code of at least 8 characters.".into();
                        } else if self.peer_address.trim().is_empty() {
                            self.pairing_status = "Enter the other device address, for example 192.168.1.20:45820.".into();
                        } else if self.backup_passphrase.len() < 12 {
                            self.pairing_status = "Enter your device passphrase first.".into();
                        } else {
                            match pairing::pair_with_peer(&self.peer_address, &self.backup_passphrase, &self.pairing_code) {
                                Ok(peer) => self.pairing_status = format!("Paired with device {}.", peer.device_id),
                                Err(e) => self.pairing_status = format!("Pairing failed: {e:#}"),
                            }
                            self.backup_passphrase.zeroize();
                            self.backup_confirm.zeroize();
                            self.refresh_peers();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Listen address");
                    ui.text_edit_singleline(&mut self.pair_bind_address);
                    if ui.button("ACCEPT PAIRING").clicked() {
                        if self.pairing_code.trim().len() < 8 {
                            self.pairing_status = "Enter the same pairing code used by the other device.".into();
                        } else if self.backup_passphrase.len() < 12 {
                            self.pairing_status = "Enter your device passphrase first.".into();
                        } else {
                            match pairing::accept_pairing(&self.pair_bind_address, &self.backup_passphrase, &self.pairing_code) {
                                Ok(peer) => self.pairing_status = format!("Paired with device {}.", peer.device_id),
                                Err(e) => self.pairing_status = format!("Pairing failed: {e:#}"),
                            }
                            self.backup_passphrase.zeroize();
                            self.backup_confirm.zeroize();
                            self.refresh_peers();
                        }
                    }
                });
                if !self.pairing_status.is_empty() {
                    ui.label(&self.pairing_status);
                }
                if self.paired_peers.is_empty() {
                    ui.weak("No trusted devices paired yet.");
                } else {
                    ui.label(format!("{} trusted device(s)", self.paired_peers.len()));
                    for peer in &self.paired_peers {
                        ui.small(format!("{} • {}", peer.device_id, peer.address));
                    }
                }
                ui.small("Pairing uses Noise NNpsk0 for encrypted, authenticated key exchange plus the device identity signature. The pairing code is not stored.");
            });

            ui.add_space(10.0);
            ui.group(|ui| {
                ui.heading("TRUSTED DEVICES");
                ui.label("Pair directly with another Honeycomb device. Both devices must use the same one-time pairing code.");
                ui.horizontal(|ui| {
                    ui.label("Pairing code");
                    ui.text_edit_singleline(&mut self.pairing_code);
                    if ui.button("GENERATE CODE").clicked() {
                        self.pairing_code = pairing::generate_pairing_code();
                        self.pairing_status = "Share this code with the other device.".into();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Peer address");
                    ui.text_edit_singleline(&mut self.peer_address);
                    if ui.button("PAIR WITH DEVICE").clicked() {
                        if self.pairing_code.trim().len() < 8 {
                            self.pairing_status = "Use a pairing code of at least 8 characters.".into();
                        } else if self.peer_address.trim().is_empty() {
                            self.pairing_status = "Enter the peer address, for example 192.168.1.20:45820.".into();
                        } else if self.backup_passphrase.len() < 12 {
                            self.pairing_status = "Enter your device passphrase first.".into();
                        } else {
                            match pairing::pair_with_peer(&self.peer_address, &self.backup_passphrase, &self.pairing_code) {
                                Ok(peer) => self.pairing_status = format!("Paired with device {}.", peer.device_id),
                                Err(e) => self.pairing_status = format!("Pairing failed: {e:#}"),
                            }
                            self.backup_passphrase.zeroize();
                            self.backup_confirm.zeroize();
                            self.refresh_peers();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Listen address");
                    ui.text_edit_singleline(&mut self.pair_bind_address);
                    if ui.button("ACCEPT PAIRING").clicked() {
                        if self.pairing_code.trim().len() < 8 {
                            self.pairing_status = "Enter the same pairing code used by the other device.".into();
                        } else if self.backup_passphrase.len() < 12 {
                            self.pairing_status = "Enter your device passphrase first.".into();
                        } else {
                            match pairing::accept_pairing(&self.pair_bind_address, &self.backup_passphrase, &self.pairing_code) {
                                Ok(peer) => self.pairing_status = format!("Paired with device {}.", peer.device_id),
                                Err(e) => self.pairing_status = format!("Pairing failed: {e:#}"),
                            }
                            self.backup_passphrase.zeroize();
                            self.backup_confirm.zeroize();
                            self.refresh_peers();
                        }
                    }
                });
                if !self.pairing_status.is_empty() {
                    ui.label(&self.pairing_status);
                }
                if self.paired_peers.is_empty() {
                    ui.weak("No trusted devices paired yet.");
                } else {
                    ui.label(format!("{} trusted device(s)", self.paired_peers.len()));
                    for peer in &self.paired_peers {
                        ui.small(format!("{} • {}", peer.device_id, peer.address));
                    }
                }
                ui.small("Uses Noise NNpsk0 for encrypted transport and the device identity signature for peer authentication. The pairing code is not stored.");
            });

            ui.add_space(10.0);
            ui.group(|ui| {
                ui.heading("SNAPSHOT HISTORY");
                ui.horizontal(|ui| {
                    if ui.button("REFRESH").clicked() {
                        self.refresh_snapshots();
                    }
                    ui.label(format!("{} snapshot(s)", self.snapshots.len()));
                });

                if self.snapshots.is_empty() {
                    ui.weak("No snapshots loaded yet.");
                } else {
                    let labels: Vec<String> = self.snapshots.iter().map(|s| {
                        format!("{} — {} file(s)", s.id, s.files.len())
                    }).collect();
                    let selected = self.selected_snapshot.min(labels.len().saturating_sub(1));
                    self.selected_snapshot = selected;
                    egui::ComboBox::from_label("Snapshot")
                        .selected_text(&labels[selected])
                        .show_ui(ui, |ui| {
                            for (i, label) in labels.iter().enumerate() {
                                ui.selectable_value(&mut self.selected_snapshot, i, label);
                            }
                        });

                    if ui.button("RESTORE SELECTED SNAPSHOT").clicked() {
                        self.restore_selected();
                    }
                    ui.small("Restore into a new or empty folder so existing files are not overwritten.");
                }
            });

            ui.add_space(10.0);
            ui.group(|ui| {
                ui.heading("WHAT'S NEXT");
                ui.label("✓ Local encrypted snapshots");
                ui.label("✓ Change detection and automatic backup");
                ui.label("✓ Version history and restore");
                ui.label("✓ Device identity");
                ui.label("→ Secure pairing between trusted devices");
                ui.label("→ Encrypted peer storage and replication");
                ui.label("→ Recovery across your devices and trusted people");
            });

            ui.separator();
            ui.small("Honeycomb 0.5 • Safer local backup foundation");
            ui.small("Not security-audited. Keep independent backups of important data.");
        });

        if self.auto_running {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }
}

impl HoneycombApp {
    fn refresh_peers(&mut self) {
        match pairing::list_peers() {
            Ok(peers) => self.paired_peers = peers,
            Err(e) => self.pairing_status = format!("Could not load trusted devices: {e:#}"),
        }
    }

    fn validate_backup_inputs(&self) -> Result<(PathBuf, PathBuf), String> {
        let source = PathBuf::from(self.backup_source.trim());
        let repo = PathBuf::from(self.backup_repo.trim());
        if self.backup_source.trim().is_empty() || self.backup_repo.trim().is_empty() {
            return Err("Choose both the folder to protect and the Honeycomb repository.".into());
        }
        if !source.is_dir() {
            return Err("The folder to protect does not exist.".into());
        }
        if let Err(error) = backup::validate_backup_locations(&source, &repo) {
            return Err(format!("{error:#}"));
        }
        if self.backup_passphrase.len() < 12 {
            return Err("Use a backup passphrase of at least 12 characters.".into());
        }
        if self.backup_passphrase != self.backup_confirm {
            return Err("The backup passphrases do not match.".into());
        }
        Ok((source, repo))
    }

    fn create_snapshot(&mut self) {
        let (source, repo) = match self.validate_backup_inputs() {
            Ok(v) => v,
            Err(e) => { self.backup_status = e; return; }
        };
        match backup::create_snapshot(&source, &repo, &self.backup_passphrase) {
            Ok((snapshot, summary)) => {
                self.backup_status = format!(
                    "Snapshot {} created. {} files scanned, {} encrypted, {} unchanged/reused.",
                    snapshot.id, summary.scanned, summary.encrypted, summary.reused
                );
                self.refresh_snapshots();
            }
            Err(e) => self.backup_status = format!("Backup failed: {e:#}"),
        }
        self.backup_passphrase.zeroize();
        self.backup_confirm.zeroize();
    }

    fn refresh_snapshots(&mut self) {
        let repo = PathBuf::from(self.backup_repo.trim());
        if repo.as_os_str().is_empty() || self.backup_passphrase.len() < 12 {
            self.backup_status = "Enter the repository and backup passphrase to refresh snapshots.".into();
            return;
        }
        match backup::list_snapshots(&repo, &self.backup_passphrase) {
            Ok(items) => {
                self.snapshots = items;
                self.selected_snapshot = self.snapshots.len().saturating_sub(1);
                self.backup_status = format!("Loaded {} snapshot(s).", self.snapshots.len());
            }
            Err(e) => self.backup_status = format!("Could not unlock snapshots: {e:#}"),
        }
        self.backup_passphrase.zeroize();
    }

    fn restore_selected(&mut self) {
        let repo = PathBuf::from(self.backup_repo.trim());
        if repo.as_os_str().is_empty() || self.snapshots.is_empty() {
            self.backup_status = "Load a snapshot first.".into();
            return;
        }
        if self.backup_passphrase.len() < 12 {
            self.backup_status = "Enter the backup passphrase first.".into();
            return;
        }
        let Some(destination) = rfd::FileDialog::new().pick_folder() else {
            self.backup_status = "Restore cancelled.".into();
            return;
        };
        let snapshot_id = self.snapshots[self.selected_snapshot].id.clone();
        match backup::restore_snapshot(&repo, &destination, &self.backup_passphrase, &snapshot_id) {
            Ok(count) => self.backup_status = format!("Restored {} file(s) from snapshot {}.", count, snapshot_id),
            Err(e) => self.backup_status = format!("Restore failed: {e:#}"),
        }
        self.backup_passphrase.zeroize();
    }

    fn start_automatic_backup(&mut self) {
        let (source, repo) = match self.validate_backup_inputs() {
            Ok(v) => v,
            Err(e) => { self.backup_status = e; return; }
        };
        let passphrase = self.backup_passphrase.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        backup::start_auto_backup(source, repo, passphrase, stop.clone(), tx);
        self.auto_stop = Some(stop);
        self.auto_rx = Some(rx);
        self.auto_running = true;
        self.auto_status = "Automatic backup is running.".into();
        self.backup_passphrase.zeroize();
        self.backup_confirm.zeroize();
    }

    fn stop_automatic_backup(&mut self) {
        if let Some(stop) = &self.auto_stop {
            stop.store(true, Ordering::Relaxed);
        }
        self.auto_stop = None;
        self.auto_rx = None;
        self.auto_running = false;
        self.auto_status = "Automatic backup stopped.".into();
    }
}

impl Drop for HoneycombApp {
    fn drop(&mut self) {
        if let Some(stop) = &self.auto_stop {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([820.0, 900.0])
            .with_min_inner_size([680.0, 700.0])
            .with_title("Honeycomb"),
        ..Default::default()
    };
    eframe::run_native(
        "Honeycomb",
        options,
        Box::new(|_cc| Box::<HoneycombApp>::default()),
    )
}

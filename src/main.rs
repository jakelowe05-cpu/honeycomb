mod vault;
mod peer;

use eframe::egui;
use std::{path::PathBuf, sync::mpsc, thread};
use zeroize::Zeroize;

#[derive(Default)]
struct HoneycombApp {
    selected_file: Option<PathBuf>,
    output_file: String,
    passphrase: String,
    confirm_passphrase: String,
    mode: Mode,
    status: String,
    send_file: Option<PathBuf>,
    peer_address: String,
    receive_bind: String,
    receive_output: String,
    peer_status: String,
    peer_rx: Option<mpsc::Receiver<String>>,
}

#[derive(Default, PartialEq, Clone, Copy)]
enum Mode {
    #[default]
    Encrypt,
    Decrypt,
}

impl eframe::App for HoneycombApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.peer_rx {
            if let Ok(message) = rx.try_recv() {
                self.peer_status = message;
                self.peer_rx = None;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("HONEYCOMB");
                ui.label("Your data. Your devices. Your people.");
                ui.add_space(12.0);
            });

            ui.group(|ui| {
                ui.label("LOCAL FILE PROTECTION");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.mode, Mode::Encrypt, "Encrypt a file");
                    ui.selectable_value(&mut self.mode, Mode::Decrypt, "Restore a file");
                });

                if ui.button("Choose file…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.output_file = match self.mode {
                            Mode::Encrypt => format!("{}.hny", path.display()),
                            Mode::Decrypt => {
                                let mut p = path.clone();
                                p.set_extension("restored");
                                p.to_string_lossy().to_string()
                            }
                        };
                        self.selected_file = Some(path);
                        self.status.clear();
                    }
                }

                if let Some(path) = &self.selected_file {
                    ui.label(format!("Selected: {}", path.display()));
                } else {
                    ui.weak("No file selected.");
                }

                ui.add_space(8.0);
                ui.label("Output file path");
                ui.text_edit_singleline(&mut self.output_file);
                ui.add_space(8.0);
                ui.label("Passphrase (minimum 12 characters)");
                ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));

                if self.mode == Mode::Encrypt {
                    ui.label("Confirm passphrase");
                    ui.add(egui::TextEdit::singleline(&mut self.confirm_passphrase).password(true));
                }

                ui.add_space(12.0);
                let action = match self.mode {
                    Mode::Encrypt => "ENCRYPT FILE",
                    Mode::Decrypt => "RESTORE FILE",
                };
                if ui.button(action).clicked() {
                    self.run_action();
                }
                if !self.status.is_empty() {
                    ui.label(&self.status);
                }
            });

            ui.add_space(10.0);
            ui.group(|ui| {
                ui.label("DIRECT ENCRYPTED TRANSFER (LOCAL NETWORK)");
                ui.label("Send only .hny files. Your passphrase is never sent.");

                if ui.button("Choose encrypted file to send…").clicked() {
                    self.send_file = rfd::FileDialog::new()
                        .add_filter("Honeycomb encrypted file", &["hny"])
                        .pick_file();
                }
                if let Some(path) = &self.send_file {
                    ui.label(format!("File: {}", path.display()));
                }
                ui.horizontal(|ui| {
                    ui.label("Friend's address");
                    ui.text_edit_singleline(&mut self.peer_address);
                });
                if ui.button("SEND ENCRYPTED FILE").clicked() {
                    if let Some(path) = self.send_file.clone() {
                        let address = self.peer_address.clone();
                        let (tx, rx) = mpsc::channel();
                        self.peer_rx = Some(rx);
                        self.peer_status = "Connecting and sending…".into();
                        thread::spawn(move || {
                            let message = match peer::send_encrypted_file(&path, &address) {
                                Ok(()) => "Transfer sent. The other computer should have the encrypted file.".to_string(),
                                Err(e) => format!("Send failed: {e:#}"),
                            };
                            let _ = tx.send(message);
                        });
                    } else {
                        self.peer_status = "Choose a .hny file first.".into();
                    }
                }

                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Listen on");
                    if self.receive_bind.is_empty() {
                        self.receive_bind = "0.0.0.0:45820".into();
                    }
                    ui.text_edit_singleline(&mut self.receive_bind);
                });
                ui.horizontal(|ui| {
                    ui.label("Save received file as");
                    ui.text_edit_singleline(&mut self.receive_output);
                    if ui.button("Browse…").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Honeycomb encrypted file", &["hny"])
                            .save_file() {
                            self.receive_output = path.to_string_lossy().to_string();
                        }
                    }
                });
                if ui.button("WAIT FOR ONE FILE").clicked() {
                    let bind = self.receive_bind.clone();
                    let output = PathBuf::from(self.receive_output.trim());
                    let (tx, rx) = mpsc::channel();
                    self.peer_rx = Some(rx);
                    self.peer_status = "Listening for one incoming transfer…".into();
                    thread::spawn(move || {
                        let message = if output.as_os_str().is_empty() {
                            "Choose where to save the received file.".to_string()
                        } else {
                            match peer::receive_one(&bind, &output) {
                                Ok(()) => format!("Received encrypted file: {}", output.display()),
                                Err(e) => format!("Receive failed: {e:#}"),
                            }
                        };
                        let _ = tx.send(message);
                    });
                }
                if !self.peer_status.is_empty() {
                    ui.label(&self.peer_status);
                }
                ui.small("Both computers must be able to reach each other on the same network. Allow Honeycomb through Windows Firewall on private networks only.");
            });

            ui.add_space(8.0);
            ui.separator();
            ui.small("Prototype 0.3 • Local encryption + one-file LAN transfer");
            ui.small("Not security-audited. Keep separate backups of important files.");
        });
        if self.peer_rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
    }
}

impl HoneycombApp {
    fn run_action(&mut self) {
        let Some(input) = self.selected_file.clone() else {
            self.status = "Choose a file first.".into();
            return;
        };
        let output = PathBuf::from(self.output_file.trim());
        if self.output_file.trim().is_empty() {
            self.status = "Choose an output filename.".into();
            return;
        }
        if output.exists() {
            self.status = "That output file already exists. Choose a different name.".into();
            return;
        }
        if self.passphrase.len() < 12 {
            self.status = "Use a passphrase of at least 12 characters.".into();
            return;
        }
        if self.mode == Mode::Encrypt && self.passphrase != self.confirm_passphrase {
            self.status = "The passphrases do not match.".into();
            return;
        }

        let result = match self.mode {
            Mode::Encrypt => vault::encrypt_file(&input, &output, &self.passphrase),
            Mode::Decrypt => vault::decrypt_file(&input, &output, &self.passphrase),
        };
        self.passphrase.zeroize();
        self.confirm_passphrase.zeroize();
        self.status = match result {
            Ok(()) => format!("Success. Output saved to: {}", output.display()),
            Err(e) => format!("Could not complete operation: {e:#}"),
        };
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 820.0])
            .with_min_inner_size([620.0, 650.0])
            .with_title("Honeycomb"),
        ..Default::default()
    };
    eframe::run_native(
        "Honeycomb",
        options,
        Box::new(|_cc| Box::<HoneycombApp>::default()),
    )
}

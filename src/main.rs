mod vault;

use eframe::egui;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Default)]
struct HoneycombApp {
    selected_file: Option<PathBuf>,
    output_file: String,
    passphrase: String,
    confirm_passphrase: String,
    mode: Mode,
    status: String,
}

#[derive(Default, PartialEq, Clone, Copy)]
enum Mode {
    #[default]
    Encrypt,
    Decrypt,
}

impl eframe::App for HoneycombApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
            });

            if !self.status.is_empty() {
                ui.add_space(12.0);
                ui.label(&self.status);
            }

            ui.add_space(12.0);
            ui.separator();
            ui.small("Prototype 0.2 • Local encryption only • No peer networking yet");
            ui.small("Not security-audited. Keep separate backups of important files.");
        });
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
            .with_inner_size([620.0, 520.0])
            .with_min_inner_size([520.0, 440.0])
            .with_title("Honeycomb"),
        ..Default::default()
    };
    eframe::run_native(
        "Honeycomb",
        options,
        Box::new(|_cc| Box::<HoneycombApp>::default()),
    )
}

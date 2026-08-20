#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ring;

use app::{start_scan, AppState, Phase};
use eframe::egui;
use powerscanner_core::scan::result::Verdict;
use powerscanner_core::scan::targets::ScanPreset;
use std::time::{Duration, Instant};

#[derive(Default)]
struct PowerScannerApp {
    state: AppState,
}

impl PowerScannerApp {
    fn begin(&mut self, preset: ScanPreset) {
        self.state.rx = Some(start_scan(preset));
        self.state.stream.clear();
        self.state.results.clear();
        self.state.malicious_seen = 0;
        self.state.errors_seen = 0;
        self.state.filter.clear();
        self.state.only_bad = false;
        self.state.started_at = Some(Instant::now());
        self.state.elapsed = Duration::ZERO;
        self.state.phase = Phase::Scanning {
            done: 0,
            total: 0,
            preset,
        };
    }
}

impl eframe::App for PowerScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.pump();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);
                ui.heading("PowerScanner");
                ui.add_space(8.0);

                let phase_label = match &self.state.phase {
                    Phase::Idle => "ready".to_string(),
                    Phase::Scanning { preset, .. } => {
                        format!("scanning ({})", preset_name(*preset))
                    }
                    Phase::Done {
                        malicious, errors, ..
                    } => format!("done - {malicious} malicious, {errors} errors"),
                    Phase::Failed(_) => "error".to_string(),
                };
                ring::circular_progress(ui, self.state.fraction(), &phase_label);
                ui.add_space(10.0);

                let scanning = matches!(self.state.phase, Phase::Scanning { .. });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!scanning, egui::Button::new("Quick"))
                        .clicked()
                    {
                        self.begin(ScanPreset::Quick);
                    }
                    if ui
                        .add_enabled(!scanning, egui::Button::new("Full"))
                        .clicked()
                    {
                        self.begin(ScanPreset::Full);
                    }
                    if ui
                        .add_enabled(!scanning, egui::Button::new("Risky Spots"))
                        .clicked()
                    {
                        self.begin(ScanPreset::RiskySpots);
                    }
                });
            });

            ui.add_space(10.0);
            let (scanned, malicious, errors) = match &self.state.phase {
                Phase::Scanning { done, .. } => {
                    (*done, self.state.malicious_seen, self.state.errors_seen)
                }
                Phase::Done {
                    scanned,
                    malicious,
                    errors,
                } => (*scanned, *malicious, *errors),
                _ => (0, 0, 0),
            };
            ui.horizontal(|ui| {
                metric(ui, "Scanned", &scanned.to_string());
                metric(ui, "Malicious", &malicious.to_string());
                metric(ui, "Errors", &errors.to_string());
                metric(
                    ui,
                    "Elapsed",
                    &format!("{}s", self.state.elapsed_duration().as_secs()),
                );
            });

            ui.separator();
            match &self.state.phase {
                Phase::Done { .. } => self.result_table(ui),
                Phase::Failed(error) => {
                    ui.colored_label(egui::Color32::RED, error);
                }
                _ => self.file_stream(ui),
            }
        });

        if matches!(self.state.phase, Phase::Scanning { .. }) {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
    }
}

impl PowerScannerApp {
    fn file_stream(&self, ui: &mut egui::Ui) {
        ui.label("Files being scanned");
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .max_height(160.0)
            .show(ui, |ui| {
                if self.state.stream.is_empty() {
                    ui.weak("idle - press a scan button");
                }
                for line in &self.state.stream {
                    let prefix = match line.verdict {
                        Verdict::Malicious => "!",
                        Verdict::Error => "x",
                        Verdict::Clean => "+",
                    };
                    ui.monospace(format!("{prefix} {}", line.path));
                }
            });
    }

    fn result_table(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.state.filter);
            ui.checkbox(&mut self.state.only_bad, "Bad only");
        });
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .show(ui, |ui| {
                egui::Grid::new("results")
                    .striped(true)
                    .num_columns(4)
                    .show(ui, |ui| {
                        ui.strong("Verdict");
                        ui.strong("Path");
                        ui.strong("Detection");
                        ui.strong("Type");
                        ui.end_row();
                        for result in self.state.visible_results() {
                            match result.verdict {
                                Verdict::Malicious => {
                                    ui.colored_label(egui::Color32::RED, "bad");
                                }
                                Verdict::Clean => {
                                    ui.weak("clean");
                                }
                                Verdict::Error => {
                                    ui.colored_label(egui::Color32::YELLOW, "error");
                                }
                            }
                            ui.label(&result.path);
                            ui.label(
                                result
                                    .findings
                                    .first()
                                    .map(|finding| finding.label.clone())
                                    .or_else(|| result.error.clone())
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.label(
                                result
                                    .findings
                                    .first()
                                    .map(|finding| format!("{:?}", finding.kind))
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.end_row();
                        }
                    });
            });
    }
}

fn preset_name(preset: ScanPreset) -> &'static str {
    match preset {
        ScanPreset::Quick => "quick",
        ScanPreset::Full => "full",
        ScanPreset::RiskySpots => "risky",
    }
}

fn metric(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.weak(label);
        ui.heading(value);
    });
    ui.add_space(24.0);
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "PowerScanner",
        options,
        Box::new(|_creation_context| Ok(Box::new(PowerScannerApp::default()))),
    )
}

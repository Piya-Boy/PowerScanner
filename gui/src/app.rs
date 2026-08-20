use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant};

use powerscanner_core::scan::result::{ScanResult, Verdict};
use powerscanner_core::scan::targets::ScanPreset;

/// Max lines kept in the live file stream (bounded memory).
pub const STREAM_CAP: usize = 200;
const CHANNEL_CAP: usize = 256;
const DISCONNECTED_MESSAGE: &str = "scan worker disconnected";

pub enum ScanMsg {
    /// One file finished scanning.
    FileScanned {
        path: String,
        verdict: Verdict,
    },
    Progress {
        done: usize,
        total: usize,
    },
    Finished {
        results: Vec<ScanResult>,
        malicious: usize,
        errors: usize,
    },
    Error(String),
}

#[derive(PartialEq, Debug, Clone, Default)]
pub enum Phase {
    #[default]
    Idle,
    Scanning {
        done: usize,
        total: usize,
        preset: ScanPreset,
    },
    Done {
        scanned: usize,
        malicious: usize,
        errors: usize,
    },
    Failed(String),
}

/// One row in the live stream.
#[derive(Clone, PartialEq, Debug)]
pub struct StreamLine {
    pub path: String,
    pub verdict: Verdict,
}

#[derive(Default)]
pub struct AppState {
    pub phase: Phase,
    pub stream: VecDeque<StreamLine>,
    pub results: Vec<ScanResult>,
    pub rx: Option<Receiver<ScanMsg>>,
    pub filter: String,
    pub only_bad: bool,
    /// Cumulative malicious count; unlike `stream`, this is never truncated.
    pub malicious_seen: usize,
    /// Cumulative scan-error count; unlike `stream`, this is never truncated.
    pub errors_seen: usize,
    pub started_at: Option<Instant>,
    pub elapsed: Duration,
}

impl AppState {
    /// Drain pending scan messages into state. Call once per frame.
    pub fn pump(&mut self) {
        if matches!(self.phase, Phase::Scanning { .. }) && self.started_at.is_none() {
            self.started_at = Some(Instant::now());
            self.elapsed = Duration::ZERO;
        }

        if let Some(rx) = self.rx.take() {
            let mut disconnected = false;

            loop {
                match rx.try_recv() {
                    Ok(msg) => reduce(self, msg),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }

            if disconnected {
                if !matches!(self.phase, Phase::Done { .. } | Phase::Failed(_)) {
                    reduce(self, ScanMsg::Error(DISCONNECTED_MESSAGE.to_string()));
                }
            } else {
                self.rx = Some(rx);
            }
        }
    }

    /// Fraction 0.0..=1.0 for the ring, or 0.0 when not scanning.
    pub fn fraction(&self) -> f32 {
        match self.phase {
            Phase::Scanning { done, total, .. } if total > 0 => done as f32 / total as f32,
            Phase::Done { .. } => 1.0,
            _ => 0.0,
        }
    }

    /// Rows visible in the result table after filter + "bad only".
    pub fn visible_results(&self) -> Vec<&ScanResult> {
        let query = self.filter.to_lowercase();

        self.results
            .iter()
            .filter(|result| !self.only_bad || !matches!(result.verdict, Verdict::Clean))
            .filter(|result| {
                if query.is_empty() {
                    return true;
                }

                let findings = result
                    .findings
                    .iter()
                    .map(|finding| finding.label.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let error = result.error.as_deref().unwrap_or_default();
                format!("{} {findings} {error}", result.path.to_lowercase())
                    .to_lowercase()
                    .contains(&query)
            })
            .collect()
    }

    pub fn elapsed_duration(&self) -> Duration {
        self.started_at
            .map(|started_at| started_at.elapsed())
            .unwrap_or(self.elapsed)
    }
}

pub fn reduce(state: &mut AppState, msg: ScanMsg) {
    match msg {
        ScanMsg::FileScanned { path, verdict } => {
            match verdict {
                Verdict::Malicious => {
                    state.malicious_seen = state.malicious_seen.saturating_add(1);
                }
                Verdict::Error => {
                    state.errors_seen = state.errors_seen.saturating_add(1);
                }
                Verdict::Clean => {}
            }
            state.stream.push_back(StreamLine { path, verdict });
            while state.stream.len() > STREAM_CAP {
                state.stream.pop_front();
            }
        }
        ScanMsg::Progress { done, total } => {
            let preset = match &state.phase {
                Phase::Scanning { preset, .. } => *preset,
                _ => ScanPreset::Quick,
            };
            state.phase = Phase::Scanning {
                done,
                total,
                preset,
            };
        }
        ScanMsg::Finished {
            results,
            malicious,
            errors,
        } => {
            state.malicious_seen = malicious;
            state.errors_seen = errors;
            state.phase = Phase::Done {
                scanned: results.len(),
                malicious,
                errors,
            };
            state.results = results;
            state.stream.clear();
            finish_elapsed(state);
        }
        ScanMsg::Error(error) => {
            state.phase = Phase::Failed(error);
            finish_elapsed(state);
        }
    }
}

fn finish_elapsed(state: &mut AppState) {
    if let Some(started_at) = state.started_at.take() {
        state.elapsed = started_at.elapsed();
    }
}

/// Start a background scan; returns the receiver the UI pumps each frame.
pub fn start_scan(preset: ScanPreset) -> Receiver<ScanMsg> {
    let (tx, rx) = mpsc::sync_channel(CHANNEL_CAP);
    let worker_tx = tx.clone();

    if let Err(error) = std::thread::Builder::new()
        .name("powerscanner-scan".to_string())
        .spawn(move || run_scan(preset, worker_tx))
    {
        let _ = tx.try_send(ScanMsg::Error(format!("start scan worker: {error}")));
    }

    rx
}

fn run_scan(preset: ScanPreset, tx: SyncSender<ScanMsg>) {
    use powerscanner_core::scan::{engine, targets, walk};
    use powerscanner_core::signatures::{hashdb::HashDb, rules::compile_from_sources, store};

    let roots = targets::roots_for(preset);
    let entries = walk::enumerate(&roots);

    let sig_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|directory| directory.join("signatures")))
        .unwrap_or_else(|| std::path::PathBuf::from("signatures"));
    let bundle = match store::load_or_import(&sig_dir) {
        Ok(bundle) => bundle,
        Err(error) => {
            send_error(&tx, format!("load signature bundle: {error}"));
            return;
        }
    };
    let hashes = HashDb::from_text(&bundle.hashes_text);
    let rules = match compile_from_sources(&bundle.rule_sources) {
        Ok(rules) => rules,
        Err(error) => {
            send_error(&tx, format!("rule compile: {error}"));
            return;
        }
    };

    let config = engine::ScanConfig {
        hashes: &hashes,
        rules: &rules,
        now_unix: now_unix(),
    };
    let cache = powerscanner_core::scan::incremental::ScanCache::new();
    let result_tx = tx.clone();
    let results =
        engine::scan_all_with_progress(&config, &entries, &cache, move |result, done, total| {
            send_result_update(&result_tx, result, done, total);
        });

    let malicious = results
        .iter()
        .filter(|result| matches!(result.verdict, Verdict::Malicious))
        .count();
    let errors = results
        .iter()
        .filter(|result| matches!(result.verdict, Verdict::Error))
        .count();

    if let Err(error) = persist_results(&results) {
        send_error(&tx, format!("persist signed results: {error}"));
        return;
    }

    let _ = tx.send(ScanMsg::Finished {
        results,
        malicious,
        errors,
    });
}

fn persist_results(results: &[ScanResult]) -> powerscanner_core::error::PsResult<()> {
    use powerscanner_core::crypto::derive_machine_key;
    use powerscanner_core::scan::paths::RESULT_SALT;
    use powerscanner_core::sink::{create_jsonl_sink, ResultSink};

    let key = derive_machine_key(RESULT_SALT)?;
    let directory = powerscanner_core::scan::paths::results_dir();
    powerscanner_core::scan::paths::prepare_results_dir(&directory)?;
    let path = directory.join("results.jsonl");
    let mut sink = create_jsonl_sink(&path, key)?;

    for result in results {
        sink.write(result)?;
    }

    Ok(())
}

fn send_result_update(tx: &SyncSender<ScanMsg>, result: &ScanResult, done: usize, total: usize) {
    if tx
        .send(ScanMsg::FileScanned {
            path: result.path.clone(),
            verdict: result.verdict.clone(),
        })
        .is_ok()
    {
        let _ = tx.try_send(ScanMsg::Progress { done, total });
    }
}

fn send_error(tx: &SyncSender<ScanMsg>, message: String) {
    let _ = tx.send(ScanMsg::Error(message));
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use powerscanner_core::scan::result::{DetectionKind, Finding};
    use std::sync::mpsc;

    fn result(path: &str, malicious: bool) -> ScanResult {
        ScanResult {
            path: path.to_string(),
            size: 1,
            modified_unix: 0,
            sha256: String::new(),
            verdict: if malicious {
                Verdict::Malicious
            } else {
                Verdict::Clean
            },
            findings: if malicious {
                vec![Finding {
                    kind: DetectionKind::Yara,
                    label: "EvilRule".to_string(),
                }]
            } else {
                Vec::new()
            },
            error: None,
            scanned_at_unix: 0,
        }
    }

    #[test]
    fn progress_sets_scanning_and_keeps_preset() {
        let mut state = AppState {
            phase: Phase::Scanning {
                done: 0,
                total: 0,
                preset: ScanPreset::Full,
            },
            ..AppState::default()
        };

        reduce(&mut state, ScanMsg::Progress { done: 3, total: 10 });

        assert_eq!(
            state.phase,
            Phase::Scanning {
                done: 3,
                total: 10,
                preset: ScanPreset::Full,
            }
        );
        assert_eq!(state.fraction(), 0.3);
    }

    #[test]
    fn finished_moves_results_and_clears_stream() {
        let mut state = AppState::default();
        state.stream.push_back(StreamLine {
            path: "x".to_string(),
            verdict: Verdict::Clean,
        });

        reduce(
            &mut state,
            ScanMsg::Finished {
                results: vec![result("a", true), result("b", false)],
                malicious: 1,
                errors: 0,
            },
        );

        assert_eq!(
            state.phase,
            Phase::Done {
                scanned: 2,
                malicious: 1,
                errors: 0,
            }
        );
        assert_eq!(state.results.len(), 2);
        assert!(state.stream.is_empty());
        assert_eq!(state.fraction(), 1.0);
        assert!(state.started_at.is_none());
    }

    #[test]
    fn stream_is_capped() {
        let mut state = AppState::default();

        for index in 0..(STREAM_CAP + 50) {
            reduce(
                &mut state,
                ScanMsg::FileScanned {
                    path: format!("f{index}"),
                    verdict: Verdict::Clean,
                },
            );
        }

        assert_eq!(state.stream.len(), STREAM_CAP);
        assert_ne!(state.stream.front().unwrap().path, "f0");
    }

    #[test]
    fn malicious_count_survives_stream_cap() {
        let mut state = AppState::default();

        for index in 0..(STREAM_CAP + 50) {
            reduce(
                &mut state,
                ScanMsg::FileScanned {
                    path: format!("f{index}"),
                    verdict: if index % 2 == 0 {
                        Verdict::Malicious
                    } else {
                        Verdict::Clean
                    },
                },
            );
        }

        assert_eq!(state.malicious_seen, (STREAM_CAP + 50).div_ceil(2));
        assert_eq!(
            state
                .stream
                .iter()
                .filter(|line| matches!(line.verdict, Verdict::Malicious))
                .count(),
            STREAM_CAP / 2
        );
    }

    #[test]
    fn error_sets_failed() {
        let mut state = AppState {
            started_at: Some(Instant::now()),
            ..AppState::default()
        };

        reduce(&mut state, ScanMsg::Error("boom".to_string()));

        assert_eq!(state.phase, Phase::Failed("boom".to_string()));
        assert!(state.started_at.is_none());
    }

    #[test]
    fn disconnected_receiver_fails_scan_and_is_removed() {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        let mut state = AppState {
            phase: Phase::Scanning {
                done: 0,
                total: 1,
                preset: ScanPreset::Quick,
            },
            rx: Some(receiver),
            ..AppState::default()
        };

        state.pump();

        assert_eq!(state.phase, Phase::Failed(DISCONNECTED_MESSAGE.to_string()));
        assert!(state.rx.is_none());
    }

    #[test]
    fn result_update_sends_file_before_progress() {
        let (sender, receiver) = mpsc::sync_channel(2);
        let scan_result = result("sample", true);

        send_result_update(&sender, &scan_result, 1, 1);

        assert!(matches!(
            receiver.recv(),
            Ok(ScanMsg::FileScanned { path, verdict })
                if path == "sample" && matches!(verdict, Verdict::Malicious)
        ));
        assert!(matches!(
            receiver.recv(),
            Ok(ScanMsg::Progress { done: 1, total: 1 })
        ));
    }

    #[test]
    fn visible_results_filters_and_bad_only() {
        let mut state = AppState {
            results: vec![result(r"C:\evil.exe", true), result(r"C:\clean.txt", false)],
            ..AppState::default()
        };

        state.filter = "evil".to_string();
        assert_eq!(state.visible_results().len(), 1);

        state.filter.clear();
        state.only_bad = true;
        assert_eq!(state.visible_results().len(), 1);
        assert!(matches!(
            state.visible_results()[0].verdict,
            Verdict::Malicious
        ));

        state.only_bad = false;
        assert_eq!(state.visible_results().len(), 2);
    }

    #[test]
    fn error_result_is_visible_and_counted_separately() {
        let mut error = result(r"C:\locked.exe", false);
        error.verdict = Verdict::Error;
        error.error = Some("access denied".to_string());
        let mut state = AppState {
            results: vec![error.clone()],
            only_bad: true,
            ..AppState::default()
        };

        reduce(
            &mut state,
            ScanMsg::FileScanned {
                path: error.path.clone(),
                verdict: error.verdict.clone(),
            },
        );

        assert_eq!(state.malicious_seen, 0);
        assert_eq!(state.errors_seen, 1);
        assert_eq!(state.visible_results(), vec![&error]);

        state.filter = "access denied".to_string();
        assert_eq!(state.visible_results(), vec![&error]);
    }
}

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

use rayon::prelude::*;

use crate::error::{PsError, PsResult};
use crate::scan::incremental::ScanCache;
use crate::scan::result::{DetectionKind, Finding, ScanResult, Verdict};
use crate::scan::walk::FileEntry;
use crate::signatures::hashdb::HashDb;
use crate::signatures::rules::RuleSet;

const MAX_YARA_BYTES: u64 = 16 * 1024 * 1024;

pub struct ScanConfig<'a> {
    pub hashes: &'a HashDb,
    pub rules: &'a RuleSet,
    pub now_unix: i64,
}

pub fn scan_entry(cfg: &ScanConfig<'_>, entry: &FileEntry) -> PsResult<ScanResult> {
    let sha256 = crate::scan::hasher::sha256_file(&entry.path)?;
    let mut findings = Vec::new();

    if cfg.hashes.contains(&sha256) {
        findings.push(Finding {
            kind: DetectionKind::Hash,
            label: "blacklist".to_string(),
        });
    }

    if entry.size <= MAX_YARA_BYTES {
        match read_yara_bytes(&entry.path, entry.size).and_then(|data| cfg.rules.scan_bytes(&data))
        {
            Ok(rule_ids) => {
                for rule_id in rule_ids {
                    findings.push(Finding {
                        kind: DetectionKind::Yara,
                        label: rule_id,
                    });
                }
            }
            Err(error) if findings.is_empty() => return Err(error),
            Err(_) => {}
        }
    }

    let verdict = if findings.is_empty() {
        Verdict::Clean
    } else {
        Verdict::Malicious
    };

    Ok(ScanResult {
        path: entry.path.to_string_lossy().into_owned(),
        size: entry.size,
        modified_unix: entry.mtime_unix,
        sha256,
        verdict,
        findings,
        scanned_at_unix: cfg.now_unix,
    })
}

pub fn scan_all<F>(
    cfg: &ScanConfig<'_>,
    entries: &[FileEntry],
    cache: &ScanCache,
    on_progress: F,
) -> Vec<ScanResult>
where
    F: Fn(usize, usize) + Sync,
{
    scan_all_with_progress(cfg, entries, cache, |_, done, total| {
        on_progress(done, total);
    })
}

/// Scan entries in parallel and report each completed result in order of
/// completion. The callback is serialized so its progress values are
/// monotonic even though hashing and YARA work runs in parallel.
pub fn scan_all_with_progress<F>(
    cfg: &ScanConfig<'_>,
    entries: &[FileEntry],
    cache: &ScanCache,
    on_result: F,
) -> Vec<ScanResult>
where
    F: Fn(&ScanResult, usize, usize) + Sync,
{
    let entries_to_scan: Vec<&FileEntry> = entries
        .iter()
        .filter(|entry| {
            !cache.is_unchanged(&entry.path.to_string_lossy(), entry.size, entry.mtime_unix)
        })
        .collect();
    let total = entries_to_scan.len();
    let progress = Mutex::new(0usize);

    entries_to_scan
        .into_par_iter()
        .map(|entry| {
            let result = scan_entry(cfg, entry).unwrap_or_else(|_| ScanResult {
                path: entry.path.to_string_lossy().into_owned(),
                size: entry.size,
                modified_unix: entry.mtime_unix,
                sha256: String::new(),
                verdict: Verdict::Clean,
                findings: Vec::new(),
                scanned_at_unix: cfg.now_unix,
            });
            let mut completed = match progress.lock() {
                Ok(completed) => completed,
                Err(poisoned) => poisoned.into_inner(),
            };
            *completed += 1;
            on_result(&result, *completed, total);

            result
        })
        .collect()
}

fn read_yara_bytes(path: &Path, expected_size: u64) -> PsResult<Vec<u8>> {
    let file = File::open(path)?;
    let maximum_with_sentinel = MAX_YARA_BYTES + 1;
    let mut data = Vec::with_capacity(expected_size as usize);

    file.take(maximum_with_sentinel).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_YARA_BYTES {
        return Err(PsError::Yara(
            "scan input exceeds the 16 MiB YARA limit".to_string(),
        ));
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::scan::hasher::sha256_file;
    use crate::signatures::rules::compile_from_sources;

    const RULE: &str = r#"rule Marker { strings: $a = "MALWARE_MARKER" condition: $a }"#;

    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempFile(PathBuf);

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn write_temp(bytes: &[u8]) -> (TempFile, FileEntry) {
        let process_id = std::process::id();

        loop {
            let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("powerscanner-engine-{process_id}-{counter}.bin"));
            let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create temporary test file: {error}"),
            };
            file.write_all(bytes).unwrap();
            drop(file);

            let metadata = fs::metadata(&path).unwrap();
            let entry = FileEntry {
                path: path.clone(),
                size: metadata.len(),
                mtime_unix: 1,
            };

            return (TempFile(path), entry);
        }
    }

    fn config<'a>(hashes: &'a HashDb, rules: &'a RuleSet) -> ScanConfig<'a> {
        ScanConfig {
            hashes,
            rules,
            now_unix: 100,
        }
    }

    #[test]
    fn yara_marker_is_malicious() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes = HashDb::from_text("");
        let (_file, entry) = write_temp(b"xx MALWARE_MARKER xx");

        let result = scan_entry(&config(&hashes, &rules), &entry).unwrap();

        assert_eq!(result.verdict, Verdict::Malicious);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.kind == DetectionKind::Yara && finding.label == "Marker"));
    }

    #[test]
    fn hash_blacklist_is_malicious() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes =
            HashDb::from_text("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let (_file, entry) = write_temp(b"abc");

        let result = scan_entry(&config(&hashes, &rules), &entry).unwrap();

        assert_eq!(result.verdict, Verdict::Malicious);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.kind == DetectionKind::Hash));
    }

    #[test]
    fn clean_file_is_clean() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes = HashDb::from_text("");
        let (_file, entry) = write_temp(b"harmless content");

        let result = scan_entry(&config(&hashes, &rules), &entry).unwrap();

        assert_eq!(result.verdict, Verdict::Clean);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_all_skips_unchanged_entries() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes = HashDb::from_text("");
        let (_cached_file, cached_entry) = write_temp(b"cached content");
        let (_scanned_file, scanned_entry) = write_temp(b"harmless content");
        let mut cache = ScanCache::new();
        cache.record(
            &cached_entry.path.to_string_lossy(),
            cached_entry.size,
            cached_entry.mtime_unix,
        );
        let progress = Mutex::new(Vec::new());

        let results = scan_all(
            &config(&hashes, &rules),
            &[cached_entry, scanned_entry],
            &cache,
            |completed, total| progress.lock().unwrap().push((completed, total)),
        );

        assert_eq!(results.len(), 1);
        assert_eq!(*progress.lock().unwrap(), vec![(1, 1)]);
    }

    #[test]
    fn preserves_hash_detection_when_yara_read_exceeds_cap() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let (file, entry) = write_oversized_temp();
        let hashes = HashDb::from_text(&sha256_file(&entry.path).unwrap());

        let result = scan_entry(&config(&hashes, &rules), &entry).unwrap();

        assert_eq!(result.verdict, Verdict::Malicious);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.kind == DetectionKind::Hash));
        drop(file);
    }

    fn write_oversized_temp() -> (TempFile, FileEntry) {
        let process_id = std::process::id();

        loop {
            let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "powerscanner-engine-large-{process_id}-{counter}.bin"
            ));
            let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create temporary test file: {error}"),
            };
            let block = [0_u8; 64 * 1024];
            let mut remaining = MAX_YARA_BYTES + 1;

            while remaining > 0 {
                let written = remaining.min(block.len() as u64) as usize;
                file.write_all(&block[..written]).unwrap();
                remaining -= written as u64;
            }
            drop(file);

            return (
                TempFile(path.clone()),
                FileEntry {
                    path,
                    size: 0,
                    mtime_unix: 1,
                },
            );
        }
    }
}

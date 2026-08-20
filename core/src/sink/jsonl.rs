use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use fs4::FileExt;

use crate::crypto::signer::{sign_line, verify_line};
use crate::crypto::MachineKey;
use crate::error::{PsError, PsResult};
use crate::scan::ScanResult;
use crate::sink::ResultSink;

const DATA_PREFIX: &str = r#"{"data":"#;
const HMAC_PREFIX: &str = r#","hmac":""#;
const HMAC_SUFFIX: &str = r#""}"#;

pub struct JsonlSink {
    file: File,
    key: MachineKey,
}

pub fn create(path: &Path, key: MachineKey) -> PsResult<JsonlSink> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;

    Ok(JsonlSink { file, key })
}

impl ResultSink for JsonlSink {
    fn write(&mut self, result: &ScanResult) -> PsResult<()> {
        let data_json = serde_json::to_string(result)
            .map_err(|error| PsError::Config(format!("result serialize: {error}")))?;
        let mac = sign_line(&self.key, &data_json);
        let line = format!("{{\"data\":{data_json},\"hmac\":\"{mac}\"}}\n");

        self.file.lock_exclusive()?;
        let write_result = self
            .file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush());
        let unlock_result = FileExt::unlock(&self.file);

        write_result.and(unlock_result)?;

        Ok(())
    }
}

pub fn verify_file(path: &Path, key: &MachineKey) -> PsResult<usize> {
    let file = File::open(path)?;
    FileExt::lock_shared(&file)?;
    let result = verify_reader(BufReader::new(&file), key);
    let unlock_result: PsResult<()> = FileExt::unlock(&file).map_err(PsError::Io);

    result.and_then(|count| unlock_result.map(|()| count))
}

fn verify_reader(reader: impl BufRead, key: &MachineKey) -> PsResult<usize> {
    let mut count = 0;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let data_and_hmac = line.strip_prefix(DATA_PREFIX).ok_or_else(|| {
            PsError::Config("record envelope must start with {\"data\":".to_string())
        })?;
        let data_and_mac = data_and_hmac.strip_suffix(HMAC_SUFFIX).ok_or_else(|| {
            PsError::Config("record envelope must end with a hmac field".to_string())
        })?;
        let marker_offset = data_and_mac.rfind(HMAC_PREFIX).ok_or_else(|| {
            PsError::Config("record envelope is missing a hmac field".to_string())
        })?;
        let data_json = &data_and_mac[..marker_offset];
        let mac_hex = &data_and_mac[marker_offset + HMAC_PREFIX.len()..];

        if data_json.is_empty() || mac_hex.is_empty() || data_json.contains(HMAC_PREFIX) {
            return Err(PsError::Config(
                "record envelope has an empty or ambiguous data/hmac field".to_string(),
            ));
        }

        verify_line(key, data_json, mac_hex)?;
        let _result: ScanResult = serde_json::from_str(data_json)
            .map_err(|error| PsError::Config(format!("record data parse: {error}")))?;

        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_machine_key;
    use crate::crypto::signer::sign_line;
    use crate::scan::{DetectionKind, Finding, Verdict};

    fn sample() -> ScanResult {
        ScanResult {
            path: r"C:\evil.exe".to_string(),
            size: 12,
            modified_unix: 1_700_000_000,
            sha256: "de".repeat(32),
            verdict: Verdict::Malicious,
            findings: vec![Finding {
                kind: DetectionKind::Hash,
                label: "blacklist".to_string(),
            }],
            scanned_at_unix: 1_700_000_050,
        }
    }

    fn temporary_path(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "powerscanner-jsonl-{tag}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn writes_and_verifies_records() {
        let key = derive_machine_key(b"jsonl-test-salt-00000").unwrap();
        let path = temporary_path("valid");

        {
            let mut sink =
                create(&path, derive_machine_key(b"jsonl-test-salt-00000").unwrap()).unwrap();
            sink.write(&sample()).unwrap();
            sink.write(&sample()).unwrap();
        }

        assert_eq!(verify_file(&path, &key).unwrap(), 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn independent_sinks_append_complete_records() {
        let key = derive_machine_key(b"jsonl-test-salt-00000").unwrap();
        let path = temporary_path("independent-sinks");
        let mut first =
            create(&path, derive_machine_key(b"jsonl-test-salt-00000").unwrap()).unwrap();
        let mut second =
            create(&path, derive_machine_key(b"jsonl-test-salt-00000").unwrap()).unwrap();

        first.write(&sample()).unwrap();
        second.write(&sample()).unwrap();
        drop(first);
        drop(second);

        assert_eq!(verify_file(&path, &key).unwrap(), 2);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tampered_data_fails_verification() {
        let key = derive_machine_key(b"jsonl-test-salt-00000").unwrap();
        let path = temporary_path("tamper");

        {
            let mut sink =
                create(&path, derive_machine_key(b"jsonl-test-salt-00000").unwrap()).unwrap();
            sink.write(&sample()).unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.replace("evil.exe", "nice.exe")).unwrap();

        assert!(matches!(verify_file(&path, &key), Err(PsError::Tamper(_))));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn malformed_tampered_data_fails_verification_before_parsing() {
        let key = derive_machine_key(b"jsonl-test-salt-00000").unwrap();
        let path = temporary_path("malformed-tamper");

        {
            let mut sink =
                create(&path, derive_machine_key(b"jsonl-test-salt-00000").unwrap()).unwrap();
            sink.write(&sample()).unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.replace(r#""size":12"#, r#""size":broken"#)).unwrap();

        assert!(matches!(verify_file(&path, &key), Err(PsError::Tamper(_))));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn authenticated_malformed_data_is_config_error() {
        let key = derive_machine_key(b"jsonl-test-salt-00000").unwrap();
        let path = temporary_path("authenticated-malformed");
        let data_json = r#"{"size":broken}"#;
        let mac = sign_line(&key, data_json);
        let line = format!(r#"{{"data":{data_json},"hmac":"{mac}"}}"#);

        std::fs::write(&path, line).unwrap();

        assert!(matches!(verify_file(&path, &key), Err(PsError::Config(_))));
        let _ = std::fs::remove_file(path);
    }
}

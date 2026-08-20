//! Offline packaging tool for the encrypted signature bundle.

use powerscanner_core::signatures::{open_bundle, rules, seal_bundle, SignatureBundle};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn collect_bundle(sig_dir: &Path) -> Result<SignatureBundle, String> {
    let hashes_path = sig_dir.join("hashes.txt");
    let hashes_text = fs::read_to_string(&hashes_path)
        .map_err(|error| format!("read {}: {error}", hashes_path.display()))?;
    if hashes_text.trim().is_empty() {
        return Err(format!("{} is empty", hashes_path.display()));
    }

    let rules_dir = sig_dir.join("rules");
    let mut paths = Vec::new();
    let entries = fs::read_dir(&rules_dir)
        .map_err(|error| format!("read {}: {error}", rules_dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|error| format!("read entry in {}: {error}", rules_dir.display()))?
            .path();
        let is_rule = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| matches!(extension.to_ascii_lowercase().as_str(), "yar" | "yara"))
            .unwrap_or(false);
        if is_rule && path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(format!(
            "no .yar/.yara sources under {}",
            rules_dir.display()
        ));
    }

    let mut rule_sources = Vec::with_capacity(paths.len());
    for path in paths {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        rule_sources.push(source);
    }
    rules::compile_from_sources(&rule_sources)
        .map_err(|error| format!("compile signature rules: {error}"))?;
    Ok(SignatureBundle {
        hashes_text,
        rule_sources,
    })
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("output path has no valid filename: {}", path.display()))?;
    let temp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| format!("create {}: {error}", temp.display()))?;
    let write_result = (|| {
        file.write_all(bytes)
            .map_err(|error| format!("write {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temp.display()))?;
        Ok(())
    })();
    drop(file);
    let result = write_result.and_then(|()| replace_file(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(windows)]
fn replace_file(temp: &Path, path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let existing: Vec<u16> = temp.as_os_str().encode_wide().chain([0]).collect();
    let new: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let ok = unsafe {
        // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH.
        MoveFileExW(existing.as_ptr(), new.as_ptr(), 0x0000_0001 | 0x0000_0008)
    };
    if ok == 0 {
        Err(format!(
            "publish {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(temp: &Path, path: &Path) -> Result<(), String> {
    fs::rename(temp, path).map_err(|error| format!("publish {}: {error}", path.display()))
}

fn verify_bundle(sig_dir: &Path) -> Result<(), String> {
    let path = sig_dir.join("bundle.psenc");
    let sealed = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let plaintext = open_bundle(&sealed).map_err(|error| format!("open bundle: {error}"))?;
    let bundle = SignatureBundle::from_bytes(&plaintext)
        .map_err(|error| format!("parse bundle: {error}"))?;
    if bundle.hashes_text.trim().is_empty() {
        return Err("bundle hashes are empty".to_string());
    }
    rules::compile_from_sources(&bundle.rule_sources)
        .map_err(|error| format!("compile sealed rules: {error}"))?;
    let manifest_path = sig_dir.join("MANIFEST.json");
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .map_err(|error| format!("read {}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", manifest_path.display()))?;
    let expected = manifest
        .pointer("/artifacts/bundled.yar/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "MANIFEST.json lacks artifacts.bundled.yar.sha256".to_string())?;
    let mut hasher = Sha256::new();
    for source in &bundle.rule_sources {
        hasher.update(source.as_bytes());
    }
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        return Err(format!(
            "sealed rule source hash mismatch: manifest {expected}, actual {actual}"
        ));
    }
    let expected_hashes = manifest
        .pointer("/artifacts/hashes.txt/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "MANIFEST.json lacks artifacts.hashes.txt.sha256".to_string())?;
    let actual_hashes = hex::encode(Sha256::digest(bundle.hashes_text.as_bytes()));
    if actual_hashes != expected_hashes {
        return Err(format!(
            "sealed hash database mismatch: manifest {expected_hashes}, actual {actual_hashes}"
        ));
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let verify = matches!(args.next().as_deref(), Some("--verify"));
    let sig_dir = if verify {
        args.next()
    } else {
        std::env::args().nth(1)
    }
    .map(PathBuf::from)
    .ok_or_else(|| "usage: seal-bundle [--verify] <sig_dir>".to_string())?;
    if verify {
        verify_bundle(&sig_dir)?;
        println!("verified sealed bundle at {}", sig_dir.display());
        return Ok(());
    }
    let bundle = collect_bundle(&sig_dir)?;
    let plaintext = bundle
        .to_bytes()
        .map_err(|error| format!("serialize bundle: {error}"))?;
    let sealed = seal_bundle(&plaintext).map_err(|error| format!("seal bundle: {error}"))?;
    let opened = open_bundle(&sealed).map_err(|error| format!("verify sealed bundle: {error}"))?;
    if opened != plaintext {
        return Err("sealed bundle verification mismatch".to_string());
    }
    let output = sig_dir.join("bundle.psenc");
    atomic_write(&output, &sealed)?;
    println!("sealed {} bytes to {}", sealed.len(), output.display());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("seal-bundle error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "powerscanner-seal-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("rules")).expect("create fixture");
        path
    }

    #[test]
    fn collects_sorted_sources_and_validates_rules() {
        let directory = fixture();
        fs::write(directory.join("hashes.txt"), "aabb\n").unwrap();
        fs::write(
            directory.join("rules").join("b.yar"),
            "rule B { condition: true }",
        )
        .unwrap();
        fs::write(
            directory.join("rules").join("a.yara"),
            "rule A { condition: true }",
        )
        .unwrap();

        let bundle = collect_bundle(&directory).unwrap();
        assert_eq!(bundle.rule_sources[0], "rule A { condition: true }");
        assert_eq!(bundle.rule_sources[1], "rule B { condition: true }");
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_invalid_rule_source_before_sealing() {
        let directory = fixture();
        fs::write(directory.join("hashes.txt"), "aabb\n").unwrap();
        fs::write(directory.join("rules").join("bad.yar"), "rule broken {").unwrap();

        let error = collect_bundle(&directory).unwrap_err();
        assert!(error.contains("compile signature rules"));
        let _ = fs::remove_dir_all(directory);
    }
}

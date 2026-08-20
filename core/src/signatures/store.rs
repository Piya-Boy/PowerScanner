use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use argon2::Argon2;
use serde::{Deserialize, Serialize};

use crate::crypto::{vault, MachineKey};
use crate::error::{PsError, PsResult};

/// Fixed salt for the portable bundle key. Distinct from machine-key salts.
pub const BUNDLE_SALT: &[u8] = b"powerscanner-bundle-v1-salt-001";

static BUNDLE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn embedded_secret() -> [u8; 32] {
    const A: [u8; 32] = [
        0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8,
        0x34, 0x10, 0x28, 0x2b, 0xdd, 0x1f, 0xf9, 0x0a, 0xfe, 0x6d, 0x1b, 0x2e, 0x64, 0x77, 0x35,
        0xc1, 0x02,
    ];
    const B: [u8; 32] = [
        0x2f, 0xe1, 0x5a, 0x7c, 0x88, 0x11, 0xd9, 0x0e, 0x43, 0xa7, 0x6b, 0x2c, 0x90, 0x5f, 0x1d,
        0xb8, 0x77, 0x04, 0xe2, 0x3a, 0x66, 0xcd, 0x91, 0x08, 0x14, 0xbf, 0x5e, 0x29, 0xa0, 0x3b,
        0x7d, 0xee,
    ];
    let mut secret = [0_u8; 32];

    for index in 0..secret.len() {
        secret[index] = A[index] ^ B[index];
    }

    secret
}

/// Derives a portable key so the same sealed bundle opens on every host.
pub fn bundle_key() -> PsResult<[u8; 32]> {
    let mut key = [0_u8; 32];

    Argon2::default()
        .hash_password_into(&embedded_secret(), BUNDLE_SALT, &mut key)
        .map_err(|error| PsError::Crypto(format!("bundle key derive: {error}")))?;

    Ok(key)
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SignatureBundle {
    pub hashes_text: String,
    pub rule_sources: Vec<String>,
}

impl SignatureBundle {
    pub fn to_bytes(&self) -> PsResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|error| PsError::Config(format!("bundle serialize: {error}")))
    }

    pub fn from_bytes(bytes: &[u8]) -> PsResult<SignatureBundle> {
        serde_json::from_slice(bytes)
            .map_err(|error| PsError::Config(format!("bundle parse: {error}")))
    }
}

pub fn seal_bundle(plaintext_bundle: &[u8]) -> PsResult<Vec<u8>> {
    vault::encrypt(&portable_key()?, plaintext_bundle)
}

pub fn open_bundle(sealed: &[u8]) -> PsResult<Vec<u8>> {
    vault::decrypt(&portable_key()?, sealed)
}

pub fn load_or_import(sig_dir: &Path) -> PsResult<SignatureBundle> {
    let sealed_path = sig_dir.join("bundle.psenc");

    if sealed_path.try_exists()? {
        return load_sealed_bundle(&sealed_path);
    }

    let bundle = import_plaintext(sig_dir)?;
    let sealed = seal_bundle(&bundle.to_bytes()?)?;
    match persist_bundle(&sealed_path, &sealed)? {
        PersistOutcome::Written => Ok(bundle),
        PersistOutcome::Existing => load_sealed_bundle(&sealed_path),
    }
}

fn portable_key() -> PsResult<MachineKey> {
    Ok(MachineKey::from_bytes(bundle_key()?))
}

fn import_plaintext(sig_dir: &Path) -> PsResult<SignatureBundle> {
    let hashes_text = std::fs::read_to_string(sig_dir.join("hashes.txt"))?;
    if hashes_text.trim().is_empty() {
        return Err(PsError::Config("signature hashes.txt is empty".to_string()));
    }

    let mut rule_sources = Vec::new();
    for entry in std::fs::read_dir(sig_dir.join("rules"))? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yar" || extension == "yara")
        {
            rule_sources.push(std::fs::read_to_string(path)?);
        }
    }
    if rule_sources.is_empty() {
        return Err(PsError::Config(
            "no signature rule sources found".to_string(),
        ));
    }

    crate::signatures::rules::compile_from_sources(&rule_sources)?;

    Ok(SignatureBundle {
        hashes_text,
        rule_sources,
    })
}

fn load_sealed_bundle(sealed_path: &Path) -> PsResult<SignatureBundle> {
    let sealed = std::fs::read(sealed_path)?;
    let plaintext = open_bundle(&sealed)?;
    SignatureBundle::from_bytes(&plaintext)
}

enum PersistOutcome {
    Written,
    Existing,
}

fn persist_bundle(bundle_path: &Path, sealed: &[u8]) -> PsResult<PersistOutcome> {
    let (temp_path, mut temp_file) = create_temp_file(bundle_path)?;

    if let Err(error) = temp_file.write_all(sealed) {
        drop(temp_file);
        remove_temp_file(&temp_path)?;
        return Err(error.into());
    }
    if let Err(error) = temp_file.sync_all() {
        drop(temp_file);
        remove_temp_file(&temp_path)?;
        return Err(error.into());
    }
    drop(temp_file);

    match std::fs::rename(&temp_path, bundle_path) {
        Ok(()) => Ok(PersistOutcome::Written),
        Err(error) => {
            remove_temp_file(&temp_path)?;
            match std::fs::metadata(bundle_path) {
                Ok(metadata) if metadata.is_file() => Ok(PersistOutcome::Existing),
                Ok(_) => Err(error.into()),
                Err(metadata_error) if metadata_error.kind() == std::io::ErrorKind::NotFound => {
                    Err(error.into())
                }
                Err(metadata_error) => Err(metadata_error.into()),
            }
        }
    }
}

fn create_temp_file(bundle_path: &Path) -> PsResult<(PathBuf, std::fs::File)> {
    let directory = bundle_path
        .parent()
        .ok_or_else(|| PsError::Config("bundle path has no parent directory".to_string()))?;
    let process_id = std::process::id();

    loop {
        let counter = BUNDLE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = directory.join(format!(".powerscanner-bundle-{process_id}-{counter}.tmp"));

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn remove_temp_file(temp_path: &Path) -> PsResult<()> {
    match std::fs::remove_file(temp_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temporary_directory() -> TempDir {
        let process_id = std::process::id();

        loop {
            let counter = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("powerscanner-store-{process_id}-{counter}"));

            match fs::create_dir(&path) {
                Ok(()) => return TempDir(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create temporary directory: {error}"),
            }
        }
    }

    fn sample_bundle() -> SignatureBundle {
        SignatureBundle {
            hashes_text: "aabb\nccdd".to_string(),
            rule_sources: vec!["rule Example { condition: true }".to_string()],
        }
    }

    #[test]
    fn bundle_key_is_deterministic_and_portable() {
        let first = bundle_key().unwrap();
        let second = bundle_key().unwrap();

        assert_eq!(first, second);
        assert_ne!(first, [0_u8; 32]);
    }

    #[test]
    fn bundle_json_roundtrip() {
        let bundle = sample_bundle();

        let parsed = SignatureBundle::from_bytes(&bundle.to_bytes().unwrap()).unwrap();

        assert_eq!(parsed, bundle);
    }

    #[test]
    fn sealed_bundle_roundtrips_and_rejects_tampering() {
        let plaintext = sample_bundle().to_bytes().unwrap();
        let sealed = seal_bundle(&plaintext).unwrap();

        assert_eq!(open_bundle(&sealed).unwrap(), plaintext);

        let mut tampered = sealed;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(matches!(open_bundle(&tampered), Err(PsError::Crypto(_))));
    }

    #[test]
    fn strict_import_rejects_empty_hashes_and_missing_rules() {
        let directory = temporary_directory();
        fs::create_dir(directory.path().join("rules")).unwrap();
        fs::write(directory.path().join("hashes.txt"), " \n\t ").unwrap();
        fs::write(
            directory.path().join("rules").join("example.yar"),
            "rule Example { condition: true }",
        )
        .unwrap();

        assert!(matches!(
            load_or_import(directory.path()),
            Err(PsError::Config(_))
        ));

        fs::write(directory.path().join("hashes.txt"), "aabb").unwrap();
        fs::remove_file(directory.path().join("rules").join("example.yar")).unwrap();

        assert!(matches!(
            load_or_import(directory.path()),
            Err(PsError::Config(_))
        ));

        fs::write(
            directory.path().join("rules").join("example.yar"),
            "// no effective rule declaration",
        )
        .unwrap();

        assert!(matches!(
            load_or_import(directory.path()),
            Err(PsError::Yara(_))
        ));
    }

    #[test]
    fn import_seals_then_loads_without_plaintext_sources() {
        let directory = temporary_directory();
        fs::create_dir(directory.path().join("rules")).unwrap();
        fs::write(directory.path().join("hashes.txt"), "aabb").unwrap();
        fs::write(
            directory.path().join("rules").join("example.yar"),
            "rule Example { condition: true }",
        )
        .unwrap();

        let imported = load_or_import(directory.path()).unwrap();
        assert!(directory.path().join("bundle.psenc").exists());

        fs::remove_file(directory.path().join("hashes.txt")).unwrap();
        fs::remove_dir_all(directory.path().join("rules")).unwrap();
        let loaded = load_or_import(directory.path()).unwrap();

        assert_eq!(loaded, imported);
    }

    #[test]
    fn stale_partial_temp_does_not_replace_the_sealed_bundle() {
        let directory = temporary_directory();
        let stale = directory.path().join(".powerscanner-bundle-stale.tmp");
        fs::create_dir(directory.path().join("rules")).unwrap();
        fs::write(directory.path().join("hashes.txt"), "aabb").unwrap();
        fs::write(
            directory.path().join("rules").join("example.yar"),
            "rule Example { condition: true }",
        )
        .unwrap();
        fs::write(&stale, b"partial bundle").unwrap();

        let imported = load_or_import(directory.path()).unwrap();
        let sealed = fs::read(directory.path().join("bundle.psenc")).unwrap();
        let loaded = SignatureBundle::from_bytes(&open_bundle(&sealed).unwrap()).unwrap();

        assert!(stale.exists());
        assert_eq!(loaded, imported);
    }
}

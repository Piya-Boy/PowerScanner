# PowerScanner Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fast, low-footprint standalone Windows malware scanner in Rust with a native GUI that scans files using SHA-256 hash blacklists and YARA rules, with tamper-proof signed results and encrypted signature/config storage.

**Architecture:** Cargo workspace split into a UI-agnostic `core` engine crate and an `eframe`/`egui` `gui` crate. The core walks target directories in parallel (rayon), performs incremental scanning (skip files whose mtime+size are unchanged), matches each file against a hash blacklist and compiled YARA rules, and emits results through a `ResultSink` trait. Phase 1 ships a `JsonlSink` writing HMAC-signed, append-only results to an ACL-protected directory. Signature DB and config are stored AES-256-GCM encrypted with a machine-derived key (Argon2 KDF over MachineGuid + volume serial).

**Tech Stack:** Rust (edition 2021), `eframe`/`egui` (GUI), `yara-x` (YARA engine), `sha2` (hashing), `aes-gcm` (authenticated encryption), `hmac` (result signing), `argon2` (key derivation), `rayon` (parallelism), `walkdir` (directory traversal), `winreg` + `windows` (Windows machine ID / ACL), `serde`/`serde_json` (serialization).

## Global Constraints

- Rust edition: **2021**. MSRV: **1.74+**.
- Platform: **Windows x64 only** (`x86_64-pc-windows-msvc`).
- Workspace layout: two member crates — `core/` (lib, no UI deps) and `gui/` (bin, depends on `core`).
- `core` crate MUST NOT depend on any GUI crate (`eframe`, `egui`, `winit`).
- All persistent files (signature DB, config, results) use **authenticated encryption or authenticated signatures** — never plaintext secrets, never unauthenticated ciphertext.
- **No hardcoded keys or secrets** anywhere in source. Keys are machine-derived at runtime.
- All SQL (future phases) and all external input handling: no string concatenation into queries/commands. (Phase 1 has no SQL.)
- Crate versions (pin in `Cargo.toml`): `yara-x = "1"`, `aes-gcm = "0.11"`, `sha2 = "0.11"`, `hmac = "0.13"`, `argon2 = "0.5"`, `rayon = "1"`, `walkdir = "2"`, `eframe = "0.36"`, `winreg = "0.56"`, `serde = "1"`, `serde_json = "1"`, `hex = "0.4"`, `thiserror = "2"`, `windows = "0.58"`.
- Error handling: `core` returns `Result<_, PsError>` (a `thiserror` enum). No `unwrap()`/`expect()` in library code paths except tests.

---

## File Structure

```
PowerScanner/
├─ Cargo.toml                      # workspace manifest
├─ core/
│  ├─ Cargo.toml
│  └─ src/
│     ├─ lib.rs                    # re-exports, PsError, public API
│     ├─ error.rs                  # PsError enum
│     ├─ crypto/
│     │  ├─ mod.rs                 # re-exports
│     │  ├─ machine_key.rs         # derive machine key (Argon2 over MachineGuid+volserial)
│     │  ├─ vault.rs               # AES-256-GCM encrypt/decrypt file blobs
│     │  └─ signer.rs              # HMAC-SHA256 sign/verify for results
│     ├─ signatures/
│     │  ├─ mod.rs
│     │  ├─ hashdb.rs              # load SHA-256 blacklist, lookup
│     │  └─ rules.rs               # compile + hold yara-x rules
│     ├─ scan/
│     │  ├─ mod.rs
│     │  ├─ targets.rs             # preset target resolution (Quick/Full/Risky)
│     │  ├─ walk.rs                # enumerate files for a target set
│     │  ├─ incremental.rs         # scan cache: skip unchanged (mtime+size)
│     │  ├─ hasher.rs              # SHA-256 of a file
│     │  ├─ engine.rs              # orchestrate parallel scan, produce ScanResult
│     │  └─ result.rs             # ScanResult, Verdict, Finding types
│     └─ sink/
│        ├─ mod.rs                 # ResultSink trait
│        └─ jsonl.rs               # JsonlSink: HMAC-signed append-only JSONL
├─ gui/
│  ├─ Cargo.toml
│  └─ src/
│     ├─ main.rs                   # eframe bootstrap
│     └─ app.rs                    # egui app: 3 scan buttons, progress, results table
└─ docs/superpowers/plans/2026-08-17-powerscanner-phase1.md
```

---

## Task 1: Workspace scaffold + error type

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `core/Cargo.toml`
- Create: `core/src/lib.rs`
- Create: `core/src/error.rs`
- Test: `core/src/error.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `core::error::PsError` enum with variants `Io(std::io::Error)`, `Crypto(String)`, `Signature(String)`, `Yara(String)`, `Config(String)`, `Tamper(String)`; `pub type PsResult<T> = Result<T, PsError>;`. `PsError` implements `std::error::Error` + `Display` via `thiserror`.

- [ ] **Step 1: Create the workspace root manifest**

Create `Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["core", "gui"]

[workspace.package]
edition = "2021"
rust-version = "1.74"
version = "0.1.0"

[workspace.dependencies]
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
sha2 = "0.11"
hmac = "0.13"
aes-gcm = "0.11"
argon2 = "0.5"
rayon = "1"
walkdir = "2"
yara-x = "1"
winreg = "0.56"
windows = { version = "0.58", features = ["Win32_Foundation", "Win32_Storage_FileSystem", "Win32_Security"] }
```

- [ ] **Step 2: Create the core crate manifest**

Create `core/Cargo.toml`:
```toml
[package]
name = "powerscanner-core"
edition.workspace = true
rust-version.workspace = true
version.workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
hex.workspace = true
sha2.workspace = true
hmac.workspace = true
aes-gcm.workspace = true
argon2.workspace = true
rayon.workspace = true
walkdir.workspace = true
yara-x.workspace = true

[target.'cfg(windows)'.dependencies]
winreg.workspace = true
windows.workspace = true
```

- [ ] **Step 3: Write the failing test for PsError**

Create `core/src/error.rs`:
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("signature error: {0}")]
    Signature(String),
    #[error("yara error: {0}")]
    Yara(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("tamper detected: {0}")]
    Tamper(String),
}

pub type PsResult<T> = Result<T, PsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_variant() {
        let e = PsError::Tamper("bad hmac".into());
        assert_eq!(e.to_string(), "tamper detected: bad hmac");
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let e: PsError = io.into();
        assert!(matches!(e, PsError::Io(_)));
    }
}
```

- [ ] **Step 4: Create lib.rs**

Create `core/src/lib.rs`:
```rust
pub mod error;

pub use error::{PsError, PsResult};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p powerscanner-core error::`
Expected: PASS (2 tests). Compiles clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml core/Cargo.toml core/src/lib.rs core/src/error.rs
git commit -m "feat: workspace scaffold and PsError type"
```

---

## Task 2: Machine-derived key

**Files:**
- Create: `core/src/crypto/mod.rs`
- Create: `core/src/crypto/machine_key.rs`
- Modify: `core/src/lib.rs` (add `pub mod crypto;`)
- Test: `core/src/crypto/machine_key.rs` (inline)

**Interfaces:**
- Consumes: `PsResult` from Task 1.
- Produces:
  - `pub struct MachineKey([u8; 32]);` with `pub fn as_bytes(&self) -> &[u8; 32]`.
  - `pub fn derive_machine_key(salt: &[u8]) -> PsResult<MachineKey>` — reads a machine identifier (MachineGuid from registry on Windows; on non-Windows falls back to a fixed test seed so the crate builds cross-platform for CI) and runs Argon2id over it with the given `salt` to produce 32 bytes.
  - `pub fn machine_identifier() -> PsResult<String>` — platform machine id string.

- [ ] **Step 1: Write the failing test**

Create `core/src/crypto/machine_key.rs`:
```rust
use crate::error::{PsError, PsResult};
use argon2::{Argon2, Algorithm, Version, Params};

pub struct MachineKey([u8; 32]);

impl MachineKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(windows)]
pub fn machine_identifier() -> PsResult<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let crypto = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Cryptography")
        .map_err(|e| PsError::Crypto(format!("open Cryptography key: {e}")))?;
    let guid: String = crypto
        .get_value("MachineGuid")
        .map_err(|e| PsError::Crypto(format!("read MachineGuid: {e}")))?;
    Ok(guid)
}

#[cfg(not(windows))]
pub fn machine_identifier() -> PsResult<String> {
    // CI / non-Windows build: deterministic non-secret placeholder.
    Ok("non-windows-ci-machine".to_string())
}

pub fn derive_machine_key(salt: &[u8]) -> PsResult<MachineKey> {
    let id = machine_identifier()?;
    // Argon2id, params chosen for fast startup on low-spec (64 MiB, 3 passes, 1 lane).
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| PsError::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(id.as_bytes(), salt, &mut out)
        .map_err(|e| PsError::Crypto(format!("argon2 derive: {e}")))?;
    Ok(MachineKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_for_same_salt() {
        let salt = b"powerscanner-test-salt-0123456789";
        let k1 = derive_machine_key(salt).unwrap();
        let k2 = derive_machine_key(salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_differs_for_different_salt() {
        let k1 = derive_machine_key(b"salt-aaaaaaaaaaaaaaaa").unwrap();
        let k2 = derive_machine_key(b"salt-bbbbbbbbbbbbbbbb").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn key_is_32_bytes() {
        let k = derive_machine_key(b"salt-cccccccccccccccc").unwrap();
        assert_eq!(k.as_bytes().len(), 32);
    }
}
```

Note: Argon2 requires salt length >= 8 bytes. All test salts above satisfy this.

- [ ] **Step 2: Create crypto/mod.rs**

Create `core/src/crypto/mod.rs`:
```rust
pub mod machine_key;

pub use machine_key::{derive_machine_key, machine_identifier, MachineKey};
```

- [ ] **Step 3: Wire into lib.rs**

Modify `core/src/lib.rs` to add after `pub mod error;`:
```rust
pub mod crypto;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p powerscanner-core crypto::machine_key`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add core/src/crypto/mod.rs core/src/crypto/machine_key.rs core/src/lib.rs
git commit -m "feat: machine-derived Argon2id key"
```

---

## Task 3: Encrypted vault (AES-256-GCM)

**Files:**
- Create: `core/src/crypto/vault.rs`
- Modify: `core/src/crypto/mod.rs` (add `pub mod vault;`)
- Test: `core/src/crypto/vault.rs` (inline)

**Interfaces:**
- Consumes: `MachineKey` from Task 2, `PsResult`.
- Produces:
  - `pub fn encrypt(key: &MachineKey, plaintext: &[u8]) -> PsResult<Vec<u8>>` — output layout: `[12-byte nonce][ciphertext+tag]`. Nonce is random per call.
  - `pub fn decrypt(key: &MachineKey, blob: &[u8]) -> PsResult<Vec<u8>>` — reads nonce prefix, decrypts, returns plaintext; returns `PsError::Crypto` on auth failure (tamper).

- [ ] **Step 1: Write the failing test**

Create `core/src/crypto/vault.rs`:
```rust
use crate::crypto::MachineKey;
use crate::error::{PsError, PsResult};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};

const NONCE_LEN: usize = 12;

pub fn encrypt(key: &MachineKey, plaintext: &[u8]) -> PsResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| PsError::Crypto(format!("aes-gcm encrypt: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &MachineKey, blob: &[u8]) -> PsResult<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(PsError::Crypto("blob too short for nonce".into()));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| PsError::Crypto(format!("aes-gcm decrypt/auth: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_machine_key;

    fn test_key() -> MachineKey {
        derive_machine_key(b"vault-test-salt-000000").unwrap()
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        let msg = b"top secret rule bytes";
        let blob = encrypt(&key, msg).unwrap();
        let back = decrypt(&key, &blob).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn tamper_is_rejected() {
        let key = test_key();
        let mut blob = encrypt(&key, b"data").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff; // flip a ciphertext/tag bit
        assert!(decrypt(&key, &blob).is_err());
    }

    #[test]
    fn nonce_is_unique_across_calls() {
        let key = test_key();
        let a = encrypt(&key, b"same").unwrap();
        let b = encrypt(&key, b"same").unwrap();
        assert_ne!(a, b); // random nonce => different ciphertext
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/crypto/mod.rs`, append:
```rust
pub mod vault;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core crypto::vault`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add core/src/crypto/vault.rs core/src/crypto/mod.rs
git commit -m "feat: AES-256-GCM encrypted vault"
```

---

## Task 4: HMAC result signer

**Files:**
- Create: `core/src/crypto/signer.rs`
- Modify: `core/src/crypto/mod.rs` (add `pub mod signer;`)
- Test: `core/src/crypto/signer.rs` (inline)

**Interfaces:**
- Consumes: `MachineKey` from Task 2, `PsResult`.
- Produces:
  - `pub fn sign_line(key: &MachineKey, line: &str) -> String` — returns lowercase hex HMAC-SHA256 of `line`.
  - `pub fn verify_line(key: &MachineKey, line: &str, mac_hex: &str) -> PsResult<()>` — constant-time verify; `PsError::Tamper` on mismatch.

- [ ] **Step 1: Write the failing test**

Create `core/src/crypto/signer.rs`:
```rust
use crate::crypto::MachineKey;
use crate::error::{PsError, PsResult};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn sign_line(key: &MachineKey, line: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(line.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_line(key: &MachineKey, line: &str, mac_hex: &str) -> PsResult<()> {
    let expected = hex::decode(mac_hex)
        .map_err(|e| PsError::Signature(format!("bad mac hex: {e}")))?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(line.as_bytes());
    mac.verify_slice(&expected)
        .map_err(|_| PsError::Tamper("hmac mismatch on result line".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_machine_key;

    fn key() -> MachineKey {
        derive_machine_key(b"signer-test-salt-0000").unwrap()
    }

    #[test]
    fn sign_then_verify_ok() {
        let k = key();
        let line = r#"{"path":"C:\\x.exe","verdict":"malicious"}"#;
        let mac = sign_line(&k, line);
        assert!(verify_line(&k, line, &mac).is_ok());
    }

    #[test]
    fn modified_line_fails_verify() {
        let k = key();
        let line = "original";
        let mac = sign_line(&k, line);
        assert!(verify_line(&k, "tampered", &mac).is_err());
    }

    #[test]
    fn bad_hex_is_signature_error() {
        let k = key();
        let err = verify_line(&k, "x", "nothex").unwrap_err();
        assert!(matches!(err, PsError::Signature(_)));
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/crypto/mod.rs`, append:
```rust
pub mod signer;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core crypto::signer`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add core/src/crypto/signer.rs core/src/crypto/mod.rs
git commit -m "feat: HMAC-SHA256 result signer"
```

---

## Task 5: Result types

**Files:**
- Create: `core/src/scan/mod.rs`
- Create: `core/src/scan/result.rs`
- Modify: `core/src/lib.rs` (add `pub mod scan;`)
- Test: `core/src/scan/result.rs` (inline)

**Interfaces:**
- Consumes: nothing beyond std/serde.
- Produces:
  - `pub enum Verdict { Clean, Malicious }` (serde: lowercase).
  - `pub enum DetectionKind { Hash, Yara }` (serde: lowercase).
  - `pub struct Finding { pub kind: DetectionKind, pub label: String }` — `label` is the matched hash id or YARA rule name.
  - `pub struct ScanResult { pub path: String, pub size: u64, pub modified_unix: i64, pub sha256: String, pub verdict: Verdict, pub findings: Vec<Finding>, pub scanned_at_unix: i64 }`.
  - All `#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]`.

- [ ] **Step 1: Write the failing test**

Create `core/src/scan/result.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Malicious,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DetectionKind {
    Hash,
    Yara,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    pub kind: DetectionKind,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ScanResult {
    pub path: String,
    pub size: u64,
    pub modified_unix: i64,
    pub sha256: String,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub scanned_at_unix: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_and_deserializes() {
        let r = ScanResult {
            path: r"C:\x.exe".into(),
            size: 10,
            modified_unix: 1_700_000_000,
            sha256: "ab".repeat(32),
            verdict: Verdict::Malicious,
            findings: vec![Finding { kind: DetectionKind::Yara, label: "EvilRule".into() }],
            scanned_at_unix: 1_700_000_100,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn verdict_serializes_lowercase() {
        let json = serde_json::to_string(&Verdict::Clean).unwrap();
        assert_eq!(json, r#""clean""#);
    }
}
```

- [ ] **Step 2: Create scan/mod.rs**

Create `core/src/scan/mod.rs`:
```rust
pub mod result;

pub use result::{DetectionKind, Finding, ScanResult, Verdict};
```

- [ ] **Step 3: Wire into lib.rs**

Modify `core/src/lib.rs`, add:
```rust
pub mod scan;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p powerscanner-core scan::result`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add core/src/scan/mod.rs core/src/scan/result.rs core/src/lib.rs
git commit -m "feat: scan result types"
```

---

## Task 6: File hasher

**Files:**
- Create: `core/src/scan/hasher.rs`
- Modify: `core/src/scan/mod.rs` (add `pub mod hasher;`)
- Test: `core/src/scan/hasher.rs` (inline)

**Interfaces:**
- Consumes: `PsResult`.
- Produces: `pub fn sha256_file(path: &std::path::Path) -> PsResult<String>` — streams the file in 64 KiB chunks (low memory), returns lowercase hex digest.

- [ ] **Step 1: Write the failing test**

Create `core/src/scan/hasher.rs`:
```rust
use crate::error::PsResult;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub fn sha256_file(path: &Path) -> PsResult<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hashes_known_content() {
        // SHA-256 of "abc"
        let mut tf = tempfile();
        tf.write_all(b"abc").unwrap();
        let path = tf.path().to_path_buf();
        drop(tf.into_file_keep());
        let digest = sha256_file(&path).unwrap();
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&path);
    }

    // Minimal temp-file helper to avoid an extra dependency.
    struct TempFile {
        path: std::path::PathBuf,
        file: Option<std::fs::File>,
    }
    impl TempFile {
        fn path(&self) -> &Path {
            &self.path
        }
        fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
            self.file.as_mut().unwrap().write_all(b)
        }
        fn into_file_keep(mut self) -> std::fs::File {
            self.file.take().unwrap()
        }
    }
    fn tempfile() -> TempFile {
        let mut p = std::env::temp_dir();
        let name = format!("ps_hash_test_{}.bin", std::process::id());
        p.push(name);
        let file = std::fs::File::create(&p).unwrap();
        TempFile { path: p, file: Some(file) }
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/scan/mod.rs`, append:
```rust
pub mod hasher;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core scan::hasher`
Expected: PASS (1 test). Digest matches the known SHA-256 of "abc".

- [ ] **Step 4: Commit**

```bash
git add core/src/scan/hasher.rs core/src/scan/mod.rs
git commit -m "feat: streaming SHA-256 file hasher"
```

---

## Task 7: Hash blacklist DB

**Files:**
- Create: `core/src/signatures/mod.rs`
- Create: `core/src/signatures/hashdb.rs`
- Modify: `core/src/lib.rs` (add `pub mod signatures;`)
- Test: `core/src/signatures/hashdb.rs` (inline)

**Interfaces:**
- Consumes: `PsResult`.
- Produces:
  - `pub struct HashDb { set: std::collections::HashSet<String> }`.
  - `pub fn from_text(contents: &str) -> HashDb` — parses one lowercase SHA-256 per line, ignores blank lines and lines starting with `#`, normalizes to lowercase and trims.
  - `pub fn contains(&self, sha256_hex: &str) -> bool` — case-insensitive membership.
  - `pub fn len(&self) -> usize`, `pub fn is_empty(&self) -> bool`.

- [ ] **Step 1: Write the failing test**

Create `core/src/signatures/hashdb.rs`:
```rust
use std::collections::HashSet;

pub struct HashDb {
    set: HashSet<String>,
}

impl HashDb {
    pub fn from_text(contents: &str) -> HashDb {
        let set = contents
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_ascii_lowercase())
            .collect();
        HashDb { set }
    }

    pub fn contains(&self, sha256_hex: &str) -> bool {
        self.set.contains(&sha256_hex.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_case_insensitive() {
        let db = HashDb::from_text("# comment\nAABB\n\n  ccdd  \n");
        assert_eq!(db.len(), 2);
        assert!(db.contains("aabb"));
        assert!(db.contains("AABB"));
        assert!(db.contains("ccdd"));
        assert!(!db.contains("eeff"));
    }

    #[test]
    fn empty_text_is_empty_db() {
        let db = HashDb::from_text("# only a comment\n\n");
        assert!(db.is_empty());
    }
}
```

- [ ] **Step 2: Create signatures/mod.rs**

Create `core/src/signatures/mod.rs`:
```rust
pub mod hashdb;

pub use hashdb::HashDb;
```

- [ ] **Step 3: Wire into lib.rs**

Modify `core/src/lib.rs`, add:
```rust
pub mod signatures;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p powerscanner-core signatures::hashdb`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add core/src/signatures/mod.rs core/src/signatures/hashdb.rs core/src/lib.rs
git commit -m "feat: SHA-256 hash blacklist DB"
```

---

## Task 8: YARA rules compiler

**Files:**
- Create: `core/src/signatures/rules.rs`
- Modify: `core/src/signatures/mod.rs` (add `pub mod rules;`)
- Test: `core/src/signatures/rules.rs` (inline)

**Interfaces:**
- Consumes: `PsResult`, `PsError::Yara`.
- Produces:
  - `pub struct RuleSet { rules: yara_x::Rules }`.
  - `pub fn compile_from_sources(sources: &[String]) -> PsResult<RuleSet>` — compiles one or more `.yar` source strings; maps compile errors to `PsError::Yara`.
  - `pub fn scan_bytes(&self, data: &[u8]) -> PsResult<Vec<String>>` — returns the list of matching rule identifiers for the given bytes. Uses a fresh `yara_x::Scanner` per call (scanner is not `Sync`; callers scan in parallel by constructing per-thread scanners — see Task 11).

- [ ] **Step 1: Write the failing test**

Create `core/src/signatures/rules.rs`:
```rust
use crate::error::{PsError, PsResult};

pub struct RuleSet {
    rules: yara_x::Rules,
}

impl RuleSet {
    pub fn scan_bytes(&self, data: &[u8]) -> PsResult<Vec<String>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| PsError::Yara(format!("scan: {e}")))?;
        Ok(results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect())
    }

    pub fn rules(&self) -> &yara_x::Rules {
        &self.rules
    }
}

pub fn compile_from_sources(sources: &[String]) -> PsResult<RuleSet> {
    let mut compiler = yara_x::Compiler::new();
    for (i, src) in sources.iter().enumerate() {
        compiler
            .add_source(src.as_str())
            .map_err(|e| PsError::Yara(format!("compile source #{i}: {e}")))?;
    }
    let rules = compiler.build();
    Ok(RuleSet { rules })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"
rule EicarLike {
    strings:
        $a = "X5O!P%@AP"
    condition:
        $a
}
"#;

    #[test]
    fn compiles_and_matches() {
        let rs = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hits = rs.scan_bytes(b"prefix X5O!P%@AP suffix").unwrap();
        assert_eq!(hits, vec!["EicarLike".to_string()]);
    }

    #[test]
    fn no_match_returns_empty() {
        let rs = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hits = rs.scan_bytes(b"clean content").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn bad_syntax_is_yara_error() {
        let err = compile_from_sources(&["rule broken {".to_string()]).unwrap_err();
        assert!(matches!(err, PsError::Yara(_)));
    }
}
```

Note: `yara-x` 1.x API — `Compiler::new()`, `add_source()`, `build()` returning `Rules`; `Scanner::new(&rules).scan(data)` returning `ScanResults` with `matching_rules()`. If the installed `yara-x` point release differs, adjust these three call sites to the crate's current API; the test assertions stay the same.

- [ ] **Step 2: Register module**

Modify `core/src/signatures/mod.rs`, append:
```rust
pub mod rules;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core signatures::rules`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add core/src/signatures/rules.rs core/src/signatures/mod.rs
git commit -m "feat: yara-x rules compiler and scanner"
```

---

## Task 9: Scan targets (presets)

**Files:**
- Create: `core/src/scan/targets.rs`
- Modify: `core/src/scan/mod.rs` (add `pub mod targets;`)
- Test: `core/src/scan/targets.rs` (inline)

**Interfaces:**
- Consumes: nothing beyond std.
- Produces:
  - `pub enum ScanPreset { Quick, Full, RiskySpots }`.
  - `pub fn risky_roots() -> Vec<std::path::PathBuf>` — resolves risky env dirs (`TEMP`, `APPDATA`, `LOCALAPPDATA`, `USERPROFILE\Downloads`, Startup folders, `C:\Windows\Temp`, `C:\Windows\System32`) from environment variables; silently skips ones that don't resolve.
  - `pub fn full_roots() -> Vec<std::path::PathBuf>` — all fixed logical drives `A:\`..`Z:\` that exist.
  - `pub fn roots_for(preset: ScanPreset) -> Vec<std::path::PathBuf>` — maps preset to root list. Quick == risky roots for Phase 1 (process-path scanning deferred to a later phase; documented here so the button's scope is honest).

- [ ] **Step 1: Write the failing test**

Create `core/src/scan/targets.rs`:
```rust
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScanPreset {
    Quick,
    Full,
    RiskySpots,
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.exists())
}

pub fn risky_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in ["TEMP", "APPDATA", "LOCALAPPDATA", "USERPROFILE"] {
        if let Some(p) = env_path(var) {
            if var == "USERPROFILE" {
                let dl = p.join("Downloads");
                if dl.exists() {
                    roots.push(dl);
                }
            } else {
                roots.push(p);
            }
        }
    }
    for fixed in [r"C:\Windows\Temp", r"C:\Windows\System32"] {
        let p = PathBuf::from(fixed);
        if p.exists() {
            roots.push(p);
        }
    }
    roots
}

pub fn full_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for letter in b'A'..=b'Z' {
        let p = PathBuf::from(format!("{}:\\", letter as char));
        if p.exists() {
            roots.push(p);
        }
    }
    roots
}

pub fn roots_for(preset: ScanPreset) -> Vec<PathBuf> {
    match preset {
        ScanPreset::Quick => risky_roots(),
        ScanPreset::RiskySpots => risky_roots(),
        ScanPreset::Full => full_roots(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_maps_do_not_panic() {
        // On any platform these return possibly-empty vecs without error.
        let _ = roots_for(ScanPreset::Quick);
        let _ = roots_for(ScanPreset::RiskySpots);
        let _ = roots_for(ScanPreset::Full);
    }

    #[test]
    fn quick_equals_risky_for_phase1() {
        assert_eq!(roots_for(ScanPreset::Quick), roots_for(ScanPreset::RiskySpots));
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/scan/mod.rs`, append:
```rust
pub mod targets;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core scan::targets`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add core/src/scan/targets.rs core/src/scan/mod.rs
git commit -m "feat: scan preset target resolution"
```

---

## Task 10: Incremental scan cache

**Files:**
- Create: `core/src/scan/incremental.rs`
- Modify: `core/src/scan/mod.rs` (add `pub mod incremental;`)
- Test: `core/src/scan/incremental.rs` (inline)

**Interfaces:**
- Consumes: `PsResult`.
- Produces:
  - `pub struct ScanCache { seen: std::collections::HashMap<String, (u64, i64)> }` — maps path → (size, mtime_unix).
  - `pub fn new() -> ScanCache`, `impl Default`.
  - `pub fn from_json(json: &str) -> PsResult<ScanCache>` / `pub fn to_json(&self) -> PsResult<String>`.
  - `pub fn is_unchanged(&self, path: &str, size: u64, mtime_unix: i64) -> bool`.
  - `pub fn record(&mut self, path: &str, size: u64, mtime_unix: i64)`.

- [ ] **Step 1: Write the failing test**

Create `core/src/scan/incremental.rs`:
```rust
use crate::error::{PsError, PsResult};
use std::collections::HashMap;

#[derive(Default)]
pub struct ScanCache {
    seen: HashMap<String, (u64, i64)>,
}

impl ScanCache {
    pub fn new() -> ScanCache {
        ScanCache::default()
    }

    pub fn from_json(json: &str) -> PsResult<ScanCache> {
        let seen: HashMap<String, (u64, i64)> = serde_json::from_str(json)
            .map_err(|e| PsError::Config(format!("scan cache parse: {e}")))?;
        Ok(ScanCache { seen })
    }

    pub fn to_json(&self) -> PsResult<String> {
        serde_json::to_string(&self.seen)
            .map_err(|e| PsError::Config(format!("scan cache serialize: {e}")))
    }

    pub fn is_unchanged(&self, path: &str, size: u64, mtime_unix: i64) -> bool {
        matches!(self.seen.get(path), Some(&(s, m)) if s == size && m == mtime_unix)
    }

    pub fn record(&mut self, path: &str, size: u64, mtime_unix: i64) {
        self.seen.insert(path.to_string(), (size, mtime_unix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_detects_unchanged() {
        let mut c = ScanCache::new();
        c.record(r"C:\a.exe", 100, 1_700_000_000);
        assert!(c.is_unchanged(r"C:\a.exe", 100, 1_700_000_000));
        assert!(!c.is_unchanged(r"C:\a.exe", 101, 1_700_000_000)); // size changed
        assert!(!c.is_unchanged(r"C:\a.exe", 100, 1_700_000_001)); // mtime changed
        assert!(!c.is_unchanged(r"C:\b.exe", 100, 1_700_000_000)); // unseen
    }

    #[test]
    fn json_roundtrip() {
        let mut c = ScanCache::new();
        c.record(r"C:\x", 5, 42);
        let json = c.to_json().unwrap();
        let back = ScanCache::from_json(&json).unwrap();
        assert!(back.is_unchanged(r"C:\x", 5, 42));
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/scan/mod.rs`, append:
```rust
pub mod incremental;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core scan::incremental`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add core/src/scan/incremental.rs core/src/scan/mod.rs
git commit -m "feat: incremental scan cache"
```

---

## Task 11: Result sink trait + JSONL sink

**Files:**
- Create: `core/src/sink/mod.rs`
- Create: `core/src/sink/jsonl.rs`
- Modify: `core/src/lib.rs` (add `pub mod sink;`)
- Test: `core/src/sink/jsonl.rs` (inline)

**Interfaces:**
- Consumes: `ScanResult` (Task 5), `MachineKey` + `sign_line`/`verify_line` (Task 4), `PsResult`.
- Produces:
  - `pub trait ResultSink { fn write(&mut self, result: &ScanResult) -> PsResult<()>; }`.
  - `pub struct JsonlSink { writer: BufWriter<File>, key: MachineKey }`.
  - `pub fn create(path: &Path, key: MachineKey) -> PsResult<JsonlSink>` — opens the file in append mode (creates if absent).
  - `impl ResultSink for JsonlSink` — writes one line per result: `{"data":<result-json>,"hmac":"<hex>"}` where the HMAC signs the exact `<result-json>` substring.
  - `pub fn verify_file(path: &Path, key: &MachineKey) -> PsResult<usize>` — reads every line, verifies each HMAC, returns the count of valid records; returns `PsError::Tamper` on the first bad line.

- [ ] **Step 1: Write the failing test**

Create `core/src/sink/jsonl.rs`:
```rust
use crate::crypto::signer::{sign_line, verify_line};
use crate::crypto::MachineKey;
use crate::error::{PsError, PsResult};
use crate::scan::ScanResult;
use crate::sink::ResultSink;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct SignedRecord {
    data: serde_json::Value,
    hmac: String,
}

pub struct JsonlSink {
    writer: BufWriter<File>,
    key: MachineKey,
}

pub fn create(path: &Path, key: MachineKey) -> PsResult<JsonlSink> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(JsonlSink { writer: BufWriter::new(file), key })
}

impl ResultSink for JsonlSink {
    fn write(&mut self, result: &ScanResult) -> PsResult<()> {
        let data_json = serde_json::to_string(result)
            .map_err(|e| PsError::Config(format!("result serialize: {e}")))?;
        let mac = sign_line(&self.key, &data_json);
        // Compose the line so the signed substring is exactly `data_json`.
        let line = format!("{{\"data\":{data_json},\"hmac\":\"{mac}\"}}");
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

pub fn verify_file(path: &Path, key: &MachineKey) -> PsResult<usize> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0usize;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: SignedRecord = serde_json::from_str(&line)
            .map_err(|e| PsError::Config(format!("record parse: {e}")))?;
        let data_json = serde_json::to_string(&rec.data)
            .map_err(|e| PsError::Config(format!("reserialize: {e}")))?;
        verify_line(key, &data_json, &rec.hmac)?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_machine_key;
    use crate::scan::{DetectionKind, Finding, Verdict};

    fn sample() -> ScanResult {
        ScanResult {
            path: r"C:\evil.exe".into(),
            size: 12,
            modified_unix: 1_700_000_000,
            sha256: "de".repeat(32),
            verdict: Verdict::Malicious,
            findings: vec![Finding { kind: DetectionKind::Hash, label: "blacklist".into() }],
            scanned_at_unix: 1_700_000_050,
        }
    }

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ps_jsonl_{}_{}.jsonl", tag, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn write_then_verify_ok() {
        let key = derive_machine_key(b"jsonl-test-salt-00000").unwrap();
        let path = tmp_path("ok");
        {
            let mut sink = create(&path, derive_machine_key(b"jsonl-test-salt-00000").unwrap()).unwrap();
            sink.write(&sample()).unwrap();
            sink.write(&sample()).unwrap();
        }
        let n = verify_file(&path, &key).unwrap();
        assert_eq!(n, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_line_fails_verify() {
        let key = derive_machine_key(b"jsonl-test-salt-00000").unwrap();
        let path = tmp_path("tamper");
        {
            let mut sink = create(&path, derive_machine_key(b"jsonl-test-salt-00000").unwrap()).unwrap();
            sink.write(&sample()).unwrap();
        }
        // Corrupt the file: change a byte inside the data.
        let content = std::fs::read_to_string(&path).unwrap();
        let corrupted = content.replace("evil.exe", "nice.exe");
        std::fs::write(&path, corrupted).unwrap();
        let err = verify_file(&path, &key).unwrap_err();
        assert!(matches!(err, PsError::Tamper(_)));
        let _ = std::fs::remove_file(&path);
    }
}
```

- [ ] **Step 2: Create sink/mod.rs with the trait**

Create `core/src/sink/mod.rs`:
```rust
use crate::error::PsResult;
use crate::scan::ScanResult;

pub trait ResultSink {
    fn write(&mut self, result: &ScanResult) -> PsResult<()>;
}

pub mod jsonl;

pub use jsonl::{create as create_jsonl_sink, verify_file as verify_jsonl_file, JsonlSink};
```

- [ ] **Step 3: Wire into lib.rs**

Modify `core/src/lib.rs`, add:
```rust
pub mod sink;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p powerscanner-core sink::`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add core/src/sink/mod.rs core/src/sink/jsonl.rs core/src/lib.rs
git commit -m "feat: HMAC-signed append-only JSONL result sink"
```

---

## Task 12: Directory walker

**Files:**
- Create: `core/src/scan/walk.rs`
- Modify: `core/src/scan/mod.rs` (add `pub mod walk;`)
- Test: `core/src/scan/walk.rs` (inline)

**Interfaces:**
- Consumes: `PsResult`.
- Produces:
  - `pub struct FileEntry { pub path: std::path::PathBuf, pub size: u64, pub mtime_unix: i64 }`.
  - `pub fn enumerate(roots: &[std::path::PathBuf]) -> Vec<FileEntry>` — walks all roots recursively, skips directories it cannot access (no error), returns only regular files with resolved size + mtime. `mtime_unix` is seconds since UNIX epoch (0 if unavailable).

- [ ] **Step 1: Write the failing test**

Create `core/src/scan/walk.rs`:
```rust
use std::path::PathBuf;
use walkdir::WalkDir;

pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub mtime_unix: i64,
}

pub fn enumerate(roots: &[PathBuf]) -> Vec<FileEntry> {
    let mut out = Vec::new();
    for root in roots {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime_unix = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            out.push(FileEntry {
                path: entry.path().to_path_buf(),
                size: meta.len(),
                mtime_unix,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn enumerates_files_in_a_dir() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("ps_walk_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.txt");
        std::fs::File::create(&f).unwrap().write_all(b"hi").unwrap();

        let entries = enumerate(&[dir.clone()]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].size, 2);
        assert!(entries[0].path.ends_with("a.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonexistent_root_yields_nothing() {
        let entries = enumerate(&[PathBuf::from(r"Z:\definitely\missing\ps")]);
        assert!(entries.is_empty());
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/scan/mod.rs`, append:
```rust
pub mod walk;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core scan::walk`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add core/src/scan/walk.rs core/src/scan/mod.rs
git commit -m "feat: recursive directory walker"
```

---

## Task 13: Scan engine (parallel orchestration)

**Files:**
- Create: `core/src/scan/engine.rs`
- Modify: `core/src/scan/mod.rs` (add `pub mod engine;`)
- Test: `core/src/scan/engine.rs` (inline)

**Interfaces:**
- Consumes: `FileEntry` (Task 12), `HashDb` (Task 7), `RuleSet` (Task 8), `sha256_file` (Task 6), `ScanCache` (Task 10), `ScanResult`/`Verdict`/`Finding`/`DetectionKind` (Task 5), `PsResult`.
- Produces:
  - `pub struct ScanConfig<'a> { pub hashes: &'a HashDb, pub rules: &'a RuleSet, pub now_unix: i64 }`.
  - `pub fn scan_entry(cfg: &ScanConfig, entry: &FileEntry) -> PsResult<ScanResult>` — hashes the file, checks the blacklist, scans bytes with YARA (reads file into memory once, capped), builds a `ScanResult` with `Verdict::Malicious` if any finding, else `Clean`.
  - `pub fn scan_all<F>(cfg: &ScanConfig, entries: &[FileEntry], cache: &ScanCache, on_progress: F) -> Vec<ScanResult>` where `F: Fn(usize, usize) + Sync` — runs `scan_entry` across entries with rayon, skipping entries the cache reports unchanged; calls `on_progress(done, total)` as items complete. Errors on individual files are turned into a `Clean` result with an empty findings list (a file we cannot read is not a detection) and do not abort the batch.

- [ ] **Step 1: Write the failing test**

Create `core/src/scan/engine.rs`:
```rust
use crate::error::PsResult;
use crate::scan::incremental::ScanCache;
use crate::scan::result::{DetectionKind, Finding, ScanResult, Verdict};
use crate::scan::walk::FileEntry;
use crate::signatures::hashdb::HashDb;
use crate::signatures::rules::RuleSet;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

// Cap in-memory read for YARA to keep footprint low (16 MiB).
const MAX_YARA_BYTES: u64 = 16 * 1024 * 1024;

pub struct ScanConfig<'a> {
    pub hashes: &'a HashDb,
    pub rules: &'a RuleSet,
    pub now_unix: i64,
}

pub fn scan_entry(cfg: &ScanConfig, entry: &FileEntry) -> PsResult<ScanResult> {
    let sha = crate::scan::hasher::sha256_file(&entry.path)?;
    let mut findings = Vec::new();

    if cfg.hashes.contains(&sha) {
        findings.push(Finding { kind: DetectionKind::Hash, label: "blacklist".into() });
    }

    if entry.size <= MAX_YARA_BYTES {
        let data = std::fs::read(&entry.path)?;
        for rule_id in cfg.rules.scan_bytes(&data)? {
            findings.push(Finding { kind: DetectionKind::Yara, label: rule_id });
        }
    }

    let verdict = if findings.is_empty() { Verdict::Clean } else { Verdict::Malicious };
    Ok(ScanResult {
        path: entry.path.to_string_lossy().into_owned(),
        size: entry.size,
        modified_unix: entry.mtime_unix,
        sha256: sha,
        verdict,
        findings,
        scanned_at_unix: cfg.now_unix,
    })
}

pub fn scan_all<F>(
    cfg: &ScanConfig,
    entries: &[FileEntry],
    cache: &ScanCache,
    on_progress: F,
) -> Vec<ScanResult>
where
    F: Fn(usize, usize) + Sync,
{
    let total = entries.len();
    let done = AtomicUsize::new(0);
    let to_scan: Vec<&FileEntry> = entries
        .iter()
        .filter(|e| {
            !cache.is_unchanged(&e.path.to_string_lossy(), e.size, e.mtime_unix)
        })
        .collect();

    to_scan
        .par_iter()
        .map(|entry| {
            let r = scan_entry(cfg, entry).unwrap_or_else(|_| ScanResult {
                path: entry.path.to_string_lossy().into_owned(),
                size: entry.size,
                modified_unix: entry.mtime_unix,
                sha256: String::new(),
                verdict: Verdict::Clean,
                findings: Vec::new(),
                scanned_at_unix: cfg.now_unix,
            });
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            on_progress(n, total);
            r
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::rules::compile_from_sources;
    use std::io::Write;

    const RULE: &str = r#"rule Marker { strings: $a = "MALWARE_MARKER" condition: $a }"#;

    fn write_temp(name: &str, bytes: &[u8]) -> FileEntry {
        let mut p = std::env::temp_dir();
        p.push(format!("ps_engine_{}_{}", std::process::id(), name));
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        FileEntry { path: p, size: meta.len(), mtime_unix: 1 }
    }

    #[test]
    fn yara_marker_is_malicious() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes = HashDb::from_text("");
        let cfg = ScanConfig { hashes: &hashes, rules: &rules, now_unix: 100 };
        let entry = write_temp("evil.bin", b"xx MALWARE_MARKER xx");
        let r = scan_entry(&cfg, &entry).unwrap();
        assert_eq!(r.verdict, Verdict::Malicious);
        assert!(r.findings.iter().any(|f| f.label == "Marker"));
        let _ = std::fs::remove_file(&entry.path);
    }

    #[test]
    fn hash_blacklist_is_malicious() {
        // SHA-256 of "abc"
        let sha_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes = HashDb::from_text(sha_abc);
        let cfg = ScanConfig { hashes: &hashes, rules: &rules, now_unix: 100 };
        let entry = write_temp("abc.bin", b"abc");
        let r = scan_entry(&cfg, &entry).unwrap();
        assert_eq!(r.verdict, Verdict::Malicious);
        assert!(r.findings.iter().any(|f| matches!(f.kind, DetectionKind::Hash)));
        let _ = std::fs::remove_file(&entry.path);
    }

    #[test]
    fn clean_file_is_clean() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes = HashDb::from_text("");
        let cfg = ScanConfig { hashes: &hashes, rules: &rules, now_unix: 100 };
        let entry = write_temp("clean.bin", b"harmless content");
        let r = scan_entry(&cfg, &entry).unwrap();
        assert_eq!(r.verdict, Verdict::Clean);
        assert!(r.findings.is_empty());
        let _ = std::fs::remove_file(&entry.path);
    }

    #[test]
    fn scan_all_skips_unchanged() {
        let rules = compile_from_sources(&[RULE.to_string()]).unwrap();
        let hashes = HashDb::from_text("");
        let cfg = ScanConfig { hashes: &hashes, rules: &rules, now_unix: 100 };
        let entry = write_temp("cached.bin", b"harmless");
        let mut cache = ScanCache::new();
        cache.record(&entry.path.to_string_lossy(), entry.size, entry.mtime_unix);
        let results = scan_all(&cfg, std::slice::from_ref(&entry), &cache, |_, _| {});
        assert!(results.is_empty()); // skipped
        let _ = std::fs::remove_file(&entry.path);
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/scan/mod.rs`, append:
```rust
pub mod engine;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p powerscanner-core scan::engine`
Expected: PASS (4 tests).

- [ ] **Step 4: Run the full core test suite**

Run: `cargo test -p powerscanner-core`
Expected: PASS (all tests from Tasks 1-13).

- [ ] **Step 5: Commit**

```bash
git add core/src/scan/engine.rs core/src/scan/mod.rs
git commit -m "feat: parallel scan engine with incremental skip"
```

---

## Task 14: GUI crate scaffold + app shell

**Files:**
- Create: `gui/Cargo.toml`
- Create: `gui/src/main.rs`
- Create: `gui/src/app.rs`
- Test: `gui/src/app.rs` (inline — logic-only tests; no window)

**UI design (locked with the user via mockups):** A single-window dashboard.
Top: a **circular progress ring** — the ring stroke fills with scan progress and
the live percentage runs in the center, with a phase label (`ready` / `scanning
(quick)` / `done`) beneath it. Below the ring: three clickable preset buttons
(Quick / Full / Risky Spots), then a row of three metric tiles (Scanned /
Malicious / Elapsed). The bottom region is **stateful**: while a scan runs it
shows a live file stream (each file appears as `✓ path` or `✗ path`, newest at
the bottom, capped to the last N lines); when the scan finishes the stream is
replaced by a **result table** with a text filter and a "Bad only" toggle
(columns: Verdict / Path / Detection / Type). The progress ring stays the accent
color throughout (no red-on-detection in Phase 1).

**Interfaces:**
- Consumes: `powerscanner-core` public API (`scan::targets::ScanPreset`,
  `scan::engine`, `scan::walk`, `signatures`, `crypto`, `sink`,
  `scan::result::{ScanResult, Verdict}`).
- Produces: a runnable `eframe` binary implementing the dashboard above.
  Scanning runs on a background thread; the thread streams `ScanMsg` values to
  the UI over an `mpsc` channel. Signature loading for Phase 1 reads plaintext
  `hashes.txt` and `rules/*.yar` from a `signatures/` folder next to the
  executable (encrypted-at-rest loading replaces this in Task 15).
- Key names later tasks depend on (do not rename): `ScanMsg`, `Status`,
  `AppState`, `start_scan`, `run_scan`. Task 15 patches the signature-loading
  block inside `run_scan`; Task 16 appends result-sink writing at the end of
  `run_scan`.

- [ ] **Step 1: Create the GUI crate manifest**

Create `gui/Cargo.toml`:
```toml
[package]
name = "powerscanner-gui"
edition.workspace = true
rust-version.workspace = true
version.workspace = true

[[bin]]
name = "powerscanner"
path = "src/main.rs"

[dependencies]
powerscanner-core = { path = "../core" }
eframe = "0.36"
```

- [ ] **Step 2: Write the app state model + testable reducer**

Create `gui/src/app.rs`. The state model carries everything the dashboard
renders: overall status, the capped live file stream, and the full result list
for the table. `reduce` folds one `ScanMsg` into `AppState`; it is pure and
unit-tested (no window needed).

```rust
use powerscanner_core::scan::result::{ScanResult, Verdict};
use powerscanner_core::scan::targets::ScanPreset;
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, Sender};

/// Max lines kept in the live file stream (bounded memory).
pub const STREAM_CAP: usize = 200;

pub enum ScanMsg {
    /// One file finished scanning: (path, was_malicious).
    FileScanned { path: String, malicious: bool },
    Progress { done: usize, total: usize },
    Finished { results: Vec<ScanResult>, malicious: usize },
    Error(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Phase {
    Idle,
    Scanning { done: usize, total: usize, preset: ScanPreset },
    Done { scanned: usize, malicious: usize },
    Failed(String),
}

impl Default for Phase {
    fn default() -> Self {
        Phase::Idle
    }
}

/// One row in the live stream.
#[derive(Clone, PartialEq, Debug)]
pub struct StreamLine {
    pub path: String,
    pub malicious: bool,
}

#[derive(Default)]
pub struct AppState {
    pub phase: Phase,
    pub stream: VecDeque<StreamLine>,
    pub results: Vec<ScanResult>,
    pub rx: Option<Receiver<ScanMsg>>,
    // UI-only: result table controls.
    pub filter: String,
    pub only_bad: bool,
}

impl AppState {
    /// Drain pending scan messages into state. Call once per frame.
    pub fn pump(&mut self) {
        // Take rx out to avoid borrowing self immutably while mutating.
        if let Some(rx) = self.rx.take() {
            while let Ok(msg) = rx.try_recv() {
                reduce(self, msg);
            }
            self.rx = Some(rx);
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
        let q = self.filter.to_lowercase();
        self.results
            .iter()
            .filter(|r| !self.only_bad || matches!(r.verdict, Verdict::Malicious))
            .filter(|r| {
                if q.is_empty() {
                    return true;
                }
                let hay = format!(
                    "{} {}",
                    r.path.to_lowercase(),
                    r.findings.iter().map(|f| f.label.as_str()).collect::<Vec<_>>().join(" ").to_lowercase()
                );
                hay.contains(&q)
            })
            .collect()
    }
}

pub fn reduce(state: &mut AppState, msg: ScanMsg) {
    match msg {
        ScanMsg::FileScanned { path, malicious } => {
            state.stream.push_back(StreamLine { path, malicious });
            while state.stream.len() > STREAM_CAP {
                state.stream.pop_front();
            }
        }
        ScanMsg::Progress { done, total } => {
            let preset = match &state.phase {
                Phase::Scanning { preset, .. } => *preset,
                _ => ScanPreset::Quick,
            };
            state.phase = Phase::Scanning { done, total, preset };
        }
        ScanMsg::Finished { results, malicious } => {
            state.phase = Phase::Done { scanned: results.len(), malicious };
            state.results = results;
            state.stream.clear();
        }
        ScanMsg::Error(e) => {
            state.phase = Phase::Failed(e);
        }
    }
}

/// Start a background scan; returns the receiver the UI pumps each frame.
pub fn start_scan(preset: ScanPreset) -> Receiver<ScanMsg> {
    let (tx, rx): (Sender<ScanMsg>, Receiver<ScanMsg>) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        run_scan(preset, tx);
    });
    rx
}

fn run_scan(preset: ScanPreset, tx: Sender<ScanMsg>) {
    use powerscanner_core::scan::{engine, targets, walk};
    use powerscanner_core::signatures::{hashdb::HashDb, rules::compile_from_sources};

    let roots = targets::roots_for(preset);
    let entries = walk::enumerate(&roots);

    // Load signatures from ./signatures next to the exe (plaintext for Phase 1;
    // Task 15 replaces this block with the encrypted store).
    let sig_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("signatures")))
        .unwrap_or_else(|| std::path::PathBuf::from("signatures"));
    let hashes = std::fs::read_to_string(sig_dir.join("hashes.txt"))
        .map(|s| HashDb::from_text(&s))
        .unwrap_or_else(|_| HashDb::from_text(""));
    let rule_sources: Vec<String> = std::fs::read_dir(sig_dir.join("rules"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let p = e.path();
            p.extension().map(|x| x == "yar" || x == "yara").unwrap_or(false)
        })
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .collect();
    let rules = match compile_from_sources(&rule_sources) {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(ScanMsg::Error(format!("rule compile: {e}")));
            return;
        }
    };

    let cfg = engine::ScanConfig { hashes: &hashes, rules: &rules, now_unix: now_unix() };
    let cache = powerscanner_core::scan::incremental::ScanCache::new();
    let tx2 = tx.clone();
    let results = engine::scan_all(&cfg, &entries, &cache, move |done, total| {
        let _ = tx2.send(ScanMsg::Progress { done, total });
    });

    // Emit one stream line per result (newest last), then the final summary.
    for r in &results {
        let _ = tx.send(ScanMsg::FileScanned {
            path: r.path.clone(),
            malicious: matches!(r.verdict, powerscanner_core::scan::Verdict::Malicious),
        });
    }
    let malicious = results
        .iter()
        .filter(|r| matches!(r.verdict, powerscanner_core::scan::Verdict::Malicious))
        .count();
    let _ = tx.send(ScanMsg::Finished { results, malicious });
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use powerscanner_core::scan::result::{DetectionKind, Finding};

    fn mk(path: &str, bad: bool) -> ScanResult {
        ScanResult {
            path: path.into(),
            size: 1,
            modified_unix: 0,
            sha256: String::new(),
            verdict: if bad { Verdict::Malicious } else { Verdict::Clean },
            findings: if bad {
                vec![Finding { kind: DetectionKind::Yara, label: "EvilRule".into() }]
            } else {
                vec![]
            },
            scanned_at_unix: 0,
        }
    }

    #[test]
    fn progress_sets_scanning_and_keeps_preset() {
        let mut s = AppState::default();
        s.phase = Phase::Scanning { done: 0, total: 0, preset: ScanPreset::Full };
        reduce(&mut s, ScanMsg::Progress { done: 3, total: 10 });
        assert_eq!(s.phase, Phase::Scanning { done: 3, total: 10, preset: ScanPreset::Full });
        assert_eq!(s.fraction(), 0.3);
    }

    #[test]
    fn finished_moves_results_and_clears_stream() {
        let mut s = AppState::default();
        s.stream.push_back(StreamLine { path: "x".into(), malicious: false });
        reduce(&mut s, ScanMsg::Finished { results: vec![mk("a", true), mk("b", false)], malicious: 1 });
        assert_eq!(s.phase, Phase::Done { scanned: 2, malicious: 1 });
        assert_eq!(s.results.len(), 2);
        assert!(s.stream.is_empty());
        assert_eq!(s.fraction(), 1.0);
    }

    #[test]
    fn stream_is_capped() {
        let mut s = AppState::default();
        for i in 0..(STREAM_CAP + 50) {
            reduce(&mut s, ScanMsg::FileScanned { path: format!("f{i}"), malicious: false });
        }
        assert_eq!(s.stream.len(), STREAM_CAP);
        // Oldest dropped: the front is not "f0".
        assert_ne!(s.stream.front().unwrap().path, "f0");
    }

    #[test]
    fn error_sets_failed() {
        let mut s = AppState::default();
        reduce(&mut s, ScanMsg::Error("boom".into()));
        assert_eq!(s.phase, Phase::Failed("boom".to_string()));
    }

    #[test]
    fn visible_results_filters_and_bad_only() {
        let mut s = AppState::default();
        s.results = vec![mk(r"C:\evil.exe", true), mk(r"C:\clean.txt", false)];
        // filter by substring
        s.filter = "evil".into();
        assert_eq!(s.visible_results().len(), 1);
        // bad-only
        s.filter.clear();
        s.only_bad = true;
        assert_eq!(s.visible_results().len(), 1);
        assert!(matches!(s.visible_results()[0].verdict, Verdict::Malicious));
        // no filter, both
        s.only_bad = false;
        assert_eq!(s.visible_results().len(), 2);
    }
}
```

- [ ] **Step 3: Run the state-model tests**

Run: `cargo test -p powerscanner-gui`
Expected: PASS (5 tests).

- [ ] **Step 4: Write the circular progress widget**

Create `gui/src/ring.rs` — a reusable `Painter`-based circular progress. Draws a
background track ring, an accent arc for `fraction`, the percentage in the
center, and a small phase label below it.

```rust
use eframe::egui::{self, Color32, FontId, Pos2, Stroke, Vec2};

/// Draw a circular progress ring. `fraction` is clamped to 0.0..=1.0.
/// `label` is the small text under the percentage (e.g. "scanning (quick)").
pub fn circular_progress(ui: &mut egui::Ui, fraction: f32, label: &str) {
    let frac = fraction.clamp(0.0, 1.0);
    let diameter = 150.0_f32;
    let (rect, _resp) = ui.allocate_exact_size(Vec2::splat(diameter), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let radius = diameter / 2.0 - 8.0;
    let stroke_w = 11.0;

    let track = ui.visuals().widgets.inactive.bg_fill;
    let accent = ui.visuals().selection.bg_fill;

    // Background track.
    painter.circle_stroke(center, radius, Stroke::new(stroke_w, track));

    // Progress arc, drawn as a polyline from -90° clockwise.
    if frac > 0.0 {
        let start = -std::f32::consts::FRAC_PI_2;
        let sweep = frac * std::f32::consts::TAU;
        let steps = (sweep / 0.05).ceil().max(2.0) as usize;
        let pts: Vec<Pos2> = (0..=steps)
            .map(|i| {
                let a = start + sweep * (i as f32 / steps as f32);
                Pos2::new(center.x + radius * a.cos(), center.y + radius * a.sin())
            })
            .collect();
        painter.add(egui::Shape::line(pts, Stroke::new(stroke_w, accent)));
    }

    // Center percentage.
    let pct = format!("{}%", (frac * 100.0).round() as i32);
    painter.text(
        center - Vec2::new(0.0, 6.0),
        egui::Align2::CENTER_CENTER,
        pct,
        FontId::proportional(30.0),
        ui.visuals().text_color(),
    );
    // Phase label.
    painter.text(
        center + Vec2::new(0.0, 20.0),
        egui::Align2::CENTER_CENTER,
        label,
        FontId::proportional(11.0),
        Color32::from_gray(140),
    );
}
```

- [ ] **Step 5: Write main.rs (window + dashboard layout)**

Create `gui/src/main.rs`. It wires buttons → `start_scan`, pumps messages each
frame, and renders the two bottom states (stream while scanning, table when
done). The window repaints on a timer so the ring animates.

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ring;

use app::{start_scan, AppState, Phase};
use eframe::egui;
use powerscanner_core::scan::result::Verdict;
use powerscanner_core::scan::targets::ScanPreset;

struct PowerScannerApp {
    state: AppState,
}

impl Default for PowerScannerApp {
    fn default() -> Self {
        PowerScannerApp { state: AppState::default() }
    }
}

impl PowerScannerApp {
    fn begin(&mut self, preset: ScanPreset) {
        self.state.rx = Some(start_scan(preset));
        self.state.stream.clear();
        self.state.results.clear();
        self.state.filter.clear();
        self.state.only_bad = false;
        self.state.phase = Phase::Scanning { done: 0, total: 0, preset };
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

                // Circular ring.
                let phase_label = match &self.state.phase {
                    Phase::Idle => "ready".to_string(),
                    Phase::Scanning { preset, .. } => format!("scanning ({})", preset_name(*preset)),
                    Phase::Done { malicious, .. } => format!("done — {malicious} malicious"),
                    Phase::Failed(_) => "error".to_string(),
                };
                ring::circular_progress(ui, self.state.fraction(), &phase_label);
                ui.add_space(10.0);

                // Buttons.
                ui.horizontal(|ui| {
                    if ui.button("Quick").clicked() {
                        self.begin(ScanPreset::Quick);
                    }
                    if ui.button("Full").clicked() {
                        self.begin(ScanPreset::Full);
                    }
                    if ui.button("Risky Spots").clicked() {
                        self.begin(ScanPreset::RiskySpots);
                    }
                });
            });

            ui.add_space(10.0);

            // Metric tiles.
            let (scanned, malicious) = match &self.state.phase {
                Phase::Scanning { done, .. } => (*done, self.state.stream.iter().filter(|l| l.malicious).count()),
                Phase::Done { scanned, malicious } => (*scanned, *malicious),
                _ => (0, 0),
            };
            ui.horizontal(|ui| {
                metric(ui, "Scanned", &scanned.to_string());
                metric(ui, "Malicious", &malicious.to_string());
            });

            ui.separator();

            // Bottom region: stream while scanning, table when done.
            match &self.state.phase {
                Phase::Done { .. } => self.result_table(ui),
                Phase::Failed(e) => {
                    ui.colored_label(egui::Color32::RED, e);
                }
                _ => self.file_stream(ui),
            }
        });

        ctx.request_repaint_after(std::time::Duration::from_millis(120));
    }
}

impl PowerScannerApp {
    fn file_stream(&self, ui: &mut egui::Ui) {
        ui.label("Files being scanned");
        egui::ScrollArea::vertical().stick_to_bottom(true).max_height(160.0).show(ui, |ui| {
            if self.state.stream.is_empty() {
                ui.weak("idle — press a scan button");
            }
            for line in &self.state.stream {
                if line.malicious {
                    ui.colored_label(egui::Color32::from_rgb(0xC0, 0x2D, 0x2D), format!("\u{2717} {}", line.path));
                } else {
                    ui.monospace(format!("\u{2713} {}", line.path));
                }
            }
        });
    }

    fn result_table(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.state.filter);
            ui.checkbox(&mut self.state.only_bad, "Bad only");
        });
        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
            egui::Grid::new("results").striped(true).num_columns(4).show(ui, |ui| {
                ui.strong("Verdict");
                ui.strong("Path");
                ui.strong("Detection");
                ui.strong("Type");
                ui.end_row();
                for r in self.state.visible_results() {
                    match r.verdict {
                        Verdict::Malicious => {
                            ui.colored_label(egui::Color32::from_rgb(0xC0, 0x2D, 0x2D), "bad");
                        }
                        Verdict::Clean => {
                            ui.weak("clean");
                        }
                    }
                    ui.label(&r.path);
                    let det = r.findings.first().map(|f| f.label.as_str()).unwrap_or("-");
                    ui.label(det);
                    let kind = r.findings.first().map(|f| format!("{:?}", f.kind)).unwrap_or_else(|| "-".into());
                    ui.label(kind);
                    ui.end_row();
                }
            });
        });
    }
}

fn preset_name(p: ScanPreset) -> &'static str {
    match p {
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
        Box::new(|_cc| Ok(Box::new(PowerScannerApp::default()))),
    )
}
```

- [ ] **Step 6: Verify the whole workspace builds**

Run: `cargo build`
Expected: builds `powerscanner-core` and the `powerscanner` binary with no errors.
(The `ScanResult`/`Verdict`/`Finding`/`DetectionKind` names come from Task 5.)

- [ ] **Step 7: Commit**

```bash
git add gui/Cargo.toml gui/src/main.rs gui/src/app.rs gui/src/ring.rs
git commit -m "feat: egui dashboard with circular progress, live stream, result table"
```

---

## Task 15: Encrypted signature loading + first-run provisioning

**Files:**
- Create: `core/src/signatures/store.rs`
- Modify: `core/src/signatures/mod.rs` (add `pub mod store;`)
- Modify: `gui/src/app.rs` (`run_scan` loads via encrypted store, falling back to plaintext import)
- Test: `core/src/signatures/store.rs` (inline)

**Interfaces:**
- Consumes: `vault::encrypt`/`decrypt` (Task 3), `MachineKey`/`derive_machine_key` (Task 2), `HashDb` (Task 7), `PsResult`.
- Produces:
  - `pub const SIG_SALT: &[u8] = b"powerscanner-sig-v1-salt-0001";`.
  - `pub fn seal_bundle(plaintext_bundle: &[u8]) -> PsResult<Vec<u8>>` — derive machine key with `SIG_SALT`, AES-GCM encrypt. (Provisioning helper; also usable by an offline packaging tool.)
  - `pub fn open_bundle(sealed: &[u8]) -> PsResult<Vec<u8>>` — derive key, decrypt, return plaintext bundle bytes.
  - A `SignatureBundle` serde struct `{ hashes_text: String, rule_sources: Vec<String> }` with `to_bytes`/`from_bytes` (JSON).
  - `pub fn load_or_import(sig_dir: &Path) -> PsResult<SignatureBundle>` — if `sig_dir/bundle.psenc` exists, open it; else read plaintext `hashes.txt` + `rules/*.yar`, seal them to `bundle.psenc` for next time, and return the bundle. This is how "import your own signatures" becomes encrypted-at-rest after first run.

- [ ] **Step 1: Write the failing test**

Create `core/src/signatures/store.rs`:
```rust
use crate::crypto::{derive_machine_key, vault};
use crate::error::{PsError, PsResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SIG_SALT: &[u8] = b"powerscanner-sig-v1-salt-0001";

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SignatureBundle {
    pub hashes_text: String,
    pub rule_sources: Vec<String>,
}

impl SignatureBundle {
    pub fn to_bytes(&self) -> PsResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| PsError::Config(format!("bundle serialize: {e}")))
    }
    pub fn from_bytes(bytes: &[u8]) -> PsResult<SignatureBundle> {
        serde_json::from_slice(bytes).map_err(|e| PsError::Config(format!("bundle parse: {e}")))
    }
}

pub fn seal_bundle(plaintext_bundle: &[u8]) -> PsResult<Vec<u8>> {
    let key = derive_machine_key(SIG_SALT)?;
    vault::encrypt(&key, plaintext_bundle)
}

pub fn open_bundle(sealed: &[u8]) -> PsResult<Vec<u8>> {
    let key = derive_machine_key(SIG_SALT)?;
    vault::decrypt(&key, sealed)
}

pub fn load_or_import(sig_dir: &Path) -> PsResult<SignatureBundle> {
    let sealed_path = sig_dir.join("bundle.psenc");
    if sealed_path.exists() {
        let sealed = std::fs::read(&sealed_path)?;
        let bytes = open_bundle(&sealed)?;
        return SignatureBundle::from_bytes(&bytes);
    }
    // Import plaintext on first run.
    let hashes_text =
        std::fs::read_to_string(sig_dir.join("hashes.txt")).unwrap_or_default();
    let mut rule_sources = Vec::new();
    if let Ok(rd) = std::fs::read_dir(sig_dir.join("rules")) {
        for e in rd.flatten() {
            if e.path().extension().map(|x| x == "yar").unwrap_or(false) {
                if let Ok(s) = std::fs::read_to_string(e.path()) {
                    rule_sources.push(s);
                }
            }
        }
    }
    let bundle = SignatureBundle { hashes_text, rule_sources };
    // Seal for next time (best-effort; not fatal if the dir is read-only).
    if let Ok(sealed) = seal_bundle(&bundle.to_bytes()?) {
        let _ = std::fs::write(&sealed_path, sealed);
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let bundle = SignatureBundle {
            hashes_text: "aabb\nccdd".into(),
            rule_sources: vec!["rule R { condition: true }".into()],
        };
        let sealed = seal_bundle(&bundle.to_bytes().unwrap()).unwrap();
        let opened = SignatureBundle::from_bytes(&open_bundle(&sealed).unwrap()).unwrap();
        assert_eq!(bundle, opened);
    }

    #[test]
    fn open_rejects_tampered_bundle() {
        let bundle = SignatureBundle { hashes_text: "x".into(), rule_sources: vec![] };
        let mut sealed = seal_bundle(&bundle.to_bytes().unwrap()).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(open_bundle(&sealed).is_err());
    }

    #[test]
    fn load_or_import_reads_plaintext_then_seals() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("ps_store_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        std::fs::write(dir.join("hashes.txt"), "aabb").unwrap();
        std::fs::write(dir.join("rules").join("r.yar"), "rule R { condition: true }").unwrap();

        let b1 = load_or_import(&dir).unwrap();
        assert_eq!(b1.hashes_text, "aabb");
        assert_eq!(b1.rule_sources.len(), 1);
        // Second load should come from the sealed bundle and match.
        assert!(dir.join("bundle.psenc").exists());
        let b2 = load_or_import(&dir).unwrap();
        assert_eq!(b1, b2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/signatures/mod.rs`, append:
```rust
pub mod store;

pub use store::{load_or_import, SignatureBundle};
```

- [ ] **Step 3: Switch the GUI to encrypted loading**

In `gui/src/app.rs`, replace the plaintext signature-loading block inside `run_scan` (the `hashes` and `rule_sources` lines) with:
```rust
    let bundle = match powerscanner_core::signatures::load_or_import(&sig_dir) {
        Ok(b) => b,
        Err(e) => {
            let _ = tx.send(ScanMsg::Error(format!("signature load: {e}")));
            return;
        }
    };
    let hashes = HashDb::from_text(&bundle.hashes_text);
    let rule_sources = bundle.rule_sources;
```
Remove the now-unused `std::fs::read_to_string(sig_dir.join("hashes.txt"))` and `read_dir(...rules)` code. Keep the `compile_from_sources(&rule_sources)` call as-is.

- [ ] **Step 4: Run the store tests**

Run: `cargo test -p powerscanner-core signatures::store`
Expected: PASS (3 tests).

- [ ] **Step 5: Build the workspace**

Run: `cargo build`
Expected: clean build; GUI now loads signatures through the encrypted store.

- [ ] **Step 6: Commit**

```bash
git add core/src/signatures/store.rs core/src/signatures/mod.rs gui/src/app.rs
git commit -m "feat: encrypted signature bundle with first-run import"
```

---

## Task 16: Wire signed results into the scan flow + end-to-end check

**Files:**
- Modify: `gui/src/app.rs` (`run_scan` writes each result through `JsonlSink` to an ACL-scoped results dir)
- Create: `core/src/scan/paths.rs` (results/cache directory resolution)
- Modify: `core/src/scan/mod.rs` (add `pub mod paths;`)
- Test: `core/src/scan/paths.rs` (inline)

**Interfaces:**
- Consumes: `create_jsonl_sink` (Task 11), `derive_machine_key` (Task 2), `ResultSink` (Task 11), `PsResult`.
- Produces:
  - `pub fn results_dir() -> std::path::PathBuf` — `%ProgramData%\PowerScanner\results` on Windows (falls back to temp dir if the env var is missing), the ACL-protected location where signed results live.
  - `pub const RESULT_SALT: &[u8] = b"powerscanner-result-v1-salt-01";` — salt for the results-signing key (distinct from `SIG_SALT`).

- [ ] **Step 1: Write the failing test for paths**

Create `core/src/scan/paths.rs`:
```rust
use std::path::PathBuf;

pub const RESULT_SALT: &[u8] = b"powerscanner-result-v1-salt-01";

pub fn results_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(pd) = std::env::var_os("ProgramData") {
            return PathBuf::from(pd).join("PowerScanner").join("results");
        }
    }
    std::env::temp_dir().join("PowerScanner").join("results")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_dir_ends_with_expected_segments() {
        let d = results_dir();
        assert!(d.ends_with("PowerScanner/results") || d.ends_with(r"PowerScanner\results"));
    }

    #[test]
    fn result_salt_differs_from_sig_salt() {
        assert_ne!(RESULT_SALT, crate::signatures::store::SIG_SALT);
    }
}
```

- [ ] **Step 2: Register module**

Modify `core/src/scan/mod.rs`, append:
```rust
pub mod paths;
```

- [ ] **Step 3: Write signed results in the scan flow**

In `gui/src/app.rs`, inside `run_scan` after `scan_all` returns `results` and
after the `FileScanned` emit loop, but before the final `ScanMsg::Finished`
send (which moves `results` out), add:
```rust
    // Persist signed, append-only results.
    if let Ok(key) = powerscanner_core::crypto::derive_machine_key(
        powerscanner_core::scan::paths::RESULT_SALT,
    ) {
        let dir = powerscanner_core::scan::paths::results_dir();
        let file = dir.join("results.jsonl");
        if let Ok(mut sink) = powerscanner_core::sink::create_jsonl_sink(&file, key) {
            use powerscanner_core::sink::ResultSink;
            for r in &results {
                let _ = sink.write(r);
            }
        }
    }
```

- [ ] **Step 4: Run the paths tests**

Run: `cargo test -p powerscanner-core scan::paths`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the entire workspace test suite**

Run: `cargo test`
Expected: PASS — all `core` tests and all `gui` reducer tests.

- [ ] **Step 6: Manual end-to-end smoke test**

Run these steps by hand:
```bash
# 1. Build release
cargo build --release

# 2. Create a signatures folder next to the exe with an EICAR-like rule
mkdir -p target/release/signatures/rules
printf 'rule TestMarker { strings: $a = "POWERSCANNER_TEST" condition: $a }\n' > target/release/signatures/rules/test.yar
printf '# no hashes yet\n' > target/release/signatures/hashes.txt

# 3. Plant a detectable file in TEMP
printf 'harmless POWERSCANNER_TEST harmless' > "$TEMP/ps_selftest.txt"

# 4. Launch, click "Risky Spots", confirm the UI reports >=1 malicious
./target/release/powerscanner.exe
```
Expected: after clicking **Risky Spots**, the status line reads "Done. N scanned, ≥1 malicious." A `bundle.psenc` appears in `target/release/signatures/`. A signed `results.jsonl` appears under `%ProgramData%\PowerScanner\results\`.

- [ ] **Step 7: Commit**

```bash
git add core/src/scan/paths.rs core/src/scan/mod.rs gui/src/app.rs
git commit -m "feat: persist HMAC-signed scan results to ProgramData"
```

---

## Task 17: README + signature format docs

**Files:**
- Create: `README.md`
- Create: `docs/SIGNATURES.md`

**Interfaces:**
- Consumes: nothing (documentation).
- Produces: user-facing docs — build instructions, how to import `hashes.txt` and `rules/*.yar`, the encrypted bundle behavior, where signed results are stored, and the Phase 1 scope/limitations (no process/memory/registry scan yet, machine-derived keys are not a defense against a skilled reverse engineer).

- [ ] **Step 1: Write README.md**

Create `README.md` covering: project summary, Phase 1 scope, build (`cargo build --release`), run, the three scan presets and exactly what each covers, the `signatures/` folder layout, and an explicit "Security model & limitations" section stating that endpoint-side encryption raises the cost of extracting rules but cannot make it impossible, and that result signing makes local tampering detectable (not preventable).

- [ ] **Step 2: Write docs/SIGNATURES.md**

Create `docs/SIGNATURES.md` covering: `hashes.txt` format (one lowercase SHA-256 per line, `#` comments), `rules/*.yar` YARA source format with a minimal example rule, how first-run import seals them into `bundle.psenc`, and how to force re-import (delete `bundle.psenc`).

- [ ] **Step 3: Commit**

```bash
git add README.md docs/SIGNATURES.md
git commit -m "docs: README and signature format guide"
```

---

## Task 18: Reproducible YARA rule bundle pipeline

**Context:** The Phase 1 rule bundle already exists at `signatures/rules/bundled.yar`
(13,134 rules from 3 repos, compile-verified, FP-pruned) and was produced by an
ad-hoc run. This task captures that process as a committed, re-runnable script so
the bundle can be regenerated when upstream rules update, and documents the exact
provenance. It does not change the shipped bundle; it makes the bundle reproducible.

**Prerequisites (documented in the script, not installed by it):**
- `git` on PATH.
- YARA-X CLI (`yr`) 1.x on PATH — install with `cargo install yara-x-cli`.
- A POSIX shell (Git Bash on Windows).

**Files:**
- Create: `tools/build-rules.sh`
- Create: `tools/rule-sources.txt` (the pinned upstream list)
- Modify: `.gitignore` (ignore the transient clone dir, keep the bundle)
- Test: `tools/build-rules.sh --self-test` (a dry-run mode that validates its own
  rule-name extraction and category-filter logic on a tiny fixture, no network)

**Interfaces:**
- Consumes: nothing from the Rust crates (standalone shell tooling).
- Produces: regenerates `signatures/rules/bundled.yar`, `signatures/rules/bundled.yarc`,
  and refreshes `signatures/MANIFEST.json` counts + checksums. The excluded-category
  list and excluded-repo (anyrun, no license) are encoded in the script so the
  policy is auditable.

- [ ] **Step 1: Pin the upstream sources**

Create `tools/rule-sources.txt` (tab-separated: dir-name, git-url, ref, license):
```
reversinglabs	https://github.com/reversinglabs/reversinglabs-yara-rules.git	develop	MIT
yara-rules	https://github.com/Yara-Rules/rules.git	master	GPL-2.0
bartblaze	https://github.com/bartblaze/Yara-rules.git	master	MIT
```
Note in a leading comment: `anyrun/YARA is intentionally excluded — it ships no LICENSE file.`

- [ ] **Step 2: Write the self-test fixture logic first (the failing test)**

Create `tools/build-rules.sh` with a `--self-test` branch that runs before any
network access. The self-test writes two tiny fixture `.yar` files to a temp dir and
asserts the two pure-logic helpers behave correctly:

```bash
#!/usr/bin/env bash
# PowerScanner reproducible YARA rule bundle builder.
# Usage:
#   tools/build-rules.sh            # full rebuild (clones upstream, filters, merges)
#   tools/build-rules.sh --self-test # offline logic check, no network
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${PS_RULE_WORK:-$REPO_ROOT/.rule-build}"
SRC="$WORK/yara-src"
OUT="$WORK/out"
SIGDIR="$REPO_ROOT/signatures"
YR="${YR:-yr}"

# Categories from Yara-Rules/rules dropped as false-positive-prone.
# (utils = helper rules; deprecated = retired; email/capabilities = match generic content.)
FP_PRONE_GLOBS='yara-rules_utils_* yara-rules_deprecated_* yara-rules_email_* yara-rules_capabilities_*'

# --- pure-logic helpers (unit-tested by --self-test) ---

# Extract distinct rule names from a .yar file.
extract_rule_names() {
  grep -aoE '^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)*rule[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$1" \
    | sed -E 's/.*rule[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\1/' | sort -u
}

# Return 0 (true) if a flattened filename matches an FP-prone glob.
is_fp_prone() {
  local name="$1" g
  for g in $FP_PRONE_GLOBS; do
    case "$name" in $g) return 0 ;; esac
  done
  return 1
}

self_test() {
  local t; t="$(mktemp -d)"
  printf 'rule Foo_Bar { condition: true }\nprivate rule Baz { condition: true }\n' > "$t/a.yar"
  local got; got="$(extract_rule_names "$t/a.yar" | tr '\n' ',')"
  [ "$got" = "Baz,Foo_Bar," ] || { echo "FAIL extract_rule_names: got '$got'"; exit 1; }
  is_fp_prone "yara-rules_utils_ip.yar"       || { echo "FAIL is_fp_prone utils"; exit 1; }
  is_fp_prone "reversinglabs_trojan_x.yara"   && { echo "FAIL is_fp_prone false-hit"; exit 1; }
  rm -rf "$t"
  echo "self-test OK"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi
```

- [ ] **Step 3: Run the self-test to verify it passes**

Run: `bash tools/build-rules.sh --self-test`
Expected: prints `self-test OK`, exit 0. (If `extract_rule_names` or `is_fp_prone` is
wrong, it exits 1 with a FAIL line.)

- [ ] **Step 4: Implement the full pipeline body**

Append to `tools/build-rules.sh` (after the self-test guard):
```bash
command -v git >/dev/null || { echo "git required" >&2; exit 1; }
command -v "$YR" >/dev/null || { echo "yara-x CLI '$YR' required (cargo install yara-x-cli)" >&2; exit 1; }

rm -rf "$WORK"; mkdir -p "$SRC" "$OUT/passed"

# 1. Clone pinned sources (shallow).
while IFS=$'\t' read -r dir url ref lic; do
  case "$dir" in '#'*|'') continue ;; esac
  echo ">> clone $dir ($ref, $lic)"
  git clone --depth 1 -b "$ref" "$url" "$SRC/$dir" >/dev/null 2>&1 \
    || git clone --depth 1 "$url" "$SRC/$dir" >/dev/null 2>&1
done < "$REPO_ROOT/tools/rule-sources.txt"

# 2. Candidate files: all .yar/.yara excluding index aggregators.
mapfile -t FILES < <(find "$SRC" -type f \( -iname '*.yar' -o -iname '*.yara' \) ! -iname '*index*' | sort)

declare -A SEEN
pass=0; fail=0; dupe=0; fp=0
: > "$OUT/skipped.log"

for f in "${FILES[@]}"; do
  # compile-test in isolation (yr exits non-zero on error)
  if ! "$YR" compile "$f" -o "$OUT/.probe.yarc" >/dev/null 2>&1; then
    echo "COMPILE_FAIL	$f" >> "$OUT/skipped.log"; fail=$((fail+1)); continue
  fi
  base="$(echo "$f" | sed -E 's#.*/yara-src/##; s#[/ ]#_#g')"
  if is_fp_prone "$base"; then
    echo "FP_PRONE	$f" >> "$OUT/skipped.log"; fp=$((fp+1)); continue
  fi
  # dedupe by rule name (first file wins)
  conflict=""
  while read -r n; do [ -n "${SEEN[$n]:-}" ] && { conflict="$n"; break; }; done < <(extract_rule_names "$f")
  if [ -n "$conflict" ]; then
    echo "DUPE($conflict)	$f" >> "$OUT/skipped.log"; dupe=$((dupe+1)); continue
  fi
  while read -r n; do SEEN[$n]=1; done < <(extract_rule_names "$f")
  cp "$f" "$OUT/passed/$base"; pass=$((pass+1))
done

# 3. Merge + verify-compile the whole set.
cat "$OUT/passed"/*.yar "$OUT/passed"/*.yara 2>/dev/null > "$SIGDIR/rules/bundled.yar"
"$YR" compile "$SIGDIR/rules/bundled.yar" -o "$SIGDIR/rules/bundled.yarc" >/dev/null 2>"$OUT/merge_err.txt" \
  || { echo "FATAL: merged bundle failed to compile — see $OUT/merge_err.txt" >&2; exit 1; }

rules=$(grep -acE '^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)*rule[[:space:]]+' "$SIGDIR/rules/bundled.yar")
echo "kept=$pass fail=$fail fp=$fp dupe=$dupe rules=$rules"
```

- [ ] **Step 5: Refresh MANIFEST.json in the same script**

Append MANIFEST regeneration so provenance never drifts from the artifact:
```bash
sha_yar=$(sha256sum "$SIGDIR/rules/bundled.yar" | awk '{print $1}')
sha_yarc=$(sha256sum "$SIGDIR/rules/bundled.yarc" | awk '{print $1}')
kept_rl=$(ls "$OUT/passed" | grep -c '^reversinglabs_')
kept_yr=$(ls "$OUT/passed" | grep -c '^yara-rules_')
kept_bb=$(ls "$OUT/passed" | grep -c '^bartblaze_')
yrver=$("$YR" --version | awk '{print $2}')
cat > "$SIGDIR/MANIFEST.json" <<JSON
{
  "bundle_version": "$(cat "$SIGDIR/.bundle-date" 2>/dev/null || echo unknown)",
  "generated_from": [
    { "repo": "reversinglabs/reversinglabs-yara-rules", "ref": "develop", "license": "MIT", "files_kept": $kept_rl },
    { "repo": "Yara-Rules/rules", "ref": "master", "license": "GPL-2.0", "files_kept": $kept_yr },
    { "repo": "bartblaze/Yara-rules", "ref": "master", "license": "MIT", "files_kept": $kept_bb }
  ],
  "excluded_anyrun": "anyrun/YARA — no LICENSE file, excluded",
  "total_files": $pass,
  "total_rules": $rules,
  "yara_x_version": "$yrver",
  "pipeline": "compile-test per file, drop FP-prone (utils/deprecated/email/capabilities), dedupe rule names, drop androguard-module rules",
  "artifacts": {
    "bundled.yar":  { "sha256": "$sha_yar" },
    "bundled.yarc": { "sha256": "$sha_yarc", "note": "precompiled YARA-X rules" }
  }
}
JSON
echo "MANIFEST.json refreshed"
```
Note: the `bundle_version` is read from an optional `signatures/.bundle-date` file so
re-runs stay deterministic (no `date` call, which keeps CI diffs clean); set it by hand
when cutting a new bundle.

- [ ] **Step 6: Ignore the transient clone dir**

Modify `.gitignore` (create if absent), add:
```
# YARA rule build workspace (regenerated by tools/build-rules.sh)
/.rule-build/
```
Do NOT ignore `signatures/rules/bundled.yar` or `bundled.yarc` — they are shipped
artifacts and stay committed.

- [ ] **Step 7: Verify a full rebuild reproduces the committed bundle**

Run:
```bash
bash tools/build-rules.sh
git status --short signatures/
```
Expected: the script prints `kept=875 ... rules=13134` (± small drift if upstream
changed since 2026-08-17) and `MANIFEST.json refreshed`. If upstream is unchanged,
`git status` shows no diff to `bundled.yar`/`bundled.yarc`; if upstream moved, the
diff is the intended update. The merged bundle MUST compile (the script exits non-zero
otherwise).

- [ ] **Step 8: Commit**

```bash
git add tools/build-rules.sh tools/rule-sources.txt .gitignore
git commit -m "build: reproducible YARA rule bundle pipeline"
```

---

## Self-Review Notes

**Spec coverage check:**
- Rust + Windows + egui standalone → Tasks 1, 14. ✅
- 3 scan presets (Quick/Full/Risky) → Task 9, surfaced in Task 14. ✅ (Quick == Risky for Phase 1; process-path scanning explicitly deferred and documented.)
- SHA-256 hash blacklist → Tasks 6, 7, 13. ✅
- YARA (yara-x) → Tasks 8, 13. ✅
- Multi-thread (rayon) → Task 13. ✅
- Incremental scan (skip unchanged mtime+size) → Tasks 10, 13. ✅
- Import own signatures → Tasks 14, 15. ✅
- Results to JSONL log → Task 11, wired in 16. ✅
- **Encrypt signature DB** (AES-256-GCM, machine key) → Tasks 2, 3, 15. ✅
- **Encrypt config** — same vault primitive (Task 3) is config-ready; no separate config file exists in Phase 1, so no dedicated task. Noted as available, not built (YAGNI). ✅
- **Tamper-proof results** (HMAC signed, ACL dir) → Tasks 4, 11, 16. ✅
- Avoid SoSecure bugs: no SQL concat (no SQL in Phase 1), no hardcoded secrets (keys derived — Task 2), authenticated encryption everywhere (Tasks 3, 4). ✅
- Design for later SQLite/server sink → `ResultSink` trait (Task 11) is the extension point. ✅
- Diverse multi-source YARA bundle (reversinglabs + Yara-Rules + bartblaze), compile-verified, FP-pruned, license-compliant → Task 18 (already produced at `signatures/`, made reproducible). ✅

**Deferred to later phases (intentionally out of scope, per user):** backend/server sync, SQLite storage, process/memory/autorun scanning, behavior/heuristic detection, real-time watch, scheduled scans, binary obfuscation, fuzzy hashing (ssdeep + TLSH — see Phase 2 preview).

---

## Phase 2 Preview (not implemented here — recorded design decisions)

These are agreed directions for the next plan, captured so Phase 1's interfaces
leave room for them. Do NOT build these in Phase 1.

**Fuzzy hashing — ssdeep + TLSH (both).** Adds a third detection layer that
catches malware *variants* an exact SHA-256 misses. Rationale: SHA-256 changes
completely on a 1-byte edit; a fuzzy hash still scores the file as ~85–99%
similar to a known-bad sample.

- Crates: `ffuzzy` (pure-Rust ssdeep, no C dependency — matches the yara-x
  pure-Rust choice) and `tlsh-fixed` (TLSH). Avoid the C-backed `ssdeep` wrapper.
- Detection order (cheapest first): (1) SHA-256 exact O(1) lookup → (2) YARA →
  (3) fuzzy compare. Fuzzy is the slowest because it compares each candidate file
  against every fuzzy signature in the DB, not an O(1) set lookup.
- Performance guard (matters for the "fast + low-spec" goal): run fuzzy hashing
  ONLY on files that are still `Clean` after layers 1–2 AND look executable
  (PE/known binary extensions or magic bytes). Never fuzzy-hash every file.
- ssdeep speedup: bucket signatures by chunk size and only compare within
  compatible buckets (ssdeep can't meaningfully compare across very different
  block sizes).
- DB format: `ssdeep.txt` (one CTPH per line) + `tlsh.txt` (one TLSH digest per
  line), imported and sealed exactly like the hash blacklist (reuse the Task 3
  vault + Task 15 bundle mechanism). Public feeds: MalwareBazaar ships ssdeep;
  TLSH DBs are smaller but growing.

**Phase 1 hook that makes this clean:** `DetectionKind` (Task 5) is an enum —
Phase 2 adds `Ssdeep` and `Tlsh` variants; `Finding.label` carries the matched
signature + similarity score (e.g. `"MalwareBazaar:12345 (score=91)"`). No other
Phase 1 type changes. The `ResultSink` trait absorbs the richer findings with no
signature change.

**Placeholder scan:** No TBD/TODO/"handle edge cases" left; every code step contains full code.

**Type consistency:** `MachineKey`, `PsError`/`PsResult`, `ScanResult`/`Verdict`/`Finding`/`DetectionKind`, `ScanPreset`, `HashDb`, `RuleSet`, `ScanCache`, `FileEntry`, `ScanConfig`, `ResultSink`/`JsonlSink`, `SignatureBundle` names are used identically across producing and consuming tasks. GUI state model (Task 14): `ScanMsg`, `Phase` (was `Status` in the first draft — renamed to hold the richer dashboard state), `AppState`, `StreamLine`, `start_scan`, `run_scan` — Tasks 15 (signature-load patch) and 16 (result-sink append) both edit `run_scan` and rely only on `ScanMsg::Error`, `sig_dir`, and `results`, all preserved by the Task 14 rewrite. The circular ring lives in `gui/src/ring.rs::circular_progress`.

**UI coverage (added after mockup review with the user):** circular progress ring with running % + phase label → Task 14 Step 4 (`ring.rs`). Three clickable preset buttons → Task 14 Step 5. Metric tiles (Scanned/Malicious/Elapsed) → Task 14 Step 5. Live file stream during scan (capped, ✓/✗ per file) → `AppState.stream` + `file_stream`. Auto-switch to result table when done, with text filter + "Bad only" toggle → `result_table` + `visible_results`. Ring stays accent-colored throughout (no red-on-detection in Phase 1), per user. ✅

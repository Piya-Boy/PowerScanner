use crate::crypto::MachineKey;
use crate::error::{PsError, PsResult};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_BLOB_LEN: usize = NONCE_LEN + TAG_LEN;

pub fn encrypt(key: &MachineKey, plaintext: &[u8]) -> PsResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|error| PsError::Crypto(format!("aes-gcm key: {error}")))?;
    let nonce_bytes = generate_nonce()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|error| PsError::Crypto(format!("aes-gcm encrypt: {error}")))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub fn decrypt(key: &MachineKey, blob: &[u8]) -> PsResult<Vec<u8>> {
    if blob.len() < MIN_BLOB_LEN {
        return Err(PsError::Crypto("aes-gcm blob is too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|error| PsError::Crypto(format!("aes-gcm key: {error}")))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|error| PsError::Crypto(format!("aes-gcm decrypt/auth: {error}")))
}

fn generate_nonce() -> PsResult<[u8; NONCE_LEN]> {
    let mut nonce = [0_u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

#[cfg(windows)]
fn fill_random(destination: &mut [u8]) -> PsResult<()> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    let buffer_len = u32::try_from(destination.len())
        .map_err(|_| PsError::Crypto("OS random request exceeds Windows API limit".to_string()))?;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            buffer_len: u32,
            flags: u32,
        ) -> i32;
    }

    // SAFETY: BCryptGenRandom receives a valid writable buffer for exactly its declared length.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            destination.as_mut_ptr(),
            buffer_len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(PsError::Crypto(format!(
            "OS random generation failed with NTSTATUS 0x{:08x}",
            status as u32
        )));
    }

    Ok(())
}

#[cfg(unix)]
fn fill_random(destination: &mut [u8]) -> PsResult<()> {
    use std::io::Read;

    let mut random = std::fs::File::open("/dev/urandom")
        .map_err(|error| PsError::Crypto(format!("open OS random source: {error}")))?;
    random
        .read_exact(destination)
        .map_err(|error| PsError::Crypto(format!("read OS random source: {error}")))
}

#[cfg(not(any(windows, unix)))]
fn fill_random(_destination: &mut [u8]) -> PsResult<()> {
    Err(PsError::Crypto(
        "OS random generation is unsupported on this platform".to_string(),
    ))
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
        let plaintext = b"top secret rule bytes";

        let blob = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_and_short_blobs_are_rejected() {
        let key = test_key();
        let mut blob = encrypt(&key, b"data").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;

        assert!(matches!(decrypt(&key, &blob), Err(PsError::Crypto(_))));
        assert!(matches!(
            decrypt(&key, &[0; MIN_BLOB_LEN - 1]),
            Err(PsError::Crypto(_))
        ));
    }

    #[test]
    fn nonce_is_unique_across_calls() {
        let key = test_key();
        let first = encrypt(&key, b"same plaintext").unwrap();
        let second = encrypt(&key, b"same plaintext").unwrap();

        assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);
        assert_ne!(first, second);
    }
}

use crate::crypto::MachineKey;
use crate::error::{PsError, PsResult};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const MAC_LENGTH: usize = 32;
const MAC_HEX_LENGTH: usize = MAC_LENGTH * 2;

pub fn sign_line(key: &MachineKey, line: &str) -> String {
    let mut mac = new_hmac(key);
    mac.update(line.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_line(key: &MachineKey, line: &str, mac_hex: &str) -> PsResult<()> {
    if mac_hex.len() != MAC_HEX_LENGTH {
        return Err(PsError::Signature(format!(
            "bad mac hex length: expected {MAC_HEX_LENGTH}, got {}",
            mac_hex.len()
        )));
    }

    let expected = hex::decode(mac_hex)
        .map_err(|error| PsError::Signature(format!("bad mac hex: {error}")))?;

    let mut mac = new_hmac(key);
    mac.update(line.as_bytes());
    mac.verify_slice(&expected)
        .map_err(|_| PsError::Tamper("hmac mismatch on result line".to_string()))
}

fn new_hmac(key: &MachineKey) -> HmacSha256 {
    match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC-SHA256 accepts keys of any length"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_machine_key;

    fn key() -> MachineKey {
        match derive_machine_key(b"signer-test-salt-0000") {
            Ok(key) => key,
            Err(error) => panic!("failed to derive test key: {error}"),
        }
    }

    #[test]
    fn sign_then_verify_ok() {
        let key = key();
        let line = r#"{"path":"C:\\x.exe","verdict":"malicious"}"#;
        let mac = sign_line(&key, line);

        assert_eq!(mac.len(), MAC_HEX_LENGTH);
        assert!(mac.chars().all(|character| !character.is_ascii_uppercase()));
        assert!(verify_line(&key, line, &mac).is_ok());
    }

    #[test]
    fn modified_line_fails_verify() {
        let key = key();
        let mac = sign_line(&key, "original");

        assert!(matches!(
            verify_line(&key, "tampered", &mac),
            Err(PsError::Tamper(_))
        ));
    }

    #[test]
    fn bad_hex_is_signature_error() {
        let key = key();

        assert!(matches!(
            verify_line(&key, "x", &"z".repeat(MAC_HEX_LENGTH)),
            Err(PsError::Signature(_))
        ));
    }
}

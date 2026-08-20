use crate::error::{PsError, PsResult};
use argon2::{Algorithm, Argon2, Params, Version};

const KEY_LENGTH: usize = 32;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

pub struct MachineKey([u8; KEY_LENGTH]);

impl MachineKey {
    /// Wrap an already-derived 256-bit key for crypto APIs such as the vault.
    pub const fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

fn compose_machine_identifier(machine_guid: &str, volume_serial: u32) -> PsResult<String> {
    let machine_guid = machine_guid.trim();
    if machine_guid.is_empty() {
        return Err(PsError::Crypto("MachineGuid is empty".to_string()));
    }

    Ok(format!("{machine_guid}:{volume_serial:08X}"))
}

#[cfg(windows)]
fn volume_root(system_root: &std::path::Path) -> Option<&std::path::Path> {
    system_root
        .ancestors()
        .filter(|path| path.has_root())
        .last()
}

#[cfg(windows)]
fn system_volume_serial() -> PsResult<u32> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let windows_version = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .map_err(|error| PsError::Crypto(format!("open Windows version key: {error}")))?;
    let system_root: String = windows_version
        .get_value("SystemRoot")
        .map_err(|error| PsError::Crypto(format!("read SystemRoot: {error}")))?;
    let volume_root = volume_root(Path::new(&system_root))
        .ok_or_else(|| PsError::Crypto(format!("invalid SystemRoot path: {system_root}")))?;
    let volume_root_wide: Vec<u16> = volume_root
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let mut volume_serial = 0;

    // SAFETY: the root path is NUL-terminated and remains alive for the call;
    // the only output pointer refers to a valid local u32.
    unsafe {
        GetVolumeInformationW(
            PCWSTR(volume_root_wide.as_ptr()),
            None,
            Some(&mut volume_serial),
            None,
            None,
            None,
        )
        .map_err(|error| {
            PsError::Crypto(format!(
                "read volume serial for {}: {error}",
                volume_root.display()
            ))
        })?;
    }

    Ok(volume_serial)
}

#[cfg(windows)]
pub fn machine_identifier() -> PsResult<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cryptography = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Cryptography")
        .map_err(|error| PsError::Crypto(format!("open Cryptography key: {error}")))?;
    let machine_guid: String = cryptography
        .get_value("MachineGuid")
        .map_err(|error| PsError::Crypto(format!("read MachineGuid: {error}")))?;

    let volume_serial = system_volume_serial()?;
    compose_machine_identifier(&machine_guid, volume_serial)
}

#[cfg(not(windows))]
pub fn machine_identifier() -> PsResult<String> {
    Ok("non-windows-ci-machine:00000000".to_string())
}

pub fn derive_machine_key(salt: &[u8]) -> PsResult<MachineKey> {
    let machine_identifier = machine_identifier()?;
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(KEY_LENGTH),
    )
    .map_err(|error| PsError::Crypto(format!("argon2 params: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0; KEY_LENGTH];

    argon2
        .hash_password_into(machine_identifier.as_bytes(), salt, &mut key)
        .map_err(|error| PsError::Crypto(format!("argon2 derive: {error}")))?;

    Ok(MachineKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_for_same_salt() {
        let salt = b"powerscanner-test-salt-0123456789";
        let first = derive_machine_key(salt).unwrap();
        let second = derive_machine_key(salt).unwrap();

        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn derive_differs_for_different_salts() {
        let first = derive_machine_key(b"salt-aaaaaaaaaaaaaaaa").unwrap();
        let second = derive_machine_key(b"salt-bbbbbbbbbbbbbbbb").unwrap();

        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn derived_key_is_32_bytes() {
        let key = derive_machine_key(b"salt-cccccccccccccccc").unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn machine_identifier_contains_guid_and_volume_serial() {
        let identifier = compose_machine_identifier("  test-machine-guid  ", 0x12AB_34CD).unwrap();

        assert_eq!(identifier, "test-machine-guid:12AB34CD");
    }

    #[test]
    fn machine_identifier_rejects_empty_guid() {
        for machine_guid in ["", " \t\r\n "] {
            let result = compose_machine_identifier(machine_guid, 0x12AB_34CD);

            assert!(
                matches!(result, Err(PsError::Crypto(message)) if message == "MachineGuid is empty")
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn volume_root_is_extracted_from_windows_system_root() {
        use std::path::Path;

        assert_eq!(
            volume_root(Path::new(r"C:\Windows\System32")),
            Some(Path::new(r"C:\"))
        );
    }
}

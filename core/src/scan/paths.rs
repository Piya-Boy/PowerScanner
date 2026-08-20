use std::path::PathBuf;

use crate::error::PsResult;

pub const RESULT_SALT: &[u8] = b"powerscanner-result-v1-salt-01";

pub fn results_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(program_data) = std::env::var_os("ProgramData") {
        let program_data = PathBuf::from(program_data);
        if program_data.is_absolute() {
            return program_data.join("PowerScanner").join("results");
        }
    }

    std::env::temp_dir().join("PowerScanner").join("results")
}

/// Create the results directory and apply the platform's private-data policy.
pub fn prepare_results_dir(path: &std::path::Path) -> PsResult<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(windows)]
    apply_windows_results_acl(path)?;

    #[cfg(unix)]
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;

    Ok(())
}

#[cfg(windows)]
fn apply_windows_results_acl(path: &std::path::Path) -> PsResult<()> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
        .encode_utf16()
        .chain(iter::once(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

    // The SDDL grants full control only to SYSTEM, local administrators, and
    // the directory owner (the invoking user), and disables inherited entries.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .map_err(|error| crate::error::PsError::Config(format!("build results ACL: {error}")))?;

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let dacl_result = windows::Win32::Security::GetSecurityDescriptorDacl(
            descriptor,
            &mut present,
            &mut dacl,
            &mut defaulted,
        );
        if let Err(error) = dacl_result {
            let _ = LocalFree(HLOCAL(descriptor.0));
            return Err(crate::error::PsError::Config(format!(
                "read results ACL: {error}"
            )));
        }

        let result = SetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl as *const ACL),
            None,
        );
        let _ = LocalFree(HLOCAL(descriptor.0));
        if result.0 != 0 {
            return Err(crate::error::PsError::Config(format!(
                "set results ACL: Win32 error {}",
                result.0
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_dir_ends_with_expected_segments() {
        let directory = results_dir();

        assert!(
            directory.ends_with("PowerScanner/results")
                || directory.ends_with(r"PowerScanner\results")
        );
    }

    #[test]
    fn result_salt_differs_from_bundle_salt() {
        assert_ne!(RESULT_SALT, crate::signatures::store::BUNDLE_SALT);
    }
}

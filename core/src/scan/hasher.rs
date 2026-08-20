use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::PsResult;

const HASH_BUFFER_SIZE: usize = 64 * 1024;

pub fn sha256_file(path: &Path) -> PsResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempFileGuard(PathBuf);

    impl TempFileGuard {
        fn path(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn unique_temp_file() -> (TempFileGuard, File) {
        let temp_directory = std::env::temp_dir();
        let process_id = std::process::id();

        loop {
            let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = temp_directory.join(format!("powerscanner-sha256-{process_id}-{counter}"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return (TempFileGuard(path), file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create temporary test file: {error}"),
            }
        }
    }

    #[test]
    fn hashes_abc() {
        let (temp_file, mut file) = unique_temp_file();
        file.write_all(b"abc").unwrap();
        drop(file);

        let digest = sha256_file(temp_file.path()).unwrap();

        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

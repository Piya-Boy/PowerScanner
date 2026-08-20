use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use walkdir::{DirEntry, WalkDir};

pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub mtime_unix: i64,
}

fn should_walk_entry(entry: &DirEntry) -> bool {
    !entry.file_type().is_symlink() && !is_reparse_point(entry.path())
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0)
        .unwrap_or(true)
}

#[cfg(not(windows))]
fn is_reparse_point(_path: &Path) -> bool {
    false
}

pub fn enumerate(roots: &[PathBuf]) -> Vec<FileEntry> {
    let mut files = Vec::new();

    for root in roots {
        for entry in WalkDir::new(root)
            .follow_root_links(false)
            .into_iter()
            .filter_entry(should_walk_entry)
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let mtime_unix = metadata
                .modified()
                .ok()
                .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                .and_then(|duration| i64::try_from(duration.as_secs()).ok())
                .unwrap_or(0);

            files.push(FileEntry {
                path: entry.path().to_path_buf(),
                size: metadata.len(),
                mtime_unix,
            });
        }
    }

    files
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::symlink as create_dir_link;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir as create_dir_link;

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

    fn unique_temp_dir() -> TempDir {
        let process_id = std::process::id();

        loop {
            let counter = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("powerscanner-walk-{process_id}-{counter}"));

            match fs::create_dir(&path) {
                Ok(()) => return TempDir(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create temporary directory: {error}"),
            }
        }
    }

    #[test]
    fn enumerates_regular_files_with_metadata() {
        let directory = unique_temp_dir();
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let file = nested.join("sample.bin");
        fs::write(&file, b"scan me").unwrap();

        let entries = enumerate(&[directory.path().to_path_buf()]);
        let entry = entries.iter().find(|entry| entry.path == file).unwrap();

        assert_eq!(entry.size, 7);
        assert!(entry.mtime_unix > 0);
    }

    #[test]
    fn nonexistent_root_returns_no_entries() {
        let directory = unique_temp_dir();
        let missing = directory.path().join("missing");

        assert!(enumerate(&[missing]).is_empty());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn directory_links_do_not_expand_scan_scope() {
        let scan_root = unique_temp_dir();
        let outside_root = unique_temp_dir();
        let link_parent = unique_temp_dir();
        let inside_file = scan_root.path().join("inside.bin");
        let outside_file = outside_root.path().join("outside.bin");
        let nested_link = scan_root.path().join("outside-link");
        let root_link = link_parent.path().join("root-link");

        fs::write(&inside_file, b"inside").unwrap();
        fs::write(&outside_file, b"outside").unwrap();

        if create_dir_link(outside_root.path(), &nested_link).is_err()
            || create_dir_link(outside_root.path(), &root_link).is_err()
        {
            return;
        }

        let nested_entries = enumerate(&[scan_root.path().to_path_buf()]);
        assert!(nested_entries.iter().any(|entry| entry.path == inside_file));
        assert!(nested_entries
            .iter()
            .all(|entry| !entry.path.starts_with(&nested_link)));
        assert!(nested_entries
            .iter()
            .all(|entry| !entry.path.starts_with(outside_root.path())));
        assert!(enumerate(&[root_link]).is_empty());
    }
}

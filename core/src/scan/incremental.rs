use std::collections::HashMap;

use crate::error::{PsError, PsResult};

#[derive(Default)]
pub struct ScanCache {
    seen: HashMap<String, (u64, i64)>,
}

impl ScanCache {
    pub fn new() -> ScanCache {
        ScanCache::default()
    }

    pub fn from_json(json: &str) -> PsResult<ScanCache> {
        let seen = serde_json::from_str(json)
            .map_err(|error| PsError::Config(format!("scan cache parse: {error}")))?;

        Ok(ScanCache { seen })
    }

    pub fn to_json(&self) -> PsResult<String> {
        serde_json::to_string(&self.seen)
            .map_err(|error| PsError::Config(format!("scan cache serialize: {error}")))
    }

    pub fn is_unchanged(&self, path: &str, size: u64, mtime_unix: i64) -> bool {
        matches!(self.seen.get(path), Some(&(seen_size, seen_mtime)) if seen_size == size && seen_mtime == mtime_unix)
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
        let mut cache = ScanCache::new();
        cache.record(r"C:\a.exe", 100, 1_700_000_000);

        assert!(cache.is_unchanged(r"C:\a.exe", 100, 1_700_000_000));
        assert!(!cache.is_unchanged(r"C:\a.exe", 101, 1_700_000_000));
        assert!(!cache.is_unchanged(r"C:\a.exe", 100, 1_700_000_001));
        assert!(!cache.is_unchanged(r"C:\b.exe", 100, 1_700_000_000));
    }

    #[test]
    fn json_roundtrip() {
        let mut cache = ScanCache::new();
        cache.record(r"C:\x", 5, 42);

        let json = cache.to_json().unwrap();
        let restored = ScanCache::from_json(&json).unwrap();

        assert!(restored.is_unchanged(r"C:\x", 5, 42));
    }
}

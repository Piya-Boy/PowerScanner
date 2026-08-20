use std::collections::HashSet;

pub struct HashDb {
    set: HashSet<String>,
}

impl HashDb {
    pub fn from_text(contents: &str) -> HashDb {
        let set = contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_ascii_lowercase)
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

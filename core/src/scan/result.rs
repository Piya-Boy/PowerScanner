use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Malicious,
    Error,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub scanned_at_unix: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_and_deserializes() {
        let result = ScanResult {
            path: r"C:\x.exe".into(),
            size: 10,
            modified_unix: 1_700_000_000,
            sha256: "ab".repeat(32),
            verdict: Verdict::Malicious,
            findings: vec![Finding {
                kind: DetectionKind::Yara,
                label: "EvilRule".into(),
            }],
            error: None,
            scanned_at_unix: 1_700_000_100,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();

        assert!(!json.contains("\"error\""));
        assert_eq!(result, deserialized);
    }

    #[test]
    fn verdict_serializes_lowercase() {
        let json = serde_json::to_string(&Verdict::Error).unwrap();

        assert_eq!(json, r#""error""#);
    }
}

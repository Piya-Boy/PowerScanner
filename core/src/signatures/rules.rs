use crate::error::{PsError, PsResult};

pub struct RuleSet {
    rules: yara_x::Rules,
}

impl RuleSet {
    pub fn scan_bytes(&self, data: &[u8]) -> PsResult<Vec<String>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|error| PsError::Yara(format!("scan: {error}")))?;

        Ok(results
            .matching_rules()
            .map(|rule| rule.identifier().to_string())
            .collect())
    }

    pub fn rules(&self) -> &yara_x::Rules {
        &self.rules
    }
}

pub fn compile_from_sources(sources: &[String]) -> PsResult<RuleSet> {
    if !sources
        .iter()
        .any(|source| contains_rule_declaration(source))
    {
        return Err(PsError::Yara(
            "no YARA rule declarations provided".to_string(),
        ));
    }

    let mut compiler = yara_x::Compiler::new();

    for (index, source) in sources.iter().enumerate() {
        compiler
            .add_source(source.as_str())
            .map_err(|error| PsError::Yara(format!("compile source #{index}: {error}")))?;
    }

    Ok(RuleSet {
        rules: compiler.build(),
    })
}

fn contains_rule_declaration(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            b'"' => {
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index += 2;
                    } else if bytes[index] == b'"' {
                        index += 1;
                        break;
                    } else {
                        index += 1;
                    }
                }
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if &source[start..index] == "rule" {
                    return true;
                }
            }
            _ => index += 1,
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const EICAR_LIKE_RULE: &str = r#"
rule EicarLike {
    strings:
        $a = "X5O!P%@AP"
    condition:
        $a
}
"#;

    #[test]
    fn compiles_and_matches_eicar_like_content() {
        let rules = compile_from_sources(&[EICAR_LIKE_RULE.to_string()]).unwrap();

        let hits = rules.scan_bytes(b"prefix X5O!P%@AP suffix").unwrap();

        assert_eq!(hits, vec!["EicarLike".to_string()]);
    }

    #[test]
    fn no_match_returns_empty() {
        let rules = compile_from_sources(&[EICAR_LIKE_RULE.to_string()]).unwrap();

        let hits = rules.scan_bytes(b"clean content").unwrap();

        assert!(hits.is_empty());
    }

    #[test]
    fn bad_syntax_is_yara_error() {
        let result = compile_from_sources(&["rule broken {".to_string()]);

        assert!(matches!(result, Err(PsError::Yara(_))));
    }

    #[test]
    fn rejects_sources_without_rule_declarations() {
        for sources in [
            Vec::new(),
            vec![String::new()],
            vec!["// rule CommentedOut\n/* rule AlsoCommented */".to_string()],
            vec!["import \"pe\"".to_string()],
        ] {
            assert!(matches!(
                compile_from_sources(&sources),
                Err(PsError::Yara(message)) if message == "no YARA rule declarations provided"
            ));
        }
    }
}

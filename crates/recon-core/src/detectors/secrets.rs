use crate::{
    detector::Detector,
    error::Result,
    finding::{Category, Finding, Severity},
    target::Target,
};
use async_trait::async_trait;
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;

pub struct SecretsDetector;

struct Pattern {
    name: &'static str,
    severity: Severity,
    re: Regex,
}

fn patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "AWS access key",
            severity: Severity::Critical,
            re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        Pattern {
            name: "Private key block",
            severity: Severity::Critical,
            re: Regex::new(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----").unwrap(),
        },
        Pattern {
            name: "Generic API token",
            severity: Severity::High,
            re: Regex::new(
                r#"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['"][A-Za-z0-9/_\-]{20,}['"]"#,
            )
            .unwrap(),
        },
        Pattern {
            name: "JWT",
            severity: Severity::Medium,
            re: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                .unwrap(),
        },
        Pattern {
            name: "IBAN (PII)",
            severity: Severity::Medium,
            re: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
        },
    ]
}

/// Pure, testable: scan one file's content for secret patterns.
fn scan_content(path: &str, content: &str, pats: &[Pattern]) -> Vec<Finding> {
    let mut out = vec![];
    for (i, line) in content.lines().enumerate() {
        for p in pats {
            if let Some(m) = p.re.find(line) {
                let snippet: String = m.as_str().chars().take(12).collect();
                out.push(
                    Finding::new(
                        Category::Secrets,
                        p.severity,
                        format!("{} found", p.name),
                        format!("{snippet}…"),
                        "Remove the secret, rotate it, and store it in a secret manager (add the file to .gitignore).",
                    )
                    .at(format!("{path}:{}", i + 1)),
                );
            }
        }
    }
    out
}

#[async_trait]
impl Detector for SecretsDetector {
    fn category(&self) -> Category {
        Category::Secrets
    }

    fn applies(&self, t: &Target) -> bool {
        t.repo.is_some()
    }

    async fn run(&self, t: &Target) -> Result<Vec<Finding>> {
        let root = t.repo.as_ref().unwrap().clone();
        // Respects .gitignore by default (so we scan committed files, skip target/ & node_modules).
        let files: Vec<_> = WalkBuilder::new(&root)
            .hidden(false)
            .build()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|f| f.is_file()).unwrap_or(false))
            .map(|e| e.into_path())
            .collect();
        let pats = patterns();
        let findings: Vec<Finding> = files
            .par_iter()
            .flat_map_iter(|path| match std::fs::read_to_string(path) {
                Ok(content) => scan_content(&path.display().to_string(), &content, &pats),
                Err(_) => vec![], // binary/unreadable — skip
            })
            .collect();
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_key_with_location() {
        let content = "line one\nconst k = \"AKIAIOSFODNN7EXAMPLE\";\nline three";
        let findings = scan_content("foo.js", content, &patterns());
        let aws: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("AWS"))
            .collect();
        assert_eq!(aws.len(), 1);
        assert_eq!(aws[0].severity, Severity::Critical);
        assert_eq!(aws[0].location.as_deref(), Some("foo.js:2"));
        assert!(!aws[0].evidence.is_empty());
    }

    #[test]
    fn clean_content_no_findings() {
        let findings = scan_content(
            "clean.txt",
            "just some normal text\nnothing here",
            &patterns(),
        );
        assert!(findings.is_empty());
    }
}

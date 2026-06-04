use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Headers,
    Tls,
    Stack,
    Secrets,
    Deps,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Headers => "Headers",
            Self::Tls => "TLS",
            Self::Stack => "Stack",
            Self::Secrets => "Secrets",
            Self::Deps => "Deps",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub evidence: String,
    pub fix: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl Finding {
    /// Every finding MUST carry verifiable evidence (the real header/cert/version/match).
    pub fn new(
        category: Category,
        severity: Severity,
        title: impl Into<String>,
        evidence: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            title: title.into(),
            evidence: evidence.into(),
            fix: fix.into(),
            references: vec![],
            location: None,
        }
    }
    pub fn with_refs(mut self, refs: Vec<String>) -> Self {
        self.references = refs;
        self
    }
    pub fn at(mut self, loc: impl Into<String>) -> Self {
        self.location = Some(loc.into());
        self
    }
}

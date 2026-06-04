use crate::finding::{Category, Finding, Severity};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn from_score(s: u8) -> Self {
        match s {
            90..=100 => Self::A,
            80..=89 => Self::B,
            70..=79 => Self::C,
            60..=69 => Self::D,
            _ => Self::F,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }
}

fn weight(s: Severity) -> i32 {
    match s {
        Severity::Critical => 40,
        Severity::High => 20,
        Severity::Medium => 10,
        Severity::Low => 5,
        Severity::Info => 0,
    }
}

pub fn score<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> u8 {
    let mut s: i32 = 100;
    for f in findings {
        s -= weight(f.severity);
    }
    s.clamp(0, 100) as u8
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryScore {
    pub category: Category,
    pub score: u8,
    pub grade: Grade,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: String,
    pub findings: Vec<Finding>,
    pub categories: Vec<CategoryScore>,
    pub overall_score: u8,
    pub overall_grade: Grade,
}

impl Report {
    /// Builds a report from the categories that actually ran plus their findings.
    /// `overall_score` is the mean of the per-category scores; only categories that
    /// ran are included (categories that never executed do not dilute the mean).
    pub fn build(target: String, ran: &[Category], findings: Vec<Finding>) -> Self {
        let mut per: BTreeMap<Category, Vec<&Finding>> = BTreeMap::new();
        for c in ran {
            per.entry(*c).or_default();
        }
        for f in &findings {
            per.entry(f.category).or_default().push(f);
        }
        let mut categories = vec![];
        let mut total: u32 = 0;
        for (cat, fs) in &per {
            let sc = score(fs.iter().copied());
            total += sc as u32;
            categories.push(CategoryScore {
                category: *cat,
                score: sc,
                grade: Grade::from_score(sc),
            });
        }
        let overall = if categories.is_empty() {
            100
        } else {
            (total / categories.len() as u32) as u8
        };
        Report {
            target,
            findings,
            categories,
            overall_score: overall,
            overall_grade: Grade::from_score(overall),
        }
    }
    /// Highest severity across all findings. `Info` sorts below every `--fail-on`
    /// threshold, so detector-error `Info` findings never trip CI gating.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_boundaries() {
        assert_eq!(Grade::from_score(100), Grade::A);
        assert_eq!(Grade::from_score(90), Grade::A);
        assert_eq!(Grade::from_score(89), Grade::B);
        assert_eq!(Grade::from_score(80), Grade::B);
        assert_eq!(Grade::from_score(79), Grade::C);
        assert_eq!(Grade::from_score(70), Grade::C);
        assert_eq!(Grade::from_score(69), Grade::D);
        assert_eq!(Grade::from_score(60), Grade::D);
        assert_eq!(Grade::from_score(59), Grade::F);
        assert_eq!(Grade::from_score(0), Grade::F);
    }

    #[test]
    fn empty_score_is_perfect() {
        assert_eq!(score(std::iter::empty()), 100);
    }
}

use crate::{
    detector::Detector,
    finding::{Category, Finding, Severity},
    report::Report,
    target::Target,
};
use std::sync::Arc;

pub async fn run(target: &Target, detectors: &[Arc<dyn Detector>]) -> Report {
    let active: Vec<Arc<dyn Detector>> = detectors
        .iter()
        .filter(|d| d.applies(target))
        .cloned()
        .collect();
    let ran: Vec<Category> = active.iter().map(|d| d.category()).collect();
    let results = futures::future::join_all(active.iter().map(|d| {
        let cat = d.category();
        let d = d.clone();
        async move { (cat, d.run(target).await) }
    }))
    .await;

    let mut findings = vec![];
    for (cat, res) in results {
        match res {
            Ok(mut fs) => findings.append(&mut fs),
            Err(e) => findings.push(Finding::new(
                cat,
                Severity::Info,
                format!("{} check could not complete", cat.label()),
                e.to_string(),
                "Re-run; verify the target is reachable.",
            )),
        }
    }
    let label = target
        .url
        .as_ref()
        .map(|u| u.to_string())
        .or_else(|| target.repo.as_ref().map(|p| p.display().to_string()))
        .unwrap_or_default();
    Report::build(label, &ran, findings)
}

use crate::{
    detector::Detector,
    error::Result,
    finding::{Category, Finding, Severity},
    target::Target,
};
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;

#[derive(Deserialize)]
struct Sig {
    name: String,
    #[serde(default)]
    header: Option<String>,
    #[serde(default)]
    body_regex: Option<String>,
    #[serde(default)]
    regex: Option<String>,
    #[serde(default)]
    eol_product: Option<String>,
}

pub struct FingerprintDetector;

#[async_trait]
impl Detector for FingerprintDetector {
    fn category(&self) -> Category {
        Category::Stack
    }
    fn applies(&self, t: &Target) -> bool {
        t.url.is_some()
    }
    async fn run(&self, t: &Target) -> Result<Vec<Finding>> {
        let sigs: Vec<Sig> = serde_json::from_str(include_str!("signatures.json"))
            .map_err(|e| crate::error::ReconError::Other(format!("bad signatures.json: {e}")))?;
        let client = reqwest::Client::builder().user_agent("frisk/0.1").build()?;
        let resp = client.get(t.url.as_ref().unwrap().clone()).send().await?;
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        let body = resp.text().await.unwrap_or_default();

        let mut out = vec![];
        for sig in &sigs {
            if let Some((evidence, version)) = match_sig(sig, &headers, &body) {
                let label = match &version {
                    Some(v) => format!("{} {}", sig.name, v),
                    None => sig.name.clone(),
                };
                out.push(Finding::new(
                    Category::Stack,
                    Severity::Info,
                    format!("Detected {label}"),
                    evidence,
                    "Informational: confirms the technology in use.",
                ));
                if let (Some(prod), Some(ver)) = (&sig.eol_product, &version) {
                    if let Some(f) = check_eol(&client, prod, ver, &sig.name).await {
                        out.push(f);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Returns (evidence, version) on a match.
fn match_sig(
    sig: &Sig,
    headers: &[(String, String)],
    body: &str,
) -> Option<(String, Option<String>)> {
    if let Some(hname) = &sig.header {
        let hname = hname.to_lowercase();
        let (_, val) = headers.iter().find(|(k, _)| *k == hname)?;
        if let Some(pat) = &sig.regex {
            let re = Regex::new(pat).ok()?;
            let c = re.captures(val)?;
            let version = c
                .get(1)
                .map(|m| m.as_str().to_string())
                .filter(|s| !s.is_empty());
            return Some((format!("{hname}: {val}"), version));
        }
        return Some((format!("{hname}: {val}"), None));
    }
    if let Some(pat) = &sig.body_regex {
        let re = Regex::new(pat).ok()?;
        let c = re.captures(body)?;
        let version = c
            .get(1)
            .map(|m| m.as_str().to_string())
            .filter(|s| !s.is_empty());
        let evidence = c.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
        return Some((evidence, version));
    }
    None
}

#[derive(Deserialize)]
struct Cycle {
    cycle: serde_json::Value,
    #[serde(default)]
    eol: serde_json::Value,
}

async fn check_eol(
    client: &reqwest::Client,
    product: &str,
    version: &str,
    name: &str,
) -> Option<Finding> {
    let url = format!("https://endoflife.date/api/{product}.json");
    let cycles: Vec<Cycle> = client.get(&url).send().await.ok()?.json().await.ok()?;
    let parts: Vec<&str> = version.split('.').collect();
    let major = parts.first().copied().unwrap_or("");
    let major_minor = if parts.len() >= 2 {
        format!("{}.{}", parts[0], parts[1])
    } else {
        major.to_string()
    };
    for c in &cycles {
        let cyc = match &c.cycle {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => continue,
        };
        if cyc == major_minor || cyc == major {
            let is_eol = match &c.eol {
                serde_json::Value::Bool(b) => *b,
                serde_json::Value::String(date) => date_is_past(date),
                _ => false,
            };
            if is_eol {
                let ev = match &c.eol {
                    serde_json::Value::String(d) => {
                        format!("{name} {version} (cycle {cyc}) reached EOL {d}")
                    }
                    _ => format!("{name} {version} (cycle {cyc}) is end-of-life"),
                };
                return Some(
                    Finding::new(
                        Category::Stack,
                        Severity::High,
                        format!("{name} {version} is end-of-life"),
                        ev,
                        "Upgrade to a supported release.",
                    )
                    .with_refs(vec![format!("https://endoflife.date/{product}")]),
                );
            }
            return None;
        }
    }
    None
}

/// Days from the civil date to the Unix epoch (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn date_is_past(date: &str) -> bool {
    let parts: Vec<i64> = date.split('-').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 3 {
        return false;
    }
    let date_days = days_from_civil(parts[0], parts[1], parts[2]);
    let now_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        / 86400) as i64;
    date_days < now_days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_drupal_version_from_header() {
        let sig = Sig {
            name: "Drupal".into(),
            header: Some("x-generator".into()),
            body_regex: None,
            regex: Some(r"Drupal (\d+(?:\.\d+)?)".into()),
            eol_product: Some("drupal".into()),
        };
        let headers = vec![(
            "x-generator".to_string(),
            "Drupal 9.4 (https://www.drupal.org)".to_string(),
        )];
        let (evidence, version) = match_sig(&sig, &headers, "").unwrap();
        assert_eq!(version.as_deref(), Some("9.4"));
        assert!(!evidence.is_empty());
    }

    #[test]
    fn no_match_returns_none() {
        let sig = Sig {
            name: "Drupal".into(),
            header: Some("x-generator".into()),
            body_regex: None,
            regex: Some(r"Drupal".into()),
            eol_product: None,
        };
        assert!(match_sig(&sig, &[], "").is_none());
    }

    #[test]
    fn old_date_is_past_future_is_not() {
        assert!(date_is_past("2000-01-01"));
        assert!(!date_is_past("2999-01-01"));
        assert!(!date_is_past("not-a-date"));
    }
}

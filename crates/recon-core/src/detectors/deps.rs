use crate::{
    detector::Detector,
    error::Result,
    finding::{Category, Finding, Severity},
    target::Target,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct DepsDetector;

#[derive(Serialize)]
struct OsvPkg {
    name: String,
    ecosystem: String,
}
#[derive(Serialize)]
struct OsvQuery {
    package: OsvPkg,
    version: String,
}
#[derive(Serialize)]
struct OsvBatch {
    queries: Vec<OsvQuery>,
}
#[derive(Deserialize, Default)]
struct OsvResp {
    #[serde(default)]
    results: Vec<OsvResult>,
}
#[derive(Deserialize, Default)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}
#[derive(Deserialize)]
struct OsvVuln {
    id: String,
}

/// (name, version, ecosystem)
type Pkg = (String, String, String);

fn parse_npm_str(text: &str) -> Vec<Pkg> {
    let mut out = vec![];
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    if let Some(pkgs) = json.get("packages").and_then(|v| v.as_object()) {
        // lockfileVersion 2/3
        for (key, val) in pkgs {
            if key.is_empty() {
                continue;
            }
            let name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key)
                .to_string();
            if let Some(ver) = val.get("version").and_then(|v| v.as_str()) {
                out.push((name, ver.to_string(), "npm".to_string()));
            }
        }
    } else if let Some(deps) = json.get("dependencies").and_then(|v| v.as_object()) {
        // lockfileVersion 1
        for (name, val) in deps {
            if let Some(ver) = val.get("version").and_then(|v| v.as_str()) {
                out.push((name.clone(), ver.to_string(), "npm".to_string()));
            }
        }
    }
    out
}

fn parse_composer_str(text: &str) -> Vec<Pkg> {
    let mut out = vec![];
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    for key in ["packages", "packages-dev"] {
        if let Some(arr) = json.get(key).and_then(|v| v.as_array()) {
            for p in arr {
                if let (Some(name), Some(ver)) = (
                    p.get("name").and_then(|v| v.as_str()),
                    p.get("version").and_then(|v| v.as_str()),
                ) {
                    let ver = ver.strip_prefix('v').unwrap_or(ver).to_string();
                    out.push((name.to_string(), ver, "Packagist".to_string()));
                }
            }
        }
    }
    out
}

fn collect_packages(root: &Path) -> Vec<Pkg> {
    let mut out = vec![];
    if let Ok(text) = std::fs::read_to_string(root.join("package-lock.json")) {
        out.extend(parse_npm_str(&text));
    }
    if let Ok(text) = std::fs::read_to_string(root.join("composer.lock")) {
        out.extend(parse_composer_str(&text));
    }
    out
}

#[async_trait]
impl Detector for DepsDetector {
    fn category(&self) -> Category {
        Category::Deps
    }
    fn applies(&self, t: &Target) -> bool {
        t.repo.is_some()
    }
    async fn run(&self, t: &Target) -> Result<Vec<Finding>> {
        let root = t.repo.as_ref().unwrap();
        let mut pkgs = collect_packages(root);
        if pkgs.is_empty() {
            return Ok(vec![]);
        }
        pkgs.truncate(1000); // OSV querybatch handles up to 1000 per request; v0.1 caps here.

        let client = reqwest::Client::new();
        let batch = OsvBatch {
            queries: pkgs
                .iter()
                .map(|(n, v, e)| OsvQuery {
                    package: OsvPkg {
                        name: n.clone(),
                        ecosystem: e.clone(),
                    },
                    version: v.clone(),
                })
                .collect(),
        };
        let resp: OsvResp = client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&batch)
            .send()
            .await?
            .json()
            .await?;

        let mut out = vec![];
        for ((name, ver, _), res) in pkgs.iter().zip(resp.results.into_iter()) {
            for v in res.vulns {
                out.push(
                    Finding::new(
                        Category::Deps,
                        Severity::High,
                        format!("{name} {ver}: {}", v.id),
                        format!("{name}@{ver}"),
                        format!("Upgrade {name} to a patched version."),
                    )
                    .with_refs(vec![format!("https://osv.dev/vulnerability/{}", v.id)]),
                );
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_lockfile_v3() {
        let text = r#"{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/@scope/pkg":{"version":"1.0.0"}}}"#;
        let pkgs = parse_npm_str(text);
        assert!(pkgs
            .iter()
            .any(|(n, v, e)| n == "lodash" && v == "4.17.20" && e == "npm"));
        assert!(pkgs.iter().any(|(n, _, _)| n == "@scope/pkg"));
    }

    #[test]
    fn parses_composer_lock() {
        let text = r#"{"packages":[{"name":"symfony/console","version":"v5.4.0"}]}"#;
        let pkgs = parse_composer_str(text);
        assert_eq!(
            pkgs[0],
            (
                "symfony/console".to_string(),
                "5.4.0".to_string(),
                "Packagist".to_string()
            )
        );
    }
}

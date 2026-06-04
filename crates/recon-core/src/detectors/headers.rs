use crate::{
    detector::Detector,
    error::Result,
    finding::{Category, Finding, Severity},
    target::Target,
};
use async_trait::async_trait;
use reqwest::header::HeaderMap;

pub struct HeadersDetector;

/// Pure header-evaluation logic — takes a HeaderMap, returns findings.
/// Extracted so it can be unit-tested without an HTTP round-trip.
pub fn evaluate(h: &HeaderMap) -> Vec<Finding> {
    let mut out = vec![];

    let checks: &[(&str, Severity, &str, &str)] = &[
        (
            "strict-transport-security",
            Severity::Medium,
            "HSTS missing",
            "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
        ),
        (
            "content-security-policy",
            Severity::Medium,
            "Content-Security-Policy missing",
            "Define a CSP restricting script/style/connect sources.",
        ),
        (
            "x-content-type-options",
            Severity::Low,
            "X-Content-Type-Options missing",
            "Add `X-Content-Type-Options: nosniff`.",
        ),
        (
            "x-frame-options",
            Severity::Low,
            "Clickjacking protection missing",
            "Add `X-Frame-Options: DENY` or a CSP `frame-ancestors`.",
        ),
        (
            "referrer-policy",
            Severity::Low,
            "Referrer-Policy missing",
            "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
        ),
        (
            "permissions-policy",
            Severity::Info,
            "Permissions-Policy missing",
            "Add a Permissions-Policy to limit powerful features.",
        ),
    ];

    for (name, sev, title, fix) in checks {
        if !h.contains_key(*name) {
            out.push(Finding::new(
                Category::Headers,
                *sev,
                *title,
                format!("response has no `{name}` header"),
                *fix,
            ));
        }
    }

    if let Some(csp) = h
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
    {
        if csp.contains("unsafe-inline") {
            out.push(Finding::new(
                Category::Headers,
                Severity::Medium,
                "CSP allows unsafe-inline",
                csp.to_string(),
                "Remove `unsafe-inline`; use nonces or hashes.",
            ));
        }
    }

    for c in h
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        let lc = c.to_lowercase();
        if !lc.contains("secure") || !lc.contains("httponly") {
            let cookie_name = c.split('=').next().unwrap_or("cookie");
            out.push(Finding::new(
                Category::Headers,
                Severity::Low,
                format!("Cookie `{cookie_name}` missing Secure/HttpOnly"),
                c.to_string(),
                "Set `Secure; HttpOnly; SameSite=Lax` on session cookies.",
            ));
        }
    }

    out
}

#[async_trait]
impl Detector for HeadersDetector {
    fn category(&self) -> Category {
        Category::Headers
    }

    fn applies(&self, t: &Target) -> bool {
        t.url.is_some()
    }

    async fn run(&self, t: &Target) -> Result<Vec<Finding>> {
        let url = t.url.as_ref().unwrap().clone();
        let client = reqwest::Client::builder()
            .user_agent("frisk/0.1 (+https://github.com/L-ubu/frisk)")
            .build()?;
        let resp = client.get(url).send().await?;
        Ok(evaluate(resp.headers()))
    }
}

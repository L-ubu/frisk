use recon_core::detectors::headers::evaluate;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

fn bare_headers() -> HeaderMap {
    HeaderMap::new()
}

fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

#[test]
fn hsts_missing_has_non_empty_evidence() {
    let findings = evaluate(&bare_headers());
    let hsts = findings
        .iter()
        .find(|f| f.title == "HSTS missing")
        .expect("should emit HSTS finding when header absent");
    assert!(
        !hsts.evidence.is_empty(),
        "evidence must be non-empty; got {:?}",
        hsts.evidence
    );
}

#[test]
fn all_six_baseline_headers_flagged_on_bare_response() {
    let findings = evaluate(&bare_headers());
    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    for expected in &[
        "HSTS missing",
        "Content-Security-Policy missing",
        "X-Content-Type-Options missing",
        "Clickjacking protection missing",
        "Referrer-Policy missing",
        "Permissions-Policy missing",
    ] {
        assert!(
            titles.contains(expected),
            "expected finding '{expected}' not found in: {titles:?}"
        );
    }
}

#[test]
fn no_findings_when_all_headers_present() {
    let h = headers_with(&[
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains; preload",
        ),
        ("content-security-policy", "default-src 'self'"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "geolocation=()"),
    ]);
    let findings = evaluate(&h);
    assert!(
        findings.is_empty(),
        "expected no findings but got: {findings:?}"
    );
}

#[test]
fn csp_unsafe_inline_is_flagged() {
    let h = headers_with(&[
        ("strict-transport-security", "max-age=63072000"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'unsafe-inline'",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "geolocation=()"),
    ]);
    let findings = evaluate(&h);
    let f = findings
        .iter()
        .find(|f| f.title == "CSP allows unsafe-inline")
        .expect("should flag unsafe-inline in CSP");
    assert!(f.evidence.contains("unsafe-inline"));
}

#[test]
fn insecure_cookie_is_flagged() {
    // reqwest HeaderMap only supports one value per key for insert; use append for Set-Cookie
    let mut h = headers_with(&[
        ("strict-transport-security", "max-age=63072000"),
        ("content-security-policy", "default-src 'self'"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "geolocation=()"),
    ]);
    h.append(
        HeaderName::from_bytes(b"set-cookie").unwrap(),
        HeaderValue::from_str("session=abc123; Path=/").unwrap(),
    );
    let findings = evaluate(&h);
    let f = findings
        .iter()
        .find(|f| f.title.contains("missing Secure/HttpOnly"))
        .expect("should flag cookie missing Secure/HttpOnly");
    assert_eq!(f.evidence, "session=abc123; Path=/");
}

#[test]
fn secure_httponly_cookie_not_flagged() {
    let mut h = headers_with(&[
        ("strict-transport-security", "max-age=63072000"),
        ("content-security-policy", "default-src 'self'"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "geolocation=()"),
    ]);
    h.append(
        HeaderName::from_bytes(b"set-cookie").unwrap(),
        HeaderValue::from_str("session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax").unwrap(),
    );
    let findings = evaluate(&h);
    assert!(
        !findings
            .iter()
            .any(|f| f.title.contains("missing Secure/HttpOnly")),
        "secure+httponly cookie should not be flagged"
    );
}

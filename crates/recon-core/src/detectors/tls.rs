use crate::{
    detector::Detector,
    error::Result,
    finding::{Category, Finding, Severity},
    target::Target,
};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TlsDetector;

/// Pure expiry-classification logic — maps a days-remaining count to a finding
/// shape (severity, title, fix), or `None` when the runway is healthy.
/// Extracted so it can be unit-tested without a TLS round-trip.
pub fn classify_expiry(days_remaining: i64) -> Option<(Severity, String, String)> {
    if days_remaining <= 0 {
        Some((
            Severity::Critical,
            "Certificate expired".into(),
            "Renew the TLS certificate immediately.".into(),
        ))
    } else if days_remaining < 21 {
        Some((
            Severity::High,
            "Certificate expiring soon".into(),
            "Renew before expiry; automate with ACME.".into(),
        ))
    } else {
        None
    }
}

#[async_trait]
impl Detector for TlsDetector {
    fn category(&self) -> Category {
        Category::Tls
    }

    fn applies(&self, t: &Target) -> bool {
        t.url
            .as_ref()
            .map(|u| u.scheme() == "https")
            .unwrap_or(false)
    }

    async fn run(&self, t: &Target) -> Result<Vec<Finding>> {
        // rustls 0.23 needs a process-wide crypto provider. Install one if none
        // is set yet; an Err here just means another caller already installed it.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let url = t.url.as_ref().unwrap();
        let host = url
            .host_str()
            .ok_or_else(|| crate::error::ReconError::Other("URL has no host".into()))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let server_name = match rustls_pki_types::ServerName::try_from(host.clone()) {
            Ok(n) => n,
            Err(e) => {
                return Ok(vec![handshake_failure(format!("invalid server name: {e}"))]);
            }
        };

        let tcp = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => s,
            Err(e) => {
                return Ok(vec![handshake_failure(format!("TCP connect failed: {e}"))]);
            }
        };

        // A failing handshake/validation IS the security finding — turn the
        // connect error into a High finding rather than propagating it as Err.
        let tls = match connector.connect(server_name, tcp).await {
            Ok(t) => t,
            Err(e) => {
                return Ok(vec![handshake_failure(e.to_string())]);
            }
        };

        let certs = tls.get_ref().1.peer_certificates();
        let leaf = match certs.and_then(|c| c.first()) {
            Some(c) => c,
            None => {
                return Ok(vec![handshake_failure(
                    "server presented no certificates".into(),
                )]);
            }
        };

        let parsed = match x509_parser::parse_x509_certificate(leaf.as_ref()) {
            Ok((_, p)) => p,
            Err(e) => {
                return Ok(vec![handshake_failure(format!(
                    "failed to parse leaf certificate: {e}"
                ))]);
            }
        };

        let not_after = parsed.validity().not_after;
        let not_after_ts = not_after.timestamp();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let days_remaining = (not_after_ts - now) / 86_400;

        let mut out = vec![];
        if let Some((sev, title, fix)) = classify_expiry(days_remaining) {
            let evidence = if days_remaining <= 0 {
                format!("notAfter {not_after}")
            } else {
                format!("{days_remaining} days remaining")
            };
            out.push(Finding::new(Category::Tls, sev, title, evidence, fix));
        }
        Ok(out)
    }
}

fn handshake_failure(err: String) -> Finding {
    Finding::new(
        Category::Tls,
        Severity::High,
        "TLS handshake/validation failed",
        err,
        "Fix the certificate chain / validity; ensure a trusted CA and correct hostname.",
    )
}

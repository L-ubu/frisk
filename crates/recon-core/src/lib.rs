//! recon-core is the reusable passive scan engine behind frisk.
//! It runs a set of [`Detector`]s against a [`Target`] and aggregates their
//! findings into a scored, gradable [`Report`].

pub mod detector;
pub mod detectors;
pub mod error;
pub mod finding;
pub mod registry;
pub mod report;
pub mod target;

pub use detector::Detector;
pub use error::{ReconError, Result};
pub use finding::{Category, Finding, Severity};
pub use report::{Grade, Report};
pub use target::Target;

use std::sync::Arc;

/// The full set of detectors that make up a frisk scan.
pub fn all_detectors() -> Vec<Arc<dyn Detector>> {
    vec![
        Arc::new(detectors::headers::HeadersDetector),
        Arc::new(detectors::tls::TlsDetector),
        Arc::new(detectors::fingerprint::FingerprintDetector),
        Arc::new(detectors::secrets::SecretsDetector),
        Arc::new(detectors::deps::DepsDetector),
    ]
}

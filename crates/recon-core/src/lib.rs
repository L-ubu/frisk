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

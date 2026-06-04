use crate::{
    error::Result,
    finding::{Category, Finding},
    target::Target,
};
use async_trait::async_trait;

#[async_trait]
pub trait Detector: Send + Sync {
    fn category(&self) -> Category;
    fn applies(&self, target: &Target) -> bool;
    async fn run(&self, target: &Target) -> Result<Vec<Finding>>;
}

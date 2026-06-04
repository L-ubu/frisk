use std::path::PathBuf;
use url::Url;

#[derive(Debug, Clone)]
pub struct Target {
    pub url: Option<Url>,
    pub repo: Option<PathBuf>,
}

impl Target {
    pub fn url(u: Url) -> Self {
        Self {
            url: Some(u),
            repo: None,
        }
    }
    pub fn with_repo(mut self, p: PathBuf) -> Self {
        self.repo = Some(p);
        self
    }
}

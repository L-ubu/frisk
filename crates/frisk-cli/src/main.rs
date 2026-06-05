use clap::Parser;
use recon_core::{Severity, Target};
use std::path::PathBuf;
use url::Url;

mod render;

#[derive(Parser)]
#[command(
    name = "frisk",
    version,
    about = "Fast passive security/audit pre-flight for any site or repo"
)]
struct Args {
    /// Target URL (e.g. https://example.com)
    url: Option<String>,
    /// Also scan a local repository path
    #[arg(long)]
    repo: Option<PathBuf>,
    /// Emit JSON instead of a table
    #[arg(long)]
    json: bool,
    /// Exit non-zero if any finding is at or above this severity
    #[arg(long, value_parser = ["low","medium","high","critical"])]
    fail_on: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let url = match &args.url {
        Some(u) => Some(Url::parse(u).or_else(|_| Url::parse(&format!("https://{u}")))?),
        None => None,
    };
    if url.is_none() && args.repo.is_none() {
        anyhow::bail!("provide a URL and/or --repo <path>");
    }
    let target = Target {
        url,
        repo: args.repo,
    };
    let report = recon_core::registry::run(&target, &recon_core::all_detectors()).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render::table(&report);
    }

    if let Some(level) = args.fail_on.as_deref() {
        let threshold = match level {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            _ => Severity::Critical,
        };
        if report
            .max_severity()
            .map(|m| m >= threshold)
            .unwrap_or(false)
        {
            std::process::exit(1);
        }
    }
    Ok(())
}

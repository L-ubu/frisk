use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::tempdir;

/// Running frisk with no URL and no --repo must exit non-zero and explain what to provide.
#[test]
fn no_args_errors() {
    Command::cargo_bin("frisk")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("provide a URL"));
}

/// A repo containing an AWS access key must appear as a finding in --json output.
#[test]
fn repo_scan_finds_secret_json() {
    let dir = tempdir().unwrap();
    let secret_file = dir.path().join("config.env");
    let mut f = std::fs::File::create(&secret_file).unwrap();
    writeln!(f, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").unwrap();

    Command::cargo_bin("frisk")
        .unwrap()
        .arg("--repo")
        .arg(dir.path())
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("AWS access key"));
}

/// With --fail-on critical, the AWS key must cause a non-zero exit.
#[test]
fn fail_on_critical_exits_nonzero() {
    let dir = tempdir().unwrap();
    let secret_file = dir.path().join("leak.txt");
    let mut f = std::fs::File::create(&secret_file).unwrap();
    writeln!(f, "key = AKIAIOSFODNN7EXAMPLE").unwrap();

    Command::cargo_bin("frisk")
        .unwrap()
        .arg("--repo")
        .arg(dir.path())
        .arg("--fail-on")
        .arg("critical")
        .assert()
        .failure();
}

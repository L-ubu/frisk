# frisk — fast Rust security/audit pre-flight

**Status:** approved design (2026-06-04)
**Author:** Luca
**Repo:** standalone, MIT, public on personal GitHub. Listable on io-tooling-hub.

## Summary

`frisk` is a single fast Rust binary that gives any website (and optionally its
repo) a quick security "pat-down": it runs five checks in parallel and prints a
graded report (A–F) with copy-paste fixes. Point it at a URL; add `--repo` to
also scan the codebase.

It is built as a Cargo **workspace** whose value lives in a library crate,
`recon-core`. The CLI and an MCP server are thin frontends over that engine, and
later consumers — `web-audit-agent` and `PitchProofPack` — reuse the same engine
and JSON contract. `frisk` is therefore the foundation ("recon-core"), not a
one-off tool.

### Goals
- A genuinely useful, demoable standalone tool (star-bait, daily-driver, pre-sales hook).
- A clean, reusable engine that downstream tools plug into.
- Showcase of Rust craft and Luca's security edge.

### Non-goals (v0.1)
- No branded PDF output — that stays `web-audit-agent`'s job; `frisk` feeds it JSON.
- No active scanning of any kind (no auth, no fuzzing, no exploitation). Passive only.
- No autofix/remediation PRs (findings carry *fix guidance* text only).

## Example UX

```
$ frisk https://prospect.example.com --repo ./their-codebase

  frisk  prospect.example.com                          overall: C  (68/100)
  ─────────────────────────────────────────────────────────────────────
  Headers     B    HSTS missing · CSP allows unsafe-inline · 2 more
  TLS         A    valid 312d · TLS1.3 · HSTS preload eligible
  Stack       D    Drupal 9.4.8  ⚠ EOL since 2023-12 · nginx 1.18
  Secrets     F    1 AWS key (their-codebase/.env.bak:3) · 2 more
  Deps        C    3 CVEs (1 high: lodash<4.17.21 GHSA-xxxx)
  ─────────────────────────────────────────────────────────────────────
  18 findings · `frisk … --json` for full report · `--fix` for guidance
```

- `--json` emits a **stable schema** (the contract for web-audit-agent / PitchProofPack).
- `--fail-on <severity>` → non-zero exit for CI gating.
- URL-only invocation runs the 3 web detectors; `--repo <path>` adds the 2 repo detectors.

## Architecture

Cargo workspace:

```
frisk/
├─ crates/
│  ├─ recon-core/    # engine: Target, Detector trait, Finding/Report, scoring, registry
│  ├─ frisk-cli/     # thin clap frontend → table / --json / exit codes
│  └─ frisk-mcp/     # thin MCP server exposing recon-core as a tool
├─ docs/
└─ .github/workflows/
```

### Core abstractions (`recon-core`)

```rust
struct Target { url: Option<Url>, repo: Option<PathBuf> }

enum Severity { Info, Low, Medium, High, Critical }

struct Finding {
    category: Category,      // Headers | Tls | Stack | Secrets | Deps
    severity: Severity,
    title: String,
    evidence: String,        // the REAL header/cert/version/match — never asserted without it
    fix: String,             // remediation guidance
    references: Vec<String>, // CVE/CWE/doc links
    location: Option<String>,// file:line for repo findings
}

#[async_trait]
trait Detector {
    fn category(&self) -> Category;
    fn applies(&self, t: &Target) -> bool;   // declares required inputs
    async fn run(&self, t: &Target) -> Result<Vec<Finding>>;
}

struct Report { target: ..., findings: Vec<Finding>, scores: CategoryScores, overall: Grade }
```

A registry runs all **applicable** detectors **concurrently** (tokio for web,
rayon inside the repo scan). Scoring maps findings → per-category grade + overall
A–F. **Invariant:** every `Finding` carries verifiable `evidence`. This is what
makes results safe to show a client and is enforced at construction.

### The five detectors (all in v0.1)

| Detector | Input | Key crates | Notes |
|---|---|---|---|
| Headers/cookies/redirects | url | reqwest(rustls), tokio | ~7 headers, cookie flags, redirect chain |
| TLS/cert hygiene | url/host | tokio-rustls, rustls, x509-parser, webpki-roots | validity, expiry runway, TLS version, HSTS — no OpenSSL |
| Fingerprint + EOL | url | scraper, regex, bundled signatures JSON, endoflife.date | ~25 starter signatures (Drupal/WP/Symfony/Laravel/React/Next/Astro/nginx/Apache/Cloudflare) |
| Secrets/PII | repo | ignore, aho-corasick/regex, rayon | gitignore-aware, entropy + EU-PII (IBAN/email), low false-positive, non-zero exit |
| Deps/CVE | repo | lockfile parsers (serde_json/toml), OSV.dev API (reqwest), semver | composer.lock + package-lock first; OSV is free/no-key; offline cache later |

Shared crates: `clap`(derive), `serde`/`serde_json`, `comfy-table` + `owo-colors`,
`anyhow`/`thiserror`, `url`, `async-trait`.

External data sources: `endoflife.date` (EOL), `OSV.dev` (CVE). Both free, no key.
Fingerprint signatures are a small bundled JSON, Wappalyzer-style, starting with
the stacks iO actually encounters.

## Build phases

1. **Workspace + engine skeleton + Headers detector + CLI.** `Target`, `Detector`
   trait, `Finding`/`Report`, scoring, registry, table + `--json` output, exit
   codes. Headers detector end-to-end. → *shippable demo against any URL.*
2. **TLS + Fingerprint/EOL detectors.** Completes the URL-only web pre-flight.
3. **`--repo` support + Secrets + Deps/CVE detectors.** Full picture; stabilize
   the `recon-core` lib API + JSON schema (the downstream contract).
4. **Distribution + polish.** `frisk-mcp` wrapper, Homebrew tap, `cargo-dist`
   GitHub releases, README, CI (build/test/clippy/fmt), io-tooling-hub listing.

Phases are chunkable: phase 1 is the sequential foundation; the detectors in
phases 2–3 are independent and can be built in parallel once the trait + registry
exist.

## Ethics & scope (load-bearing)

Every web check is a single normal unauthenticated request — the same surface a
browser and a public CVE DB already see. No authentication, no fuzzing, no
exploitation, no rate-stressing. This bright line is what makes `frisk` legal to
point at a prospect's site and is the prerequisite for `PitchProofPack`. The
README and `--help` state the passive-only scope explicitly; the tool has no
active-attack capability to misuse.

## Testing

Build-first (no TDD): implement each detector, then add tests. Detectors are pure
over fixture inputs (recorded HTTP responses, sample certs, sample repos), so each
is unit-testable in isolation. A small integration test runs the CLI against a
local fixture server. `cargo clippy` + `cargo fmt` enforced in CI.

## Distribution

- `cargo install frisk` + prebuilt mac/linux binaries via `cargo-dist` GitHub releases.
- Homebrew tap (`brew install`).
- `frisk-mcp` so Claude/Cursor — and `web-audit-agent` — can call it as a tool.
- Listed on io-tooling-hub for iO-team one-click adoption.

## Downstream (not in this build, but the design enables)

- `web-audit-agent` calls `recon-core` (lib or MCP/JSON) to replace its slowest
  shell-out recon with one fast native call.
- `PitchProofPack` runs `frisk` (passive) on a prospect URL → ranks top-3
  CMO-readable findings → LLM write-up + web-audit-agent branded PDF + talk track.
```

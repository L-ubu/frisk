# frisk

Fast passive security & audit pre-flight for any site or repo, in Rust.

---

## What it does

`frisk` is a single fast binary that gives any website (and optionally its codebase) a quick security pat-down. Run it before a client meeting, before a deploy, or as a CI gate. It executes five checks in parallel and prints a graded A–F report with copy-paste fixes.

| Detector | What it finds |
|---|---|
| **Headers** | Missing/misconfigured security headers (CSP, HSTS, X-Frame-Options, …), insecure cookies, unsafe redirect chains |
| **TLS** | Certificate expiry runway, TLS version floor, cipher hygiene, HSTS preload eligibility |
| **Stack / EOL** | CMS/framework/server fingerprints, end-of-life version warnings (Drupal, WordPress, Laravel, nginx, …) |
| **Secrets** | AWS keys, private key blocks, API tokens, JWTs, IBAN/PII in the repository |
| **Deps / CVE** | Known CVEs in `composer.lock`, `package-lock.json`, and other lockfiles via the OSV.dev API |

URL-only invocation runs the three web detectors. Add `--repo <path>` to also run the two repo detectors.

---

## Example

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

---

## Install

```bash
cargo install --path crates/frisk-cli
```

Pre-built binaries for macOS and Linux (via `cargo-dist` GitHub Releases) and a Homebrew tap are coming in a later release.

---

## Usage

```bash
# Scan a URL (runs Headers, TLS, Stack detectors)
frisk https://example.com

# Scan a URL + local repo (all five detectors)
frisk https://example.com --repo ./code

# Machine-readable JSON output
frisk https://example.com --repo ./code --json

# CI gate — exit non-zero if any finding is critical or worse
frisk https://example.com --repo ./code --fail-on critical

# Severity levels: low | medium | high | critical
frisk https://example.com --fail-on high
```

---

## Ethics & scope

frisk performs passive checks only. Every web request is a normal, unauthenticated request — the same surface a browser and a public CVE database already see. There is no authentication, fuzzing, exploitation, or stress-testing. This makes it safe to run against any site you have a legitimate reason to assess.

---

## JSON output

`--json` emits a stable schema suitable for automation, MCP tool integration, and downstream report generation. See [`crates/recon-core/SCHEMA.md`](crates/recon-core/SCHEMA.md) for the full contract.

---

## Architecture

```
frisk/
├── crates/
│   ├── recon-core/   # reusable engine: Target, Detector trait, Finding/Report, scoring, registry
│   ├── frisk-cli/    # thin clap frontend → table / --json / exit codes
│   └── frisk-mcp/    # (coming) thin MCP server exposing recon-core as a tool
└── .github/workflows/
```

`recon-core` is a library crate designed to be embedded by other tools. `frisk-cli` and the upcoming `frisk-mcp` are thin frontends over the same engine. Downstream tools (`web-audit-agent`, `PitchProofPack`) consume `recon-core` directly via the stable JSON contract.

---

## License

MIT — see [LICENSE](LICENSE).

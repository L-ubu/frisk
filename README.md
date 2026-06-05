# frisk

Fast passive security & audit pre-flight for any site or repo, in Rust.

---

## What it does

`frisk` is a single fast binary that gives any website (and optionally its codebase) a quick security pat-down. Run it before a client meeting, before a deploy, or as a CI gate. It executes five checks in parallel and prints a graded report with copy-paste fixes.

| Detector | What it finds |
|---|---|
| **Headers** | Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy), CSP `unsafe-inline`, and cookies missing `Secure`/`HttpOnly` |
| **TLS** | Certificate expiry (expired or expiring within 21 days) and handshake/validation failure (invalid chain, untrusted CA, hostname mismatch, expired) |
| **Stack / EOL** | Technology/CMS/server fingerprints, end-of-life version warnings via endoflife.date (Drupal, WordPress, Laravel, nginx, …) |
| **Secrets** | AWS keys, private-key blocks, generic API tokens, JWTs, and IBAN/PII patterns in the repository, reported with `file:line`. Respects `.gitignore`. |
| **Deps / CVE** | Known CVEs in `package-lock.json` and `composer.lock` via the OSV.dev API |

URL-only invocation runs the three web detectors (Headers, TLS, Stack). Add `--repo <path>` to also run the two repo detectors (Secrets, Deps).

---

## Example

```
$ frisk https://prospect.example.com --repo ./their-codebase

  frisk  prospect.example.com
  ─────────────────────────────────────────────────────────────────────
  Severity   Category   Title
  ─────────────────────────────────────────────────────────────────────
  MEDIUM     headers    HSTS missing
  MEDIUM     headers    Content-Security-Policy missing
  HIGH       tls        Certificate expiring soon  (12 days remaining)
  HIGH       stack      Drupal 9.4.8 is end-of-life
  INFO       stack      Detected nginx 1.18
  CRITICAL   secrets    AWS access key found  (their-codebase/.env.bak:3)
  HIGH       deps       lodash 4.17.20: GHSA-p6mc-m468-83gw
  ─────────────────────────────────────────────────────────────────────
  7 findings · run `frisk … --json` for the full report
```

---

## Install

```bash
cargo install --path crates/frisk-cli
```

Pre-built binaries and a Homebrew tap are planned for a later release — see [Roadmap](#roadmap).

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

## Usage as an MCP server

`frisk-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server that exposes frisk as a single tool, `frisk_scan`, so AI agents (Claude Desktop, Cursor, and downstream tools like `web-audit-agent`) can run a scan. It speaks the MCP **stdio** transport (newline-delimited JSON-RPC) and shares the same `recon-core` engine as the CLI.

The tool takes two optional arguments, `url` and `repo` (at least one required), and returns the full graded report as JSON text.

```bash
# Build the server binary
cargo build --release -p frisk-mcp
# → target/release/frisk-mcp
```

Example MCP client config (e.g. `claude_desktop_config.json` / Cursor):

```json
{
  "mcpServers": {
    "frisk": {
      "command": "/absolute/path/to/frisk/target/release/frisk-mcp",
      "args": []
    }
  }
}
```

---

## Ethics & scope

frisk performs passive checks only. Every web request is a normal, unauthenticated request — the same surface a browser and a public CVE database already see. There is no authentication, fuzzing, exploitation, or stress-testing. This makes it safe to run against any site you have a legitimate reason to assess.

---

## JSON output

`--json` emits a stable schema suitable for automation, MCP tool integration, and downstream report generation. See [`crates/recon-core/SCHEMA.md`](crates/recon-core/SCHEMA.md) for the full contract.

---

## Roadmap

The following are planned but not yet implemented in v0.1:

- **Redirect-chain analysis** — follow redirects and flag insecure hops
- **TLS version / cipher checks** — explicit TLS 1.0/1.1 detection and weak-cipher flagging (rustls already negotiates TLS 1.2+ so a separate floor check is intentionally deferred)
- **HSTS preload eligibility** — check `includeSubDomains` + long `max-age` + preload flag
- **More lockfile ecosystems** — yarn, pnpm, pipenv, go.sum / go.mod
- **Branded PDF export** — one-click client-ready report
- **Prebuilt binaries / Homebrew** — via `cargo-dist` and a Homebrew tap

---

## Architecture

```
frisk/
├── crates/
│   ├── recon-core/   # reusable engine: Target, Detector trait, Finding/Report, scoring, registry
│   ├── frisk-cli/    # thin clap frontend → table / --json / exit codes
│   └── frisk-mcp/    # MCP stdio server exposing recon-core as a `frisk_scan` tool
└── .github/workflows/
```

`recon-core` is a library crate designed to be embedded by other tools. `frisk-cli` and `frisk-mcp` are thin frontends over the same engine, sharing the detector set via `recon_core::all_detectors()`. Downstream tools (`web-audit-agent`, `PitchProofPack`) consume `recon-core` directly via the stable JSON contract.

---

## License

MIT — see [LICENSE](LICENSE).

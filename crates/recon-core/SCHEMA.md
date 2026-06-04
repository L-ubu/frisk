# recon-core JSON output contract (`--json`)

This document describes the stable JSON schema produced by `frisk --json`.
It is the contract that `web-audit-agent`, `frisk-mcp`, and other downstream
tools depend on.

---

## Top-level: `Report`

```json
{
  "target":        "<string>",
  "findings":      [ <Finding>, … ],
  "categories":    [ <CategoryScore>, … ],
  "overall_score": <0–100>,
  "overall_grade": "<grade>"
}
```

| Field | Type | Description |
|---|---|---|
| `target` | string | The URL or path that was scanned. |
| `findings` | array of `Finding` | All findings across all detectors, in detection order. |
| `categories` | array of `CategoryScore` | One entry per detector category that actually ran. |
| `overall_score` | integer 0–100 | Mean of per-category scores. |
| `overall_grade` | grade enum | Letter grade derived from `overall_score`. |

---

## `Finding`

```json
{
  "category":   "<category>",
  "severity":   "<severity>",
  "title":      "<string>",
  "evidence":   "<string>",
  "fix":        "<string>",
  "references": [ "<string>", … ],
  "location":   "<string>"
}
```

| Field | Type | Description |
|---|---|---|
| `category` | category enum | Which detector produced this finding. |
| `severity` | severity enum | Risk level. |
| `title` | string | Short human-readable name for the issue. |
| `evidence` | string | The actual header value, cert detail, version string, matched text, etc. Always present; never an assertion without proof. |
| `fix` | string | Remediation guidance. |
| `references` | array of string | CVE / CWE / advisory / doc links. **Omitted when empty.** |
| `location` | string | File and line number (`path/to/file:42`) for repo findings. **Omitted when absent.** |

---

## `CategoryScore`

```json
{
  "category": "<category>",
  "score":    <0–100>,
  "grade":    "<grade>"
}
```

| Field | Type | Description |
|---|---|---|
| `category` | category enum | The detector category. |
| `score` | integer 0–100 | Category score (starts at 100, minus weighted deductions per finding). |
| `grade` | grade enum | Letter grade derived from `score`. |

---

## Enum values

### `severity`
`info` | `low` | `medium` | `high` | `critical` (always lowercase)

Severity weights used in scoring:
- `critical` → −40 pts
- `high` → −20 pts
- `medium` → −10 pts
- `low` → −5 pts
- `info` → 0 pts

### `category`
`headers` | `tls` | `stack` | `secrets` | `deps` (always lowercase)

### `grade`
`A` | `B` | `C` | `D` | `F` (always uppercase)

Grade thresholds: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

---

## Optional field behavior

- `references`: key is **omitted** when the array would be empty (not `[]`).
- `location`: key is **omitted** when not applicable (not `null`).

Consumers MUST treat both as optional when deserialising.

---

## Example

```json
{
  "target": "https://example.com",
  "findings": [
    {
      "category": "headers",
      "severity": "medium",
      "title": "Content-Security-Policy missing",
      "evidence": "response has no `content-security-policy` header",
      "fix": "Define a CSP restricting script/style/connect sources."
    },
    {
      "category": "secrets",
      "severity": "critical",
      "title": "AWS access key found",
      "evidence": "AKIAIOSFODNN7…",
      "fix": "Remove the secret, rotate it, and store it in a secret manager (add the file to .gitignore).",
      "location": ".env.bak:3"
    }
  ],
  "categories": [
    { "category": "headers", "score": 90, "grade": "A" },
    { "category": "secrets", "score": 60, "grade": "D" }
  ],
  "overall_score": 75,
  "overall_grade": "C"
}
```

---

## Stability guarantees

- All field names are stable from v0.1.
- New optional fields may be added in minor versions; consumers must ignore unknown keys.
- Enum string values will not change or be removed without a major version bump.
- `references` and `location` will remain omit-when-empty (never serialised as `null`).

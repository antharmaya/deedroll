# deedroll output schema, v1

`--json` prints one document tagged `"schema": "deedroll/v1"`. `--sarif` prints SARIF 2.1.0 built
from the same result, so the two never disagree. v1 is additive-only: fields may be added, and
none will be renamed, retyped or removed without a v2.

## A package or remote scan

```json
{
  "schema": "deedroll/v1",
  "tool": { "name": "deedroll", "version": "0.1.0" },
  "target": "pypi:acme-mcp",
  "package": { "ecosystem": "pypi", "name": "acme-mcp", "version": "1.0", "sha256": "…", "file": "acme_mcp-1.0-py3-none-any.whl" },
  "listing": { "name": "io.github.acme/acme-mcp" },
  "declaredEnv": ["ACME_REGION"],
  "findings": [
    {
      "id": "9f2c4e1a7b3d5c60",
      "check": "undeclared-env",
      "subject": "ACME_API_KEY",
      "severity": "high",
      "message": "reads ACME_API_KEY (looks like a credential) but the registry entry does not declare it",
      "evidence": [{ "file": "acme_mcp/server.py", "line": 12, "text": "key = os.environ.get(\"ACME_API_KEY\")" }]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `package.ecosystem` | `npm` or `pypi`. `null` package for remote-only targets. |
| `package.file` | For PyPI, the exact file read: the wheel pip would install, or the sdist it would build. |
| `listing` | The official-registry listing the scan was judged against, or `null` when none ships this package. |
| `remote` | Present for URL targets: whether the probe got as far as listing tools, and why not. |
| `findings[].id` | Stable fingerprint of check + subject + first evidence file. It ignores line numbers and daily-changing counts, so it survives edits and re-scans; use it for baselines and suppressions. |
| `findings[].check` | Stable rule id. The catalog, with why each matters and what to do, is `RULES` in `src/rules.js`. Ids are never renamed or reused. |
| `findings[].severity` | `high`, `medium`, `low` or `info`. The same check can carry different severities (a credential is high, a setting is low). |
| `findings[].message` | For people. Its wording may change in any release; do not parse it. |
| `findings[].documented` | Optional, on `undeclared-env` only: `"README"` when the package's own README (or PyPI METADATA) documents the variable. Then the finding is `low` (or `info` with no registry entry): a gap in the listing, not a hidden read. Added 2026-10-01; additive, so schema v1 is unchanged. |
| `findings[].evidence[]` | `file` is a path inside the package, or a source such as `npm`, `PyPI metadata` or `registry`. `line` 0 means no line. `text` is the line, trimmed. |

`--installed --json` wraps the same finding shape per configured server:
`{ "schema", "tool", "configs": [...], "servers": [{ "name", "agent", "file", "findings": [...] }] }`.

## `--registry-meta`

A compact block for a registry or marketplace to attach to a listing's `server.json` `_meta`, the
mechanism the official registry's aggregator guide describes for "security scan results". Counts
and pointers only, no code text, so it fits inside a listing; the v1 JSON is the full report.

```json
{
  "com.antharmaya/deedroll": {
    "schema": "deedroll/v1",
    "tool": { "name": "deedroll", "version": "0.1.0" },
    "scannedAt": "2026-09-28T12:53:31.695Z",
    "target": "npm:pretrip-mcp",
    "package": { "ecosystem": "npm", "name": "pretrip-mcp", "version": "1.0.1", "sha256": "2b35…" },
    "counts": { "high": 1, "medium": 1, "low": 1, "info": 1 },
    "findings": [
      { "id": "b43f3faf2df668f7", "check": "undeclared-env", "severity": "high", "subject": "PRETRIP_API_KEY", "at": "index.mjs:23" }
    ]
  }
}
```

For hosted servers the block also carries `remote: { probed, era, protocolVersion, tools }`.
`info` findings are counted but not listed.

## SARIF mapping

| deedroll | SARIF |
|---|---|
| `check` | `ruleId`, with rule title, description and help from the catalog |
| `high` / `medium` / `low` / `info` | `error` / `warning` / `note` / `note`, plus `properties.security-severity` 8.0 / 5.0 / 3.0 / 0.0 for GitHub |
| `id` | `partialFingerprints["deedroll/v1"]` |
| evidence path | `physicalLocation` relative to the `PACKAGE` base; a region only when `line > 0` |
| evidence source (`npm`, `registry`) | `logicalLocations` |

Checked against the official SARIF 2.1.0 JSON schema.

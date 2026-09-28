# How mcpscan is built

For anyone changing the code, or deciding what to build next. It covers three things: the seams
(where the parts meet), the decisions that are expensive to reverse, and what breaks first.

## The shape: ports and adapters

```
            sources (adapters)                  core (pure)                   outputs
  ┌───────────────────────────────┐   ┌───────────────────────────┐   ┌──────────────────────┐
  │ npm      sources.js (Node)    │   │ model.js   rules, lookups │   │ report.js   terminal │
  │          browser.js (web)     │──▶│ checks.js  every check    │──▶│ output.js   JSON v1  │
  │ PyPI     pypi.js (both)       │   │ tools.js   tool extraction│   │ sarif.js    SARIF    │
  │ remote   remote.js (probe)    │   │ osv.js     advisories     │   │ registry _meta block │
  │          auth.js (sign-in)    │   │ rules.js   the catalog    │   │ web/app.js  the page │
  │          remote-scan.js       │   │ pins-core  tool memory    │   │ --egress allowlist   │
  │ configs  installed.js         │   │                           │   │                      │
  └───────────────────────────────┘   └───────────────────────────┘   └──────────────────────┘
        archive.js, zip.js, tar.js: reading archives in memory, never to disk
        relay-core.js + relay-node.js: the probe relay (scripts/serve.js hosts it)
        scripts/snapshot.js: the daily, hash-chained registry history
```

**The seam that matters is the `pkg` shape.** Every source adapter produces the same object:
`{ ecosystem, name, version, files: Map<path, bytes>, manifest, provenance, integrityOk, … }`.
Every check reads that shape and nothing else. That is why adding PyPI took a source adapter and
a zip reader, and almost no check changes. The next ecosystem (MCPB, OCI) is the same move.

**The second seam is `findings`.** Checks return `{ check, subject, severity, message, evidence }`.
Every output (terminal, JSON, SARIF, registry block, web page) is a function of that list, so they
cannot disagree.

**One probe, three hosts.** `inspectRemote` (remote-scan.js) is everything knowable about a
hosted server without an account. The CLI adds pins on disk; the browser adds pins in the
visitor's own storage; the relay runs it for servers that block browsers. Only the fetch and
where pins live differ.

**Two platforms, one engine.** `pypi.js`, `archive.js`, `zip.js`, `model.js`, `checks.js`,
`rules.js` and `osv.js` use only web platform APIs (fetch, DecompressionStream, crypto.subtle), so
the same code runs in Node 22 and in the browser page. `scripts/browser-parity.js` proves the two
paths give identical files, hashes and findings on real packages.

## Decisions that are expensive to reverse (one-way doors)

| Decision | Why it was made this way | What reversing it would cost |
|---|---|---|
| **Never execute what is inspected** | A scanner that runs the code it vets is the attack surface it warns about. | It is the product's promise. Adding dynamic tracing later must be a separate, opt-in sandbox. |
| **Check ids and the v1 output schema** | CI configs, suppressions and dashboards key on them. | Once public, renaming a check breaks users' pipelines. Ids are never renamed or reused (`src/rules.js`). |
| **Finding fingerprints ignore line numbers** | Baselines must survive edits and re-scans. | Changing the recipe invalidates every stored baseline. |
| **Zero dependencies** | A security tool's dependencies are its attack surface. | Cheap to add one, impossible to credibly remove them once users rely on the promise. |
| **Nothing leaves the machine except names and versions** | The difference from scanners that upload tool descriptions. | Any telemetry, even opt-out, ends the claim. |
| **The name `mcpscan`** | Chosen early. | 48 GitHub repositories use the name, including Ant Group's `antgroup/MCPScan`; npm `mcp-scan` belongs to another project. Renaming gets harder with every link and download. Decide before publishing. |

Everything else (which checks exist, their severities, the web design, the index format) is a
two-way door and should change when data says so.

## Failure modes, and what the code does about them

| What goes wrong | Where | Handling |
|---|---|---|
| A registry does not answer, or answers 503 | PyPI's provenance endpoint (measured), the MCP registry (7 s lookups) | "Unknown" is never reported as "absent". Provenance comes from the Simple API, which is reliable; the flaky endpoint is best-effort detail only. |
| A missing scoped npm package looks like being offline | npm sends no CORS header on scoped 404s | The browser probes an unscoped name to tell the two apart. |
| A hostile archive | Zip bombs, huge files, encrypted entries | Inflation is capped by actual output, not the declared size; files over 1 MB are skipped and said so. |
| A hostile hosted server | Endless streams, redirects, huge replies | 15 s timeout, 5 MB cap, redirects never followed. |
| Two protocol generations | 2026-07-28 removed `initialize` | Dual-era probe: current request first, fall back only on a non-modern error body. |
| False positives in the credential rule | Names like KEYCLOAK_REALM, MAX_TOKENS | The word must end a name segment; every tightening is re-checked against the published measurement. |
| **The relay as an SSRF door** | Anyone can ask it to fetch a URL; a hostile server's own OAuth metadata can name internal addresses | https only; no credentials or caller headers; discovery requests only; every connection resolved once, every address vetted, and the connection pinned to the vetted address (defeats DNS rebinding); IP literals vetted separately, because Node skips a custom lookup for them. Two holes were found in testing and closed with tests: `[::ffff:127.0.0.1]` rewritten by the URL parser to a form a textual check missed, and IP-literal hosts bypassing the pinned lookup. |
| A browser blocked by CORS reads nothing | Most hosted servers and many sign-in metadata endpoints | "Could not read from here" is reported as unknown, never as missing; the page offers the relay instead of guessing. |
| The history dies quietly | A daily timer on one machine | `snapshot.js --status` warns when the last entry is over 48 hours old; `--verify` re-hashes every file and checks the chain. |
| A test suite that passes but proves nothing | Any guard | New guards are mutation-checked: remove the guard, and its test must fail. |

## Where the data lives

- `src/data/registry-index.json`: package name → registry listings, rebuilt by
  `scripts/build-index.js` (a full walk of the registry takes about 10 minutes).
- `~/.cache/mcpscan/tarballs`: npm tarballs by sha512, re-verified on read.
- `~/.config/mcpscan/pins.json` (`$XDG_CONFIG_HOME/mcpscan/` when set): tool fingerprints of probed hosted servers.
- `findings.json`, `population.json`: the stored rows behind the published npm measurement.
- `archive/` (not in git): the registry history. `registry/DATE.jsonl.gz` (every listing's
  declarations), `registry/DATE.diff.json`, `tools/DATE.jsonl.gz` (tool fingerprints and text
  of a rotating slice of hosted servers), and `chain.jsonl`, where each line carries the hashes
  of that day's files and of the line before it.
- Browser pins: `localStorage["mcpscan-pins"]` in the visitor's own browser; relay consent:
  `localStorage["mcpscan-relay"]`.

## Adding things

- **A check:** write it in `checks.js` returning findings with evidence, add its id to `RULES` in
  `rules.js` (a test fails otherwise), place it in a group in `scripts/build-docs.js`, run
  `node scripts/build-docs.js`, and add a test that fails when the check is removed.
- **An ecosystem:** a source adapter that returns the `pkg` shape, a `registryType` mapping in
  `build-index.js`, dispatch in `index.js` and `browser.js`, and a benchmark script on a random
  sample before anyone quotes a number from it.

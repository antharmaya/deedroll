# mcpscan

Check an MCP server before you trust it. mcpscan reads what a server's code actually does and
compares it with what the server tells you, then reports every difference with the file and line
that proves it.

It never installs, extracts to disk, or runs what it inspects. Packages are read in memory, so
install scripts never run. Hosted servers are asked for their tool list, and how their sign-in
works, and nothing else: no tool is ever called.

**What leaves your machine:** public package names and versions (sent to npm or PyPI, the MCP
registry and OSV.dev); a probe contacts the server you name. No scan result, config, key or tool
description is ever sent anywhere. No account, no API key.

## Try it in a minute

**In a browser:** https://mcpscan.harshavar968.workers.dev (the same engine, running in the page).
To run it locally instead: `node scripts/serve.js`, then open http://localhost:4173/web/.

Type a server URL, a package or a registry name, click an example, or paste what your config
says (`npx -y …`, `uvx …`).

Most hosted servers don't let web pages read their answers (25 of 44 sampled, 2026-09-28). For
those, the page offers mcpscan's relay: the same read-only probe, run from the server behind the
page. It asks first, sees only the URL, and stores nothing. `scripts/serve.js` includes the relay
for local use.

The page does everything the command line does:

| In the page | Command line |
|---|---|
| Scan a package, a server URL or a registry name | `mcpscan <target>` |
| **Check this computer**: which MCP servers on common ports a website could reach | `mcpscan --local` (every port, and `--subnet`) |
| **Servers your agents trust**: choose your config files; read in the page, never uploaded | `mcpscan --installed` |
| Download the report as JSON, SARIF, an egress allowlist or a registry block | `--json`, `--sarif`, `--egress`, `--registry-meta` |
| Why each finding matters, and every check | `mcpscan explain` |
| The registry history, and **verifying it** in your browser | `snapshot.js --status`, `--verify` |

Not in the page: `--deps`, the agent-judge protocol (`--semantic=agent`), and tool-name
collisions (which needs every configured server's tools fetched at once, not one at a
time on click) — these need a command line.

**On the command line** (Node 22+):

```
npx @antharmaya/mcpscan io.github.owner/some-server     # any official-registry listing
npx @antharmaya/mcpscan npm:@modelcontextprotocol/server-filesystem
npx @antharmaya/mcpscan pypi:mcp-server-fetch
npx @antharmaya/mcpscan https://learn.microsoft.com/api/mcp
npx @antharmaya/mcpscan --installed                     # everything your agents already trust
npx @antharmaya/mcpscan explain                         # what every check means
```

From a clone, `node bin/mcpscan.js` works the same way. (Not yet published to npm.)

## What it can scan

| You give it | What happens |
|---|---|
| A registry name, `io.github.owner/server` | Looks the listing up in the official MCP registry. If it ships an npm or PyPI package, reads it; if it is hosted only, probes it. Also reports when the registry has deprecated or removed the listing. |
| `npm:<package>` | Downloads the tarball, verifies npm's hash, reads it in memory. |
| `pypi:<package>` | Reads the wheel `pip install` would pick (pure-Python first), or the sdist when there is no wheel, and verifies PyPI's hash. |
| `https://<host>/mcp` | Lists the server's tools read-only, never calls one. Speaks the current protocol (2026-07-28, stateless) and older ones. Pins the tools and reports changes on later runs. If it requires sign-in, checks how that sign-in is built, from public metadata only. |
| `--installed` | Reads the MCP configs of Claude Code, Codex, Claude Desktop, Cursor, Devin and Gemini CLI, scans each npm and PyPI server, and with `--remote` probes hosted ones. Nothing is launched. |
| `--local` | Finds MCP servers listening on this machine (every listening port, with the owning process) or, with `--subnet 192.168.1.0/24`, on a private network you own. Checks each for network exposure, sign-in, and whether it rejects requests from other websites, as the specification requires. |

Not yet: Docker images, `.mcpb` bundles, NuGet and Cargo packages; the tool lists of servers that
require sign-in (their sign-in is checked, their tools are not listed, since mcpscan uses no
account); and tool lists over the deprecated HTTP+SSE transport (detected and reported). Each is
reported as "not scanned" with the reason, never as clean.

## Reading a result

```
  pretrip-mcp@1.0.1
  in registry · no env vars declared · 2 file(s) scanned
  registry: listed as agency.kesey/pretrip (found via index of 2026-09-28)
  provenance: none

  HIGH   undeclared-env  reads PRETRIP_API_KEY (looks like a credential) but the registry entry does not declare it
         index.mjs:23  const API_KEY = process.env.PRETRIP_API_KEY || "";
  MEDIUM provenance  no repository field: the published code cannot be traced to source
         package.json  repository: absent
  LOW    undeclared-env  reads PRETRIP_API_BASE but the registry entry does not declare it
         index.mjs:22  const API_BASE = (process.env.PRETRIP_API_BASE || "https://scan.kesey.agency/api/v1")…
  INFO   network-egress  contacts scan.kesey.agency

  1 high · 1 medium · 1 low · 1 info
  What these mean: mcpscan explain undeclared-env · mcpscan explain provenance
```

| Severity | Meaning |
|---|---|
| **high** | Do not install until you have looked. |
| **medium** | Worth understanding before you rely on it. |
| **low** | Good to know. |
| **info** | Context, not a problem. A filesystem server writing files is the product working. |

Every finding names a check. `mcpscan explain <check>` says why it matters and what to do; the web
page shows the same text under each finding; [docs/checks.md](docs/checks.md) lists all of them.
The exit code is 1 when anything at or above `--fail-on` (default `high`) is found, so it fits in CI.

## Output for tools

| Flag | For |
|---|---|
| `--json` | Scripts and pipelines. Schema `mcpscan/v1` ([docs/schema-v1.md](docs/schema-v1.md)): stable check ids, and a stable `id` per finding for baselines and suppressions. |
| `--sarif` | GitHub code scanning, Azure DevOps and security dashboards. SARIF 2.1.0, validated against the official schema. |
| `--egress` | Egress proxies. The hosts the server's code names, as a starting allowlist (static, so a starting point). |
| `--registry-meta` | Registries and marketplaces. A `_meta` block under `com.antharmaya/mcpscan` that a subregistry can attach to a listing: the mechanism the official registry documents for "security scan results". |

GitHub code scanning, for example:

```yaml
- run: npx @antharmaya/mcpscan io.github.owner/server --sarif > mcpscan.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: mcpscan.sarif }
```

## What it checks

Grouped here; every check, with why and what to do, is in [docs/checks.md](docs/checks.md).

- **The code against the listing.** Credentials and settings the code reads that the registry
  entry never declares, code that runs at install (including PyPI packages with no wheel), hosts it
  contacts, powerful capabilities (running programs, evaluating code, writing files), and tool
  descriptions written to instruct the model.
- **Where the code came from.** No linked source, a download that does not match the registry's
  hash, provenance present on earlier releases and missing now, and a release built from a
  different repository than the one it links to. Deprecated npm versions and yanked PyPI releases.
- **The listing itself.** Deprecated or removed by the registry, or claimed by several listings.
- **Known vulnerabilities**, from OSV.dev (includes GitHub's advisories). A failed lookup is
  reported as failed, never as clean.
- **Hosted servers.** A tool description that changed since the last probe is **high**, with the
  old and new text: a hosted server can rewrite what its tools tell the model at any time. For
  servers that require sign-in: whether they publish how to sign in (as the spec requires),
  PKCE, issuer and token-audience checks, and registration only through deprecated mechanisms.
- **Upstream status.** Reference servers the MCP project has archived, which PyPI does not mark.
- **Your own configs.** Plaintext secrets, launches that always pull the newest version, and two different servers offering a tool with the same name (a client resolves tools by name, so either could silently answer a call meant for the other).

## How it compares

Checked against each project's own README on 2026-09-28.

| | mcpscan | Snyk Agent Scan | Cisco mcp-scanner |
|---|---|---|---|
| Runs the server to inspect it | Never | Starts stdio servers from your config | No |
| Sends tool descriptions elsewhere | Never | To Snyk (cannot be disabled) | Only with its API or LLM analyzers |
| Account or API key needed | No | Snyk token | Only for its API, LLM and VirusTotal analyzers |
| Reads npm and PyPI packages | Yes | No | Yes |
| Registry listing compared with the code | Yes | No | No (compares docstrings with code, through an LLM) |
| Provenance and publisher checks | Yes | No | No |
| Rug-pull pins for hosted tools | Yes | Yes | No |
| SARIF output | Yes | Not documented | No |
| Runs in a browser | Yes | No | No |
| Model judgment of descriptions | Optional, by your own agent | Yes, by Snyk | Optional |

Where they are ahead: both judge tool descriptions for prompt injection with a model by default;
Cisco traces dataflow across files in ten languages; Snyk also covers agent skills. mcpscan's
place is the check you run **before** installing, with evidence for every finding and nothing sent
anywhere. An independent audit that ran three scanners on 33 servers found about 78% of their
pattern detections were false positives
([AppSec Santa, July 2026](https://appsecsanta.com/research/mcp-server-security-audit-2026));
mcpscan only reports what it can point at.

## Hosted servers: probe, pin, and catch the rug pull

```
mcpscan https://learn.microsoft.com/api/mcp        # probe, check descriptions, pin every tool
mcpscan https://learn.microsoft.com/api/mcp        # later: reports anything that changed
mcpscan <url> --update-pins                        # accept the changes and re-pin
mcpscan --installed --remote --auth-from-env       # every hosted server your agents trust
```

- **Both protocol generations.** Revision 2026-07-28 made MCP stateless: no `initialize`, no
  session, version and client identity on every request. mcpscan sends a current request first and
  falls back to the older handshake only when the reply shows an older server, as the
  specification prescribes. On 30 random registry endpoints (2026-09-28): 2 answered on
  2026-07-28, 18 on older revisions, 5 needed sign-in, 5 were not live.
- **Read-only by construction:** only `tools/list` (plus `initialize` for older servers), never
  `tools/call`. The server does see the connection.
- **Never auto-accepted:** a changed server is reported on every probe until `--update-pins`.
- **Hostile-server limits:** a 15 s timeout, a 5 MB response cap, and redirects not followed (a
  redirect would carry the request, and any credential, somewhere else).
- **Credentials are opt-in:** `--auth-from-env` resolves `${VAR}` header references and sends them
  only to that server.

## The registry history

A hosted server can change what its tools say after you approved them, and the official
registry keeps no guarantees about its own data. So mcpscan keeps a record: once a day, every
listing's declarations (packages, settings, endpoints, status), a diff against the day before,
and the tool lists of a rotating slice of hosted servers. Each day's entry is hash-chained to the
one before, so the history cannot be quietly rewritten.

```
node scripts/snapshot.js              # take today's snapshot (a daily systemd timer runs this)
node scripts/snapshot.js --status     # the last runs, and a warning if the record went stale
node scripts/snapshot.js --verify     # re-hash every file and check every link in the chain
```

Published at https://mcpscan.harshavar968.workers.dev/history/chain.jsonl (Cloudflare R2), and
verifiable from the web page. The local copy is under `archive/` (not in git). Measured on the first run: about 4 MB a day (3.4 MB of listings, 0.6 MB of tool lists), roughly 1.5 GB a year before deduplication. At 500 endpoints a day, every hosted endpoint comes round about every 46 days.

## Audit what you already trust

```
npx @antharmaya/mcpscan --installed     # --all for every server, --remote to probe hosted ones
```

Your config files contain live keys, so values are dropped the moment they are parsed: every later
stage sees a variable's name and whether it was a literal, never its value. A test plants a fake
secret in every place a config can hold one and fails if it appears in any output.

## Use it from Claude Code or Codex

The static scan knows what the code *can* do. Whether the descriptions *say so* is a language
question, and the agent you already run can answer it, with no API key:

```
mcpscan npm:<package> --semantic=agent > request.json   # what to judge, and the rules
mcpscan --answers answers.json                          # the agent's answers, checked and applied
```

The descriptions were written by the publisher, so the request treats them as untrusted data, a
"yes" must quote the disclosing sentence verbatim (checked), and answers are bound to a hash of the
exact request. Install the skill so your agent scans before installing any server:

```
claude plugin marketplace add ./mcpscan && claude plugin install mcpscan@antharmaya   # Claude Code
cp -r mcpscan/skills/mcpscan ~/.codex/skills/                                         # Codex
```

`--semantic` does the same through TypeSafe's API instead (`TYPESAFE_API_KEY`); its thresholds are
not calibrated yet. The default scan never calls a model.

## Speed, cache and the registry index

- The official registry's search matches listing names only, so mcpscan ships an index from
  package names to listings (`src/data/registry-index.json`: 36,906 listings, 9,796 npm and 3,868
  PyPI packages, built 2026-09-28 by `scripts/build-index.js`). A complete index under seven days
  old is trusted on a miss, and says so ("no listing as of <date>").
- npm tarballs are cached compressed under `~/.cache/mcpscan/tarballs`, keyed by their sha512 and
  re-verified on every read. `--no-cache` turns it off.
- `--deps` also reads a vendor's own dependencies (one level, bounded). On 27 vendor servers it
  changed the capability picture for 10, at about 60% more download, so it is off by default.
- Median scan: 0.9 s over 40 random PyPI listings. The registry itself is sometimes slow (7 s per
  lookup on 2026-09-28); the web page says so rather than timing out.

## What it does not do

It is static. It reads code, not behaviour: a server that builds a hostname at runtime or
downloads code after starting will not be caught. It does not follow dataflow across files, so it
reports that a credential is *read*, not where it goes. `info` findings are not accusations.

## Measurements

**npm, 2026-09-26.** A seeded random sample of 60 npm-backed registry servers
(`node scripts/registry-sweep.js 60`, seed `20260926`): 57 scanned across 53 publishers, and **13
(23%, 95% CI 14–35%) read a credential their listing never declares**, across 10 publishers. Four
read an undeclared `X402_PRIVATE_KEY` (agent payment keys). The credential rule was tightened twice
(locator names like `*_URL` on 2026-09-27; words inside other words, like KEY in KEYCLOAK, on
2026-09-28); recomputed from the stored rows each time, the figure held at 13. Raw rows:
`findings.json`. Limits: npm-backed servers in the first 12,000 registry entries only.

**PyPI, 2026-09-28.** 40 random PyPI-backed listings (`node scripts/pypi-benchmark.js 40`): all 40
scanned, none errored. A benchmark of the scanner, not a published statistic.

## Documentation

| | |
|---|---|
| [docs/checks.md](docs/checks.md) | Every check: why it matters, what to do (generated from `src/rules.js`) |
| [docs/schema-v1.md](docs/schema-v1.md) | The `--json`, `--sarif` and `--registry-meta` output contract |
| [docs/architecture.md](docs/architecture.md) | How it is built: the seams, the one-way doors, the failure modes |
| [docs/nsa-coverage.md](docs/nsa-coverage.md) | What mcpscan covers of the NSA's MCP security guidance (May 2026), and what it does not |
| [web/DESIGN.md](web/DESIGN.md) | The web page's design system |
| `mcpscan --help`, `mcpscan explain` | The same, in the terminal |

## Deploying

The page, the relay and the history are one Cloudflare Worker (`wrangler.toml`, `deploy/worker.js`):

```
node scripts/build-site.js      # site/: the page and engine, with a Content-Security-Policy
npx wrangler deploy             # static assets, /api/probe (rate-limited), /history/* from R2
```

The daily snapshot uploads to the R2 bucket when `MCPSCAN_R2_BUCKET` is set (the systemd unit
sets it); `node scripts/snapshot.js --upload mcpscan-history` retries anything not yet uploaded.

## Development

```
npm test                              # ~140 tests, no network
node scripts/serve.js                 # the web page at http://localhost:4173/web/
node scripts/browser-parity.js        # browser and CLI give identical results (uses the network)
node scripts/build-index.js           # rebuild the registry index (~10 minutes)
node scripts/build-docs.js            # regenerate docs/checks.md after editing src/rules.js
node scripts/build-web-data.js        # regenerate the page's demo scan and registry figures
node scripts/registry-sweep.js 60     # the npm measurement; pypi-benchmark.js for PyPI
node scripts/snapshot.js --status     # the registry history
```

Zero dependencies, on purpose: a security tool's dependencies are its attack surface. MIT.

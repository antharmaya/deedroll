# mcpscan

Static trust scanner for MCP servers. It diffs **what a server's code actually does** against
**what its registry entry declares**, and reports the difference with file-and-line evidence.

It never installs, extracts or executes what it inspects. The npm tarball is parsed in memory, so
install scripts never run and a malicious path never touches your filesystem.

**What leaves your machine:** public package names and versions, looked up on npm, the MCP registry
and OSV.dev (`--no-osv` skips the last). No scan result, config, key or tool description is ever
sent anywhere.

```
npx @antharmaya/mcpscan npm:@modelcontextprotocol/server-filesystem
npx @antharmaya/mcpscan io.github.owner/some-server --json
```

## Audit what you already trust

```
npx @antharmaya/mcpscan --installed
```

Reads the MCP configs of Claude Code, Codex, Claude Desktop, Cursor, Windsurf and Gemini CLI,
lists every server your agents trust, and statically scans each npm-launched one. **Nothing is
launched.** On top of the package checks it reports two risks that need no package at all:

- **unpinned launches** — `npx some-mcp` or `@latest` runs whatever was published most recently,
  every time the agent starts. (On the first machine this ran on, `npx prisma mcp` was running
  `8.0.0-rc.17`, a release candidate, because that is where npm's `latest` tag pointed.)
- **plaintext secrets** — API keys written as literal values in `env`, headers or arguments rather
  than referenced as `${VAR}`.

Your config files contain live keys, so values are dropped the moment they are parsed: every later
stage sees a variable's *name* and whether it was a literal, never its value, and raw arguments and
URL query strings are never printed. A test plants a fake secret in every place a config can hold
one and fails if it appears in any output.

Remote servers, PyPI launches, containers and local binaries are listed with the reason they could
not be scanned statically, so coverage is visible rather than silently partial.

## Why

The official MCP registry's schema has a place to declare the environment variables a server needs,
including `isSecret` and `isRequired` flags. Most publishers leave it empty. Nothing in the registry
checks, because [the official registry does not scan servers](https://dev.to/sam_curatedmcp/five-hard-problems-in-the-mcp-ecosystem-3651)
and [9 of 11 major MCP directories accepted typosquatted payloads](https://nimblebrain.ai/blog/state-of-mcp-security-2026/)
with no automated review.

So you install a server, and the first thing you learn about which credentials it wants is when it
asks for them — or doesn't ask, and reads one you already exported.

## What it checks

| Check | Severity | What it means |
|---|---|---|
| `undeclared-env` | high / medium / low | The code reads an environment variable the registry entry never declares. High when the name looks like a credential. |
| `install-script` | high / low | `preinstall`, `install` or `postinstall` runs on `npm install`. The classic supply-chain vector. |
| `provenance` | high / medium / low | No repository field, tarball does not match npm's integrity hash, single version, published days ago. |
| `typosquat` | high / medium | Name is an unscoped clone of, or within two characters of, an official package. |
| `deprecated` | medium | npm itself marks this version deprecated — often with a pointer to where the vendor moved (for several, a hosted server). |
| `known-vulnerability` | high / medium / low | Published advisories for this exact version, from OSV.dev (includes GitHub's), with the fixed version. A failed lookup is reported as failed, never as clean. |
| `provenance-dropped` | medium | Earlier versions were published with npm provenance (built by CI from a named repo) and this one was not — a known sign of a publish from a stolen token. Never having provenance is not flagged. |
| `multiple-listings` | info | More than one registry listing points at this package. |
| `network-egress` | info | Every external host reachable from the source, minus hosts the entry declares. |
| `capability` | info | Process execution, dynamic evaluation, filesystem writes, raw sockets. |

Exit code is 1 when anything at or above `--fail-on` (default `high`) is found, so it fits in CI.

## Registry lookup, cache and speed

- **Which listing ships this package?** The registry's own search matches listing names only, so
  mcpscan ships `src/data/registry-index.json`, built by `scripts/build-index.js` from every
  current listing (36,586 listings, 9,744 npm packages, 2026-09-27). A complete index under seven
  days old is trusted on a miss and reported as "no listing as of <date>"; an older one falls back
  to a verified live name search. When a listing is found, undeclared credentials are judged
  against what it actually declares.
- **Cache.** Tarballs are cached compressed under `~/.cache/mcpscan/tarballs`, keyed by npm's own
  sha512 integrity and re-verified on every read; a file that no longer matches is deleted.
  Package metadata is never cached. `--no-cache` or `MCPSCAN_NO_CACHE=1` turns it off.
- **Measured:** adding the lookup first made the 27-vendor benchmark 15× slower (540 s summed),
  because it went through the registry's substring search (3–14 s a call). With the exact listing
  endpoint (~0.9 s) and the index-miss rule it takes 11.7 s wall-clock on a warm cache.

## Following dependencies (`--deps`)

Many vendor servers are thin wrappers: `@playwright/mcp` is five files, and the code that launches
browsers lives in `playwright-core`. `--deps` follows the vendor's own dependencies — same scope,
the vendor's name, or `mcp` in the name; never `@modelcontextprotocol/*`; one level; at most 16;
nothing over 25 MB — and scans them in memory like the root, under `node_modules/<name>/`.

Measured on 27 vendor servers (`node scripts/vendor-benchmark.js --deps`):

- it changed the capability picture for **10 of 27** — Playwright went from "network" to process
  execution, file writes and code evaluation — and the credential count for 6;
- it costs about **60% more download and roughly twice the time**, so it is off by default, and a
  scan without it says which vendor dependencies it did not follow;
- **tools are read from the server's own package only.** With dependencies included, 49 "tools"
  appeared across five vendors and essentially none were real: SDK documentation examples, an
  example `roll_dice`, Liquid template filters, another agent's internal tools, and a different MCP
  server shipped in the same package.

## Semantic check (optional)

```
TYPESAFE_API_KEY=... npx @antharmaya/mcpscan npm:<package> --semantic
```

The static checks find what the code *can* do: run programs, write files, evaluate code, reach
external hosts. `--semantic` asks the question they cannot: **does anything the user reads before
installing actually say so?**

It extracts each tool's name and description statically, then asks one yes/no question per
capability that is really present — never speculative ones — in a single request to TypeSafe's
[Jev](https://docs.typesafe.ai/api) System One model. A low probability becomes an
`undisclosed-capability` finding, carrying the code evidence for the capability. A middle-band
answer becomes `disclosure-unclear` and goes to a human rather than either code path.

Three design rules, each there because the alternative fails quietly:

- **The model only sees what the user sees**: the server description and the tool descriptions.
  No code, no host list. Otherwise it would judge what the server does, which static analysis
  already knows, instead of what the user was told.
- **A missing or malformed answer is an error, never a zero.** Read as zero, every capability
  would look undisclosed and the scanner would manufacture findings from an API hiccup.
- **No tool descriptions found means "not judged"**, reported as such, never as clean.

The thresholds (`0.8` yes, `0.2` no) are TypeSafe's documented starting split and **have not been
calibrated on labelled MCP servers yet**. `--json` output keeps every raw probability under
`disclosure.judgments` so they can be labelled and the thresholds set from data.

The default scan never calls this, and stays deterministic and offline. The judge sits behind a
one-method interface (`ask(state, questions)`), so a fine-tuned encoder or another provider can
replace TypeSafe without the check changing.

## What it does not do

It is static. It reads source, not behaviour, so a server that assembles a hostname at runtime or
pulls code down after starting will not be caught. Dynamic sandbox tracing is the obvious next
layer and is not built. `info` findings are not accusations — a filesystem server writing files is
the product working.

## A first measurement

Population: every npm-backed server found by walking 12,000 registry entries — **469 servers across
405 publishers**. From those, a seeded random sample of 60 (`node scripts/registry-sweep.js 60`):

```
  scanned successfully                  57   across 53 publishers
  declare no environment variables      23 (40%)  19 publishers
  read a credential they never declare  13 (23%)  10 publishers
      95% CI                            14% - 35%
  run an install script                 1 (2%)
  no repository field                   11 (19%)
  errored                               3
```

Among them: four servers that read an undeclared `X402_PRIVATE_KEY`, and one reading
`PAYER_PRIVATE_KEY` — agent payment keys, requested by code, absent from the metadata a user would
read before installing.

**Corrected 2026-09-27:** first published as 14 (25%). Running the scanner on a real machine
showed that names like `OAUTH_AUTH_SERVER_URL` and `INITE_TOKEN_FILE` were being counted as
credentials because they contain "AUTH" or "TOKEN" — they point *at* a secret, they are not one.
With locator names excluded, one server drops out. Recomputed from the stored rows, same seed.

**Limits, stated up front.** The sample is random within npm-backed servers in the first 12,000
registry entries, not the whole registry, and not remote-only servers. Seed `20260926` reproduces
the exact sample. 3 of 60 failed to scan. Raw rows are in `findings.json`.

An earlier alphabetical sample gave 21 of 30, which looked far worse — but 17 of those 21 were a
single publisher's near-identical servers sitting together in the registry's own ordering. That is
why the sampling is random and why publisher counts are reported next to server counts.

## Development

```
npm test          # 83 tests, no network
node bin/mcpscan.js npm:<package>
node scripts/build-index.js          # rebuild the registry index
node scripts/collect-population.js   # cache the npm-backed population
node scripts/registry-sweep.js 60    # seeded random sample of it
```

MIT.

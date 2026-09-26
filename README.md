# mcpscan

Static trust scanner for MCP servers. It diffs **what a server's code actually does** against
**what its registry entry declares**, and reports the difference with file-and-line evidence.

It never installs, extracts or executes what it inspects. The npm tarball is parsed in memory, so
install scripts never run and a malicious path never touches your filesystem.

```
npx @antharmaya/mcpscan npm:@modelcontextprotocol/server-filesystem
npx @antharmaya/mcpscan io.github.owner/some-server --json
```

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
| `network-egress` | info | Every external host reachable from the source, minus hosts the entry declares. |
| `capability` | info | Process execution, dynamic evaluation, filesystem writes, raw sockets. |

Exit code is 1 when anything at or above `--fail-on` (default `high`) is found, so it fits in CI.

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
  read a credential they never declare  14 (25%)  11 publishers
      95% CI                            15% - 37%
  run an install script                 1 (2%)
  no repository field                   11 (19%)
  errored                               3
```

Among them: four servers that read an undeclared `X402_PRIVATE_KEY`, and one reading
`PAYER_PRIVATE_KEY` — agent payment keys, requested by code, absent from the metadata a user would
read before installing.

**Limits, stated up front.** The sample is random within npm-backed servers in the first 12,000
registry entries, not the whole registry, and not remote-only servers. Seed `20260926` reproduces
the exact sample. 3 of 60 failed to scan. Raw rows are in `findings.json`.

An earlier alphabetical sample gave 21 of 30, which looked far worse — but 17 of those 21 were a
single publisher's near-identical servers sitting together in the registry's own ordering. That is
why the sampling is random and why publisher counts are reported next to server counts.

## Development

```
npm test          # 15 tests, no network
node bin/mcpscan.js npm:<package>
node scripts/collect-population.js   # cache the npm-backed population
node scripts/registry-sweep.js 60    # seeded random sample of it
```

MIT.

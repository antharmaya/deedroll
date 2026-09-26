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

Scanning the first 30 npm-backed servers in the registry, 2026-09-26 (`node scripts/registry-sweep.js 30`):

```
  servers scanned                       30
  declare no environment variables      25
  read a credential they never declare  21
  errored                               0
```

**Read that carefully.** The 21 servers come from only **5 distinct publishers**, and 17 of them are
one publisher shipping near-identical servers that each read an undeclared `X402_PRIVATE_KEY`. The
sample is the registry's own alphabetical order, not a random draw. So this is a real finding about
five publishers, not yet a population estimate. A random sample across the registry is the next step
before any number goes in a post.

Raw output is in `findings.json`.

## Development

```
npm test          # 13 tests, no network
node bin/mcpscan.js npm:<package>
node scripts/registry-sweep.js 30
```

MIT.

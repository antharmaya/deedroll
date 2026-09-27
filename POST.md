# More than one in five MCP servers read credentials their registry entry never mentions

*Draft launch post. Publish from the GitHub repo, not from antharmaya.com.*

---

The official MCP registry schema has a field for this. Each package entry can list its
`environmentVariables`, and each one can be marked `isSecret` and `isRequired`. It is exactly the
thing you would want to read before you install a server and hand it your shell.

Most publishers leave it empty. Nobody checks, because [the official registry does not scan
servers](https://dev.to/sam_curatedmcp/five-hard-problems-in-the-mcp-ecosystem-3651), and [9 of 11
major MCP directories accepted typosquatted payloads](https://nimblebrain.ai/blog/state-of-mcp-security-2026/)
with no automated review at all.

So I measured it.

## What I did

I walked 12,000 registry entries and kept every server shipping an npm package: **469 servers from
405 publishers**. I took a seeded random sample of 60, downloaded each package, and compared the
environment variables the code actually reads against the ones the registry entry declares.

```
  scanned successfully                  57   across 53 publishers
  declare no environment variables      23 (40%)  19 publishers
  read a credential they never declare  13 (23%)  10 publishers
      95% CI                            14% – 35%
  run an install script                 1 (2%)
  no repository field                   11 (19%)
```

Among the 13: four servers reading an undeclared `X402_PRIVATE_KEY`, and one reading
`PAYER_PRIVATE_KEY`. Those are agent payment keys — asked for by the code, absent from the metadata
a user reads before installing.

## What this is and isn't

It is a **metadata gap**, not proof of malice. Every one of these servers probably documents its
variables in a README. The problem is that the registry is what tooling reads, what a catalogue
renders, and increasingly what an agent consults before installing something on your behalf. A
README is for humans who are already paying attention.

It also means a user has no machine-readable way to answer "what is this about to ask me for?"
before the thing is running.

## The fix, for publishers

Fill in `environmentVariables` in your `server.json`, and mark the secrets `isSecret: true`. It
costs one block of JSON and it is the difference between a user seeing what you need up front and
finding out at runtime.

## The tool

```
npx @antharmaya/mcpscan npm:@modelcontextprotocol/server-filesystem
npx @antharmaya/mcpscan io.github.owner/their-server --json
```

It diffs declared against actual and prints file-and-line evidence for everything it claims. It
also checks install scripts, provenance, typosquatting, network egress and capabilities. Exit code
is non-zero on high-severity findings, so it drops into CI.

**It never installs, extracts or executes what it inspects.** The tarball is parsed in memory. A
scanner that had to run `npm install` first would have already executed three lifecycle hooks
belonging to the thing you asked it to check.

## How this differs from Snyk Agent Scan and Cisco's mcp-scanner

Both are good and both exist; use them. They answer a different question at a different moment.

[Snyk Agent Scan](https://github.com/snyk/agent-scan) (formerly Invariant's `mcp-scan`) starts your
configured servers to read their tools, sends tool names and descriptions to Snyk for analysis, and
needs a Snyk token. It is strongest at tool poisoning and prompt injection.
[Cisco's mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) connects to live servers or
scans PyPI source in a Docker sandbox, with YARA rules and an LLM that checks descriptions against
code.

mcpscan is the check **before** you install: it never runs the server, needs no account, and no
scan result, config, key or tool description ever leaves your machine — it only looks up public
package names and versions (on npm, the MCP registry and, unless you pass `--no-osv`, OSV.dev). It
reads npm packages (where most MCP servers ship) and runs in a browser. It is the
only one of the three that compares a server's **registry metadata** against its code — which is
where the number above comes from. It does not detect prompt injection; they do.

## One thing the registry cannot tell you

The official registry's search matches listing names only, so it cannot answer "which listing
ships the npm package `pretrip-mcp`?" (the answer is `agency.kesey/pretrip`). mcpscan ships an
index built by walking every current listing — 36,586 of them, pointing at 9,744 npm packages — and
267 of those packages are claimed by more than one listing.

## Reproducing this

```
git clone <repo> && cd mcpscan
node scripts/collect-population.js     # walks the registry, caches npm-backed servers
node scripts/registry-sweep.js 60      # seeded random sample, seed 20260926
```

Seed `20260926` reproduces the exact sample in this post. Raw rows are in `findings.json`.

## Limits

Static analysis reads source, not behaviour: a server that assembles a hostname at runtime or
fetches code after starting is not caught. The sample covers npm-backed servers in the first 12,000
registry entries, not remote-only servers and not the whole registry. Three of the sixty failed to
scan and are excluded.

One more, because it changed the headline: my first sample was the registry's own alphabetical
order and gave 21 of 30 — until I noticed 17 of those 21 were a single publisher's near-identical
servers, which sit together in that ordering. Random sampling and publisher-level counts fixed it.
The worse number was the wrong one.

And a second correction, found by pointing the scanner at a real machine: it first counted names
like `OAUTH_AUTH_SERVER_URL` as credentials. They point at a secret; they are not one. Excluding
them moved the headline from 14 (25%) to 13 (23%).

# A quarter of MCP servers ask for credentials their registry entry never mentions

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
  read a credential they never declare  14 (25%)  11 publishers
      95% CI                            15% – 37%
  run an install script                 1 (2%)
  no repository field                   11 (19%)
```

Among the 14: four servers reading an undeclared `X402_PRIVATE_KEY`, and one reading
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

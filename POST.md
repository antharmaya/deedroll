# One in five MCP servers leaves a credential out of its registry listing. Most explain it in the README

*Draft launch post. Publish from the GitHub repo, not from antharmaya.com.*

---

The official MCP registry schema has a field for this. Each package entry can list its
`environmentVariables`, and each one can be marked `isSecret` and `isRequired`. It is exactly the
thing you would want to read before you install a server and hand it your shell.

Many publishers leave it empty. Nobody checks, because [the official registry does not scan
servers](https://dev.to/sam_curatedmcp/five-hard-problems-in-the-mcp-ecosystem-3651), and [9 of 11
major MCP directories accepted typosquatted payloads](https://nimblebrain.ai/blog/state-of-mcp-security-2026/)
with no automated review at all.

So I measured it, and then measured it again, more carefully, after a maintainer showed me
where my first count was wrong.

## Try it now

Free, no account: **https://deedroll.antharmaya.com**. Source:
**https://github.com/antharmaya/deedroll**. It runs the same engine as the
command line, in your browser, and also does two things a package scan can't:

- **Checks a hosted server's sign-in**, when it needs one, against the official spec
  (does it publish how to sign in, does it use PKCE, does its token even name the right
  server) — from public metadata only, no account created.
- **Checks this computer.** Since the page is itself a website, it can show you exactly
  what any website could reach on your machine: it lists the tools of any MCP server on
  the usual ports that doesn't reject requests from other sites, live, in the page.

There's also now a **daily, hash-chained public record** of the whole registry —
what every listing declares, and what a rotating slice of hosted servers' tools actually
say — because a hosted server can rewrite its tools after you approved them, and the
registry itself states it keeps no durability guarantees. Each day's file carries the
hash of the day before, so the history can be checked, not just trusted; the page has a
"verify it in your browser" button that does exactly that.

## What I did

I walked 12,000 registry entries and kept every server shipping an npm package: **469 servers from
405 publishers**. I took a seeded random sample of 60, downloaded each package, and compared the
environment variables the code actually reads against the ones the registry entry declares, and
against the package's own README.

```
  scanned successfully                     57   across 53 publishers
  declare no environment variables         23 (40%)  19 publishers
  credential missing from the listing      12 (21%)
    ...explained in the README             8 (14%)
    ...mentioned nowhere                   4 (7%)    95% CI 3% – 17%
  run an install script                    1 (2%)
  no repository field                      11 (19%)
```

Among the 8 that explain it in the README: four servers whose README shows `X402_PRIVATE_KEY` in
a config example, and one whose README explains `PAYER_PRIVATE_KEY` is optional and should be a
throwaway wallet. Those are agent payment keys. A careful reader of the README knows; the listing,
which is what catalogs and agents read, does not say.

## What this is and isn't

It is a **metadata gap**, not proof of malice: two-thirds of these servers do document the
variable, in their README. The problem is that the registry is what tooling reads, what a catalogue
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
npx @antharmaya/deedroll npm:@modelcontextprotocol/server-filesystem
npx @antharmaya/deedroll pypi:mcp-server-fetch
npx @antharmaya/deedroll io.github.owner/their-server --json
npx @antharmaya/deedroll --installed          # every server your agents already trust
npx @antharmaya/deedroll --local              # MCP servers on this machine or your network
```

It diffs declared against actual and prints file-and-line evidence for everything it claims. It
also checks install scripts, provenance, typosquatting, network egress, capabilities, known
vulnerabilities (OSV.dev), and whether two servers you already trust offer a tool with the same
name (a client resolves tools by name, so either could silently answer a call meant for the
other). Exit code is non-zero on high-severity findings, so it drops into CI; `--sarif` writes
SARIF for GitHub code scanning and other dashboards.

**It never installs, extracts or executes what it inspects.** The tarball is parsed in memory. A
scanner that had to run `npm install` first would have already executed three lifecycle hooks
belonging to the thing you asked it to check.

## How this differs from Snyk Agent Scan and Cisco's mcp-scanner

Both are good and both exist; use them. They answer a different question at a different moment.

[Snyk Agent Scan](https://github.com/snyk/agent-scan) (formerly Invariant's `mcp-scan`) starts your
configured servers to read their tools, sends tool names and descriptions to Snyk for analysis, and
needs a Snyk token. It is strongest at tool poisoning and prompt injection.
[Cisco's mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) connects to live servers,
reads configs, and reads npm and PyPI packages without executing them, with YARA rules, optional
LLM and Cisco API analyzers (which need keys), and dataflow analysis that checks docstrings against
code in ten languages.

deedroll is the check **before** you install: it never runs the server, needs no account, and no
scan result, config, key or tool description ever leaves your machine — it only looks up public
package names and versions (on npm or PyPI, the MCP registry and, unless you pass `--no-osv`,
OSV.dev). It reads npm and PyPI packages, probes hosted servers on both protocol generations, writes
SARIF, and runs in a browser. Of the three it is the one that compares a server's **registry
metadata** against its code, which is where the number above comes from. It flags descriptions
that instruct the model by pattern; judging prompt injection with a model is where they are
stronger.

(The field is bigger than two tools: at least half a dozen others exist — web scanners you paste a
URL into, AI-classifier repo scanners, config auditors, trust-score directories, and runtime
"gateway" products that watch an add-on while it runs rather than before you install it. Several
send code or attack traffic to their own servers to do it; none of the ones I checked compare a
listing's declared metadata against the code the way this does.)

## One thing the registry cannot tell you

The official registry's search matches listing names only, so it cannot answer "which listing
ships the npm package `pretrip-mcp`?" (the answer is `agency.kesey/pretrip`). deedroll ships an
index built by walking every current listing: 36,906 of them on 2026-09-28, pointing at 9,796 npm
and 3,868 PyPI packages (the registry grew to 37,176 listings by 2026-09-29, per the daily record
above). On 2026-09-27, 267 npm packages were claimed by more than one listing.

## Reproducing this

```
git clone https://github.com/antharmaya/deedroll && cd deedroll
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

A third, found while re-checking this exact sample before contacting the publishers named in
it — never repeat a claim without re-deriving it first: two more name-shaped false positives
(`_PER_MINUTE`, `_CACHE_DURATION` — quantities, not secrets, and neither changed whether the row
they were on was flagged, since both belonged to servers already flagged for a different, real
variable), and two evidence-quality bugs in the scanner itself. It was citing a package's own
comment as proof of a code read when the comment only *mentioned* `process.env.X` in prose, and
citing a package's own test file stubbing a fake value to test its config loader as if the shipped
server read that value from a real user. Both are fixed. One publisher's finding — a doc comment
that was the *only* mention of a credential name in the whole package — turned out to have no real
code behind it once that comment stopped counting as evidence, and dropped out. That moved the
headline from 13 (23%) to 12 (21%) — still true, on this data, that more than one in five do it.

A fourth, the largest, found because a maintainer replied. Until 2026-10-01 the scanner never read
a package's README at all: its readers kept code files only. It reported a "hardcoded fallback
key" in one server as an undeclared credential; the maintainer pointed out it is their public
free-tier key, documented in the README. They were right, and so were seven others in the
sample. The scanner now reads the README, keeps it apart from the code (so a README's examples
are never cited as code), and reports a documented credential as a listing gap at low severity.
Every one of the 8 was checked by hand. The number that means "mentioned nowhere" went from 12 to
4. The headline above used to read "more than one in five read credentials their registry entry
never mentions". The registry half of that was true; the implication that nobody was told was not.

# mcpscan against the NSA's MCP security guidance

*Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*,
NSA Cybersecurity Information Sheet U/OO/6030316-26, May 2026, with Carnegie Mellon SEI. The PDF
is in [references/](references/nsa-csi-mcp-security-2026-06.pdf). This maps what it names to what
mcpscan does; "no" means mcpscan does not do it, not that it cannot matter.

## The risks it describes

| NSA concern | mcpscan | How |
|---|---|---|
| **Poor approval workflows**: a trusted server's capabilities change without new approval; "the malicious MCP server advertised a benign instruction at the time of installation and switched to a malicious instruction after the server's second usage" (WhatsApp) | **Yes** | Hosted tools are pinned, in the CLI and in the browser; a changed description is **high**, with old and new text, and is never accepted silently. The daily registry history records tool lists over time. |
| Poisoned tool metadata, hidden instructions ("poisoning output", tool poisoning) | **Partly** | `instruction-like-text` flags descriptions that instruct the model (0 false positives on 5,811 real descriptions). It does not judge tool *outputs*, which only exist at runtime. |
| Token and session security (OAuth, bearer tokens, lifecycle) | **Partly** | For servers that require sign-in: resource metadata present, token audience, issuer match, PKCE, deprecated registration. It does not test token lifetime or revocation: that needs an account. |
| Misconfigurations and poor implementation | **Partly** | Static reading of the code: undeclared credentials, install-time code, capabilities, hosts contacted. Not dataflow. |
| Tool invocation path confusion (naming collisions) | **Partly** | `typosquat` for npm names close to official ones; `multiple-listings` when several listings claim one package. Tool-name collisions across servers are not checked. |
| Access control, RBAC, missing audit logs, DoS | **No** | Properties of a deployment at runtime, not of a package or a listing. |
| Remote code execution in toolchains (CVE-2025-49596 in MCP Inspector) | **Yes, for known ones** | `known-vulnerability` via OSV.dev for the exact version. |

## Its recommendations

| NSA recommendation | mcpscan | How |
|---|---|---|
| **Choose supported MCP projects**: "many popular servers are no longer actively maintained"; apply "the most stringent review profile" | **Yes** | `archived-upstream` (reference servers the MCP project archived, which PyPI does not mark), `deprecated`, `listing-status`, provenance and publisher checks. The scan is the review, before install. |
| Design for boundaries; **use a filtering outgoing proxy "with specific resource URLs"** | **Yes, as input** | `--egress` prints the hosts a server's code names, as a starting allowlist. Static, and labelled so. |
| Validate parameters against schemas | **No** | A runtime property. Tool input schemas are fingerprinted, so a changed schema is reported (`tool-schema-changed`). |
| Constrain and sandbox tool execution | **Informs it** | `capability` says which servers run programs, evaluate code or write files, which decides how tightly to sandbox them. |
| Sign and verify MCP messages | **No** | A protocol change. mcpscan checks signed *build* provenance (npm, PyPI) instead. |
| Filter and monitor output pipelines | **No** | Runtime. |
| Instrument for logging and detection | **Feeds it** | `--json` (schema v1) and `--sarif` go straight into security tooling. |
| **Track and patch vulnerabilities**; "maintain a clear inventory of all deployed MCP agents and tools, along with versioning" | **Yes** | `--installed` is the inventory, across six agents, with versions and findings; OSV lookups on each. |
| **Scan for open or vulnerable MCP servers**: unauthenticated servers, outdated versions; "periodic scans and differential reports" | **Partly** | `unauthenticated` for any URL you give it; the daily snapshot and its diff are the periodic differential report for the public registry. It does not sweep your own network for servers yet. |

## What this suggests building next

1. **Local network discovery** (`mcpscan --local`): find MCP servers listening on this machine or
   subnet, and check each for sign-in, `Origin` validation (the spec requires it against DNS
   rebinding) and binding to `0.0.0.0`. The NSA lists this as baseline hygiene.
2. **Tool-name collisions** across the servers an agent has configured (`--installed`), the
   "naming collisions" class it describes.

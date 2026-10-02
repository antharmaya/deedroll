# mcpscan redesign brief (2026-10-01)

**What this is for:** prototypes from Claude Design and Google Stitch, built on the softer story.
Harsha picks one and Claude implements it in `web/`. `DESIGN.md` stays the spec for anything this
brief doesn't change.

## The story, in one breath

> **mcpscan checks an MCP server's label against its code, before you install it.**
> It reads what a server says it needs beside what its code actually reads, runs and contacts,
> without running anything. Where the two differ, it says so plainly, and says when the README
> already explains it. A difference is a question for the publisher, not a verdict on the server.

**Tone:** a careful reviewer who assumes good faith, not an alarm.

**Who it's for:**
- the person deciding whether to let an agent use someone else's server;
- the publisher who wants their listing to be complete.

**Words to avoid:** threat, vulnerable, malicious, leak, risk score, "critical".

**Words to use:** reads, runs, contacts, declares, explains, worth knowing, question for the
publisher.

## What must survive the redesign (non-negotiable)

1. **Nothing faked.** Every animated moment replays a real result, and progress text maps to real
   engine events.
2. **Every finding shows file:line evidence**, with the code line and the variable highlighted.
3. **The two ledgers, side by side:** "What it tells you" and "What the code does". The core idea
   is the label beside the code.
4. **Live vs replay is always visible.** A replayed scan is labelled with its date.
5. **No third-party anything:** fonts are self-hosted, with no CDN, analytics or trackers. A strict
   CSP, and one inline script at most.
6. **Long lists scroll or expand in place.** Never cut a list off with a dead "and N more".
7. **Light and dark themes** both designed, readable at 360 px wide, keyboard-reachable.

## What changes

- **Severity becomes three plain groups:** *Ask before installing* · *Worth knowing* · *Context*.
  No high/medium/low labels in the UI; the CLI and SARIF keep their levels. Shape still encodes
  the group, alongside colour.
- **README-explained credentials get their own look:** a ringed mark, not a filled one, with the
  sentence "its README explains it, its listing doesn't."
- **A publisher path:** "Is this your server?" leads to what to add to `server.json`, with the
  exact JSON to copy. This makes the tool helpful to the people it scans.
- **The registry section** shows three states: mentioned nowhere, README only, declared.
- **The scan stage reads as an instrument;** the explanatory sections read as a calm document.
  The two must never look alike.

## The real data states to design (use these, not lorem ipsum)

| State | Example | What it shows |
|---|---|---|
| Idle | page load | a dated replay of a real scan (`@upstash/context7-mcp` 4.1.1, 29 Sept 2026) |
| Scanning | any package | real progress lines: fetching, unpacking in memory, checking N files |
| Short result | `pretrip-mcp` 1.0.1 | 2 files: 1 credential mentioned nowhere, 1 setting, 1 host |
| Long result | `@vidofy/mcp` 0.1.2 | 36 files, scrolling; 4 facts and 3 findings |
| Hosted, sign-in | `https://mcp.higgsfield.ai/mcp` | no files; sign-in checks (PKCE yes, issuer yes); 0 findings |
| Hosted, open | `mcp.deepwiki.com` | its tool list, read-only/destructive tags |
| Relay question | a server that blocks browsers | a consent panel: what the relay sees and keeps (nothing) |
| Not found | a typo | a plain sentence and the fix |
| Your setup | dropped `.claude.json` | rows per server: agent, launch, findings, "Scan it" |
| This computer | port check | "any website can reach it" vs "keeps websites out" |
| Registry record | daily chain | days recorded, collapsed change lists, "Verify in your browser" |

## Brand

- **Ink blue:** `oklch(0.47 0.16 258)`, or `oklch(0.72 0.135 258)` on dark.
- **Paper:** warm `oklch(0.977 0.005 80)` light, `oklch(0.165 0.008 60)` dark.
- **Fonts:** Bricolage Grotesque for display, Hanken Grotesk for body, JetBrains Mono for code
  only.
- **Avoid these generated-looking defaults:** a purple gradient hero; neon on black; cream with a
  terracotta accent; emoji section markers; Inter; everything centred.

---

## Prompt for Claude Design (paste as is)

```
Design the web app for "mcpscan", a free tool that checks an MCP server's label against its code
before you install it. It reads what a server's registry listing declares beside what its code
actually reads, runs and contacts, without running anything, and says plainly where they differ.
A difference is a question for the publisher, not a verdict. Tone: a careful reviewer who assumes
good faith. Never use the words threat, vulnerable, malicious or critical.

Build one responsive page (desktop 1440 and phone 390, light and dark) with these sections:
1. Hero: "Read the label, then read the code." One input ("Server URL, package or registry
   name"), a Scan button, example chips, and "Nothing is installed or run, and no tool is ever
   called."
2. The scan instrument: the package's files on the left (scrollable list, each file's line count,
   a mark on files with findings); two ledgers on the right: "What it tells you" (listing name,
   declared settings, provenance) and "What the code does" (credentials read, other settings,
   hosts contacted, capabilities). A status line says "Live" or "Replay, 29 Sept 2026".
3. Findings in three groups: Ask before installing / Worth knowing / Context. Each row is one
   plain sentence plus file:line; expanding it shows the code line with the variable
   highlighted, then "Why it matters" and "What the publisher can do".
4. "Is this your server?": the exact server.json environmentVariables JSON to add, with a copy
   button.
5. A dark ink-blue band: "12 of 57 MCP servers read a credential that neither their listing nor
   their README mentions" with a grid of 57 dots in three states (filled = mentioned nowhere,
   ringed = README only, empty = declared).
6. "The registry, day by day": four stats and collapsible change lists.
7. "How a scan works", in three steps, and a calm note on what a result is and isn't.

Use this real data: package @vidofy/mcp 0.1.2, 36 files (dist/tools/account.js 130 lines,
dist/oauth/clients.js 621, dist/index.js 714, dist/http.js 970 ...); it tells you: listed as
ai.vidofy/mcp, declares 1 setting VIDOFY_TOKEN, no provenance, published 11 days ago; the code
reads 3 other settings (VIDOFY_MCP_PUBLIC_URL, VIDOFY_MCP_PORT, VIDOFY_ENV_FILE), contacts
cdn.vidofy.ai, can run other programs.

Visual: ink blue oklch(0.47 0.16 258) on warm paper, a precision instrument rather than a hacker
terminal. Bricolage Grotesque for display, Hanken Grotesk for body, JetBrains Mono only for code
and paths. Severity is shape and colour together: diamond, triangle, ring, dot. No gradients
behind text, no emoji, no centred-everything layout, no purple. Motion only where data arrives:
a scan line passing down the file list as files are read.
```

## Prompt for Google Stitch (paste as is)

```
App: mcpscan, a calm, trustworthy web tool that checks an MCP server's label against its code
before installing. Screens to generate, each at desktop and mobile, light and dark:

1. Home + scan instrument (idle replay state). Hero headline "Read the label, then read the
   code.", one input with a Scan button, example chips. Beside it, a card with a scrollable
   monospace file list (paths and line counts) and two ledgers: "What it tells you" and "What
   the code does".
2. Result, long package: 36 files scrolling inside the card, findings below in three groups (Ask
   before installing / Worth knowing / Context), one row expanded showing a code line with a
   highlighted variable plus "Why it matters" and "What the publisher can do".
3. Result, hosted server with sign-in: no files; the list shows sign-in checks with yes/no
   values (PKCE yes, issuer yes, dynamic registration yes) and a green-free neutral "0 findings".
4. "Is this your server?" panel with copyable JSON.
5. Registry band on dark ink blue: big figure "12 of 57" and a 57-dot grid in three states.
6. "Check your own setup": a drop zone for config files and a list of servers with agent, launch
   command and a "Scan it" chip.

Style: ink blue accent oklch(0.47 0.16 258), warm off-white paper, generous whitespace,
Bricolage Grotesque headings, Hanken Grotesk body, JetBrains Mono for code. Severity shown by
shape: filled diamond, triangle, ring, small dot. Tone of copy: plain, kind, specific. Avoid:
alarm red banners, scores out of 100, purple gradients, neon, emoji icons.
```

## What to bring back

- **From Stitch:** the HTML/CSS export, or the screen images.
- **From Claude Design:** the project link or an HTML export.

Either is enough. Claude rebuilds it inside the existing engine, CSP and data flow; the
prototype sets the visual direction, not the code. Images Claude needs supplied: none so far.
The page draws everything with type, CSS and inline SVG. If the chosen design includes
illustrations, export them as SVG.


---

# Round 2 (2026-10-02): a page for every server

Round 1 is live at https://mcpscan.antharmaya.com (commit b5b224d).

**Kept from round 1:**
- From Claude Design: the structure, the grouped ledgers, why/fix side by side, the
  `server.json` diff.
- From Stitch: the live count in the header.

**Rejected,** and to be avoided in round 2:
- claims of AST or syntax-tree analysis (mcpscan is pattern-based static reading);
- a `.mcpscan.json` manifest file, attestation, DNS claiming, "VERIFIED"/"CONFIRMED" badges;
- invented descriptions or data presented as real;
- jargon copy ("ledger memorandum", "AST-diagnostic");
- regrouping findings above the engine's severity.

**What round 2 designs:** the ledger is live. Every MCP server in the official registry (38,247)
has a git-like history and scan facts at `/api/servers/<name>`. Design the pages that show them.

## Prompt for Claude Design (paste into the same project; it can read the repo)

```
Design two new pages for mcpscan in the same system as mcpscan.dc.html (same tokens, type,
glyph-plus-shape severity, light and dark, desktop 1440 and phone 390).

1. /servers/<registry name>: one MCP server's record. It must answer, in this order:
   - What is it? Name, description, what it ships (npm/PyPI package or hosted endpoint),
     version, status, repository link.
   - What does its label say against what its code does? A reconciliation list, one row per
     setting the code reads: the name, then a state chip: "declared" (in its listing),
     "README only" (explained in the README, not the listing), "mentioned nowhere". Then
     rows for hosts contacted, capabilities (can run programs, write files), install scripts,
     provenance, flags (a tool description that instructs the AI, a release that stopped
     publishing with provenance). Each row shows the file:line it comes from.
   - What changed, and when? The log as a vertical history, like git log: a dated entry per
     event (seen, release with version from -> to, changed what it declares, moved its
     endpoint, a probe found new tools, a scan found a new credential, gone, back). Each
     entry is one plain sentence plus small diff chips (+ added, - removed). This is the heart
     of the page: make change legible at a glance, e.g. a compact strip of dots per day above
     the list showing which days something changed.
   - A verify line: "Recorded daily since 28 Sept 2026, each day chained to the one before."
2. /servers?q=: search results, 25 per page. Each result: name, one-line description, what
   it ships, last change date, and small counts (credentials mentioned nowhere, flags).
   Empty and no-result states.

States to design: a package server with many facts; a hosted server with a probe; a server
that disappeared ("gone"); a listing that points at a package its registry does not have
("missing"); a scan that failed. Use these REAL records (do not invent other data; if you need
more rows, mark them clearly as sample):

{
 "package": {
  "name": "io.github.goklab/guardvibe",
  "firstSeen": "2026-09-28",
  "lastSeen": "2026-10-02",
  "gone": null,
  "latest": {
   "name": "io.github.goklab/guardvibe",
   "version": "3.46.0",
   "description": "Deterministic security layer your AI can't be. 530 rules, 39 tools, CLI + doctor + host audit.",
   "repository": "https://github.com/goklab/guardvibe",
   "status": "active",
   "publishedAt": "2026-10-01T06:53:44.759296Z",
   "packages": [
    {
     "type": "npm",
     "id": "guardvibe",
     "version": "3.46.0",
     "transport": "stdio",
     "env": []
    }
   ],
   "remotes": []
  },
  "signals": {
   "npm:guardvibe": {
    "version": "3.46.0",
    "scanned": "2026-10-02",
    "undeclared": [
     {
      "n": "CRON_SECRET",
      "at": "build/data/rules/advanced-security.js:392"
     },
     {
      "n": "GEMINI_API_KEY",
      "at": "build/data/rules/ai-security.js:268"
     },
     {
      "n": "MCP_TOKEN",
      "at": "build/data/rules/ai-tool-runtime.js:168"
     },
     {
      "n": "NEXT_PUBLIC_SUPABASE_ANON_KEY",
      "at": "build/data/rules/auth.js:161"
     }
    ],
    "readmeOnly": [
     "OPENAI_API_KEY",
     "API_KEY",
     "ANTHROPIC_API_KEY"
    ],
    "settings": [
     "NODE_TLS_REJECT_UNAUTHORIZED",
     "PROXY_USER",
     "PROXY_PASS",
     "NEXT_PUBLIC_SUPABASE_URL"
    ],
    "hosts": [
     "trusted.example.com",
     "cdn.example.com",
     "api.anthropic.com",
     "proxy.corp.internal"
    ],
    "caps": [
     "process execution",
     "process execution (python)",
     "dynamic code evaluation",
     "filesystem writes or deletes",
     "raw network sockets"
    ],
    "install": [],
    "vulns": 0,
    "provenance": true,
    "flags": [
     "instruction-like-text"
    ],
    "files": 213
   }
  },
  "probes": {},
  "log": [
   {
    "date": "2026-09-28",
    "kind": "seen",
    "version": "3.42.0"
   },
   {
    "date": "2026-09-29",
    "kind": "changed",
    "changes": [
     {
      "field": "version",
      "from": "3.42.0",
      "to": "3.43.0"
     },
     {
      "field": "description",
      "from": "Deterministic security layer your AI can't be. 510 rules, 39 tools, CLI + doctor + host audit.",
      "to": "Deterministic security layer your AI can't be. 515 rules, 39 tools, CLI + doctor + host audit."
     }
    ]
   },
   {
    "date": "2026-09-30",
    "kind": "changed",
    "changes": [
     {
      "field": "version",
      "from": "3.43.0",
      "to": "3.44.0"
     },
     {
      "field": "description",
      "from": "Deterministic security layer your AI can't be. 515 rules, 39 tools, CLI + doctor + host audit.",
      "to": "Deterministic security layer your AI can't be. 520 rules, 39 tools, CLI + doctor + host audit."
     }
    ]
   },
   {
    "date": "2026-10-01",
    "kind": "changed",
    "changes": [
     {
      "field": "version",
      "from": "3.44.0",
      "to": "3.45.0"
     },
     {
      "field": "description",
      "from": "Deterministic security layer your AI can't be. 520 rules, 39 tools, CLI + doctor + host audit.",
      "to": "Deterministic security layer your AI can't be. 525 rules, 39 tools, CLI + doctor + host audit."
     }
    ]
   },
   {
    "date": "2026-10-01",
    "kind": "scanned",
    "package": "npm:guardvibe",
    "version": "3.45.0",
    "first": true,
    "undeclared": [
     "CRON_SECRET",
     "GEMINI_API_KEY",
     "MCP_TOKEN",
     "NEXT_PUBLIC_SUPABASE_ANON_KEY",
     "SUPABASE_SERVICE_ROLE_KEY",
     "SECRET",
     "DB_PASSWORD",
     "AWS_ACCESS_KEY_ID",
     "GITHUB_TOKEN",
     "MY_SECRET",
     "JWT_SECRET",
     "SECRET_KEY",
     "FIREBASE_SERVICE_ACCOUNT_KEY",
     "NEXT_PUBLIC_FIREBASE_API_KEY",
     "WEBHOOK_SECRET",
     "CSRF_SECRET",
     "SESSION_SECRET",
     "DJANGO_SECRET_KEY",
     "API_TOKEN",
     "SUPABASE_SERVICE_KEY",
     "TURSO_AUTH_TOKEN",
     "API_SECRET",
     "TWILIO_AUTH_TOKEN",
     "STRIPE_SECRET_KEY",
     "STRIPE_WEBHOOK_SECRET",
     "LEMONSQUEEZY_API_KEY",
     "LEMON_SQUEEZY_WEBHOOK_SECRET",
     "POLAR_ACCESS_TOKEN",
     "RESEND_API_KEY",
     "UPSTASH_REDIS_REST_TOKEN",
     "PINECONE_API_KEY",
     "CLOUDFLARE_API_TOKEN"
    ],
    "readmeOnly": [
     "OPENAI_API_KEY",
     "API_KEY",
     "ANTHROPIC_API_KEY"
    ],
    "hosts": 34,
    "caps": [
     "process execution",
     "process execution (python)",
     "dynamic code evaluation",
     "filesystem writes or deletes",
     "raw network sockets"
    ],
    "install": 0,
    "vulns": 0,
    "flags": [
     "instruction-like-text"
    ]
   },
   {
    "date": "2026-10-02",
    "kind": "changed",
    "changes": [
     {
      "field": "version",
      "from": "3.45.0",
      "to": "3.46.0"
     },
     {
      "field": "description",
      "from": "Deterministic security layer your AI can't be. 525 rules, 39 tools, CLI + doctor + host audit.",
      "to": "Deterministic security layer your AI can't be. 530 rules, 39 tools, CLI + doctor + host audit."
     }
    ]
   }
  ]
 },
 "hosted": {
  "name": "com.beeimg/mcp",
  "firstSeen": "2026-09-28",
  "lastSeen": "2026-10-02",
  "gone": null,
  "latest": {
   "name": "com.beeimg/mcp",
   "version": "1.2.0",
   "description": "Upload, delete, and manage images on BeeIMG with albums, folders, privacy controls, and API access.",
   "repository": null,
   "status": "active",
   "publishedAt": "2026-09-20T15:15:37.028687Z",
   "packages": [],
   "remotes": [
    {
     "type": "streamable-http",
     "url": "https://beeimg.com/mcp",
     "headers": []
    }
   ]
  },
  "signals": {},
  "probes": {
   "https://beeimg.com/mcp": {
    "date": "2026-10-02",
    "probed": true,
    "reason": null,
    "tools": 8
   }
  },
  "log": [
   {
    "date": "2026-09-28",
    "kind": "seen",
    "version": "1.2.0"
   },
   {
    "date": "2026-10-02",
    "kind": "probe",
    "url": "https://beeimg.com/mcp",
    "probed": true,
    "reason": null,
    "tools": 8,
    "first": true
   }
  ]
 },
 "gone": {
  "name": "chat.vitalink/directory",
  "firstSeen": "2026-10-01",
  "lastSeen": "2026-10-01",
  "gone": "2026-10-02",
  "latest": {
   "name": "chat.vitalink/directory",
   "version": "0.1.0",
   "description": "Find health professionals in 15 countries: public listings, verified credentials. No medical advice.",
   "repository": null,
   "status": "active",
   "publishedAt": "2026-09-30T23:12:07.304528Z",
   "packages": [],
   "remotes": [
    {
     "type": "streamable-http",
     "url": "https://mcp.vitalink.chat/mcp",
     "headers": []
    }
   ]
  },
  "signals": {},
  "probes": {},
  "log": [
   {
    "date": "2026-10-01",
    "kind": "seen",
    "version": "0.1.0"
   },
   {
    "date": "2026-10-02",
    "kind": "gone"
   }
  ]
 }
}

Copy rules: plain verbs, sentence case, no em dashes. Facts, never verdicts. A difference is
"a question for the publisher". Never: threat, vulnerable, malicious, critical, verified,
safe. "Seen" means seen by this record (it started 28 Sept 2026), not first published.
Motion only where data arrives: history entries settle in once on load, the day strip fills
left to right. Respect reduced motion.
```

## Prompt for Google Stitch (round 2)

```
App: mcpscan, a calm reference record of every MCP server (like a git log for each one).
Generate: (1) a server record page, (2) search results, each desktop and mobile, light and
dark, in this style: warm off-white paper, ink blue accent oklch(0.47 0.16 258), Bricolage
Grotesque headings, Hanken Grotesk body, JetBrains Mono for names and paths; severity by
shape (filled diamond, triangle, ring, small dot) plus colour.

Server page sections: header (name, description, ships npm package "guardvibe" 3.46.0,
repository link); "Label against code": rows of setting names each with a chip DECLARED /
README ONLY / MENTIONED NOWHERE and a file:line; hosts contacted; capabilities; "History":
vertical dated list (seen 28 Sept; released 3.45.0 -> 3.46.0 on 1 Oct; scan found 2 new
settings on 2 Oct) with +/- chips, and a thin day strip above it.

Do NOT include: AST or syntax-tree claims, manifest files, attestation, "verified" or
"confirmed" badges, scores, user accounts or avatars, version numbers for mcpscan itself.
```

**What to bring back:** the Claude Design project link (it syncs through the design tool now)
or the Stitch zip. Claude builds the pages on `/api/servers` (live) inside the existing Worker,
at `mcpscan.antharmaya.com/servers/<name>`.

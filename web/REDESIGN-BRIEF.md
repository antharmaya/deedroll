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

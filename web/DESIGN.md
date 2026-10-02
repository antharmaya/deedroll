# mcpscan web: design system

The page is a working instrument first and a showreel second. Everything below exists to make
one moment land: the scan, where a package's own label is laid next to what its code does.

## 1. Ideology

**A precision instrument on warm paper.** Security tools default to black screens, green text
and red alarms. That aesthetic says "hacker"; the buyer we want (an agency lead deciding whether
to let an agent run someone else's code) needs "calibrated". So:

- **Paper, not terminal.** Warm paper field, ink-blue accent, one drenched ink band. Monospace
  only where the text *is* code: package names, file paths, evidence lines.
- **Evidence over alarm.** No red banners, no scores out of 100, no "CRITICAL". A finding is a
  sentence plus the file and line that proves it. Severity is a shape before it is a colour.
- **Nothing faked.** Every progress message maps to a real event from the engine
  (`src/browser.js` `onProgress`). The animation choreographs real results; it never invents
  progress or stretches a scan to look busy.
- **The browser is the sandbox.** The page runs the same checks as the CLI (`../src`), in the
  visitor's tab. Nothing is installed, executed or uploaded.

## 2. Copy voice

| Rule | Example |
| --- | --- |
| Plain verbs, the reader's words | "Reads 13 settings its listing doesn't mention", not "Undeclared env var access detected" |
| Sentence case everywhere | "Scan package", never "SCAN PACKAGE" |
| A button says what happens | "Scan package"; the status then says "51 files read, nothing run" |
| No em dashes in UI copy | commas and full stops only |
| Headline ≤ 2 lines, lede ≤ 20 words | "Read the label, / then read the code." |
| Errors direct, never apologise | "No package called "x" on npm. Check the spelling…" |
| Privacy claims are exact | "Only public package names and versions leave your browser." It is true because OSV.dev and the registry only see names and versions |
| Numbers carry their uncertainty | the registry figure shows its sample size and interval (4 of 57, 3–17% as of 2026-10-01, with the 8 README-only servers stated beside it; regenerate via `scripts/build-web-data.js` after any scanner fix that could change past results) |

The two ledgers are the page's vocabulary: **What it tells you** (listing, README-level claims)
and **What the code does** (what the checks found). Every finding is phrased so it can sit in the
second ledger and be read against the first.

## 3. Tokens

All tokens live on `:root` in `styles.css`; dark mode redefines them under `[data-theme='dark']`.

### Colour (oklch)

| Token | Light | Role |
| --- | --- | --- |
| `--paper` | 0.977 0.005 80 | page field |
| `--paper-raised` / `--paper-sunk` | 0.99 / 0.955 | stage panel, inputs |
| `--text` / `--text-muted` / `--text-faint` | 0.235 / 0.49 / 0.66 | three text weights, no more |
| `--rule` / `--rule-soft` | 0.885 / 0.925 | hairlines, manifest ruling |
| `--accent` | 0.47 0.16 258 | ink blue: the only saturated brand colour |
| `--band` | 0.205 0.042 262 | the one drenched section (registry) |
| `--high` `--medium` `--low` `--info` | 25 / 70 / 258 / neutral hue | severity, always paired with a glyph |

Severity glyphs (so colour is never the only signal): **high** filled diamond, **medium**
triangle, **low** ring, **info** dot.

### Type

Bricolage Grotesque (display) · Hanken Grotesk (body) · JetBrains Mono (code only). All three
are self-hosted woff2 (97 KB total, OFL): Google Fonts would send every visitor's IP to Google,
which contradicts the privacy line in the hero.

Scale around a 17 px body, ratio ≈ 1.25: `13 · 15 · 17 · 21 · 27 · 36`, display
`clamp(37px → 50px)`, registry figure `clamp(64px → 136px)`. Measure 62ch for prose.

### Space, radius

4 px base: `4 8 12 16 24 32 48 64 96 144`. Gutter `clamp(16px, 4vw, 40px)`; sections
`clamp(72px, 10vw, 128px)`. One radius scale: control 10, panel 16, pill.

## 4. DOM layout

Redesigned 2026-10-02 from two prototypes (Claude Design and Google Stitch), keeping this
system's tokens and every real-data path. Claude Design gave the structure; Stitch gave the
idea of a live registry count in the header. Rejected from both: invented capabilities (AST,
manifests, attestation, "verified" badges), invented descriptions, and any regrouping that
overrides the engine's severity.

```
header.site        mark · census chip ("38,247 servers on record", live from /history) · nav · theme
main
  section.hero     grid: h1 (left, large) | .hero-copy (lede · form · help · examples)
  section.stage    full width: .stage-head (pkg · status · Skip)
                   .stage-body: ol#manifest (a third) | .ledgers (two columns)
                     #tells  "What it tells you": groups Listed as · Declares · Provenance · Published
                     #does   "What the code does": groups Credentials read · Other settings read ·
                             Hosts contacted · Capabilities · Install scripts · Known vulnerabilities
                             one row per fact, each with its file:line
  section#results  .results-head (h2 · live/replay tag · three group counts) · .results-note
                   ol.findings in three groups: Ask before installing (high, medium) ·
                   Worth knowing (low) · Context (info); an opened finding shows its code, then
                   "Why it matters" | "What the publisher can do"
                   .publisher "Is this your server?": the server.json environmentVariables to add,
                   as a diff, names and isSecret only (descriptions left for the publisher)
  section.band#registry   the census (live) · the 57-server sample as a closer read
  section.history · section.steps · section.cli
footer
```

Breakpoints: **980 px** the hero stacks; **760 px** the instrument stacks (files over the two
ledgers, which stack too). No horizontal scroll at 360 px.

## 5. Interaction states

| Element | States |
| --- | --- |
| Scan input | idle · focus (accent ring on the field wrapper) · invalid (native) |
| Scan button | idle · hover · active · busy (disabled, label unchanged) |
| Stage status | idle demo text · live stage text from `onProgress`, each ending in `…` · slow registry (after 2.5 s: "Waiting on the MCP registry, which is slow right now…"; never timed out, because a scan without the listing would misreport every credential) · done ("N files read, nothing run") · error (plain sentence, no stack; focus returns to the field) |
| Not found | npm's 404 for a missing *scoped* package has no CORS header, so the tab sees a network error. The adapter probes an unscoped name (whose 404 does carry CORS): if npm answers, it reports "No public package called…", else the real network error |
| Skip | visible only while an animation plays; finishes every running animation instantly |
| Finding rows | `<details>` collapsed · open (evidence with file:line in mono) |
| Theme | light / dark, stored in `localStorage` (`mcpscan-theme`), wrapped in try/catch; no-flash script in `<head>` |
| URL | `?q=` deep-links any scan (a package, a server URL or a registry name); `?pkg=` still works |
| Input | classified as it is read: `https://…` is a hosted server, `owner.tld/name` a registry listing, anything else a package; pasted launch commands (`npx -y`, `uvx`, `pip install`) are reduced to the package |
| Relay consent | when a hosted server blocks browsers, a panel under the input says why, what the relay sees (the URL) and keeps (nothing), with "Probe through the relay", an "Always" choice, and the CLI command as the alternative. The Scan button stays usable while it asks. |
| Hosted server stage | rows are the server's tools (tagged read-only or destructive when the server says so), or for a sign-in server the sign-in checks, one per row; the second ledger is titled "What we found", since there is no code |
| Check this computer | tries 18 common MCP ports on 127.0.0.1 from the page; a readable server is shown high, with its tools listed as proof ("this page just did it"); a port that answers opaquely is "listening, and it keeps websites out"; nothing readable explains that the browser may have blocked local access. The page's own port is skipped. |
| Servers your agents trust | a file chooser and drop zone; files are parsed in the page (secret values dropped inside the parser, never in the DOM or any request); each server shows its config findings and a "Scan it" button, except hosted ones whose URL carries a credential, which point to the command line |
| Downloads | JSON, SARIF, egress allowlist and registry block for the last live scan; hidden during the demo replay |
| Every check | a disclosure listing every check by group, with why and what to do, from the same catalog as `mcpscan explain` |
| Registry history | days recorded, the latest day's counts and diff, and "Verify it in your browser" (re-hashes every chain link and the latest file) |
| Browser pins | tools are remembered per server in this browser; a later change is reported with an explicit "Accept these tools as the new baseline" button, never accepted silently |

Races: a generation counter guards every async flow, including the last step of the animation,
so a live scan started during the intro demo cancels the demo instead of animating on top of it
or writing its counts over the new scan.

Keyboard: a skip link leads to the scanner; the 57-dot registry grid is one tab stop with arrow
keys, Home and End inside it; Escape finishes any running animation.

## 6. Motion spec

Only `transform` and `opacity` animate (plus a colour fade on developed rows). Web Animations API,
no library. `prefers-reduced-motion: reduce` renders the final state with no motion.

| Beat | What moves | Duration / delay | Easing |
| --- | --- | --- | --- |
| Intro | h1 lines rise through a mask | 760 ms, 80 + 90 ms stagger | ease-out quint |
| | lede, form | 560 ms, 320 / 430 ms | ease-out |
| | stage settles | 720 ms at 360 ms | ease-out |
| Scan A | manifest rows arrive at 32 % opacity | 300 ms, 22 ms stagger | ease-out |
| Scan B | X-ray bar travels first row → last row | `clamp(1100, rows × 80, 2200)` ms | ease-in-out |
| | each row develops as the bar crosses it | 260 ms | ease-out |
| | glyph lands | 280 ms, +60 ms | ease-back (overshoot) |
| | ink drop flies row → ledger on a quadratic curve | 620 ms, 17 keyframes | ease-in-out |
| | ledger entry slides in after the drop lands | 380 ms, +640 ms | ease-out |
| Results | first 14 findings | 360 ms, 35 ms stagger | ease-out |
| Registry | dots fill flagged-first while the figure counts up | 380 ms, 45 ms stagger, on scroll into view | ease-out |

Easings: `--ease-out cubic-bezier(0.22,1,0.36,1)` for arrivals, `--ease-inout
cubic-bezier(0.65,0,0.35,1)` for travel, `--ease-back cubic-bezier(0.34,1.56,0.64,1)` only for
marks landing. The scan is the page's one orchestrated moment; no other section animates on
scroll except the registry figure, which is data arriving.

## 7. Weight

First load (before any scan): 211 KB uncompressed, of which 97 KB is fonts; the text assets
gzip to about 33 KB. The first scan also fetches the registry index (803 KB, about 204 KB
gzipped, 2026-09-28), which maps npm and PyPI names to registry listings.

## 8. Security rules for the page

- Package content is hostile input. All of it goes through `el()` (text nodes); `innerHTML` is
  never used on anything that came from npm, the registry or OSV.
- No third-party scripts, fonts, analytics or CDNs.
- The page makes requests to `registry.npmjs.org`, `registry.modelcontextprotocol.io` and
  `api.osv.dev` only.

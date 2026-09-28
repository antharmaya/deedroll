/**
 * mcpscan web: the same engine as the CLI (../src/browser.js), and a choreography that
 * replays its REAL results — real file names, real lines — never simulated progress.
 *
 * Security: every string shown here (paths, code, descriptions) was written by a package
 * author. Nothing untrusted is ever set as HTML: all of it goes through text nodes.
 */
import { scanInBrowser } from '../src/browser.js';
import { RULES } from '../src/rules.js';
import { inspectRemote } from '../src/remote-scan.js';
import { fingerprintTools, diffFingerprints, serverKey } from '../src/pins-core.js';
import { listingStatus } from '../src/model.js';
import { init as initSetup, setCurrent } from './setup.js';

const $ = (s) => document.querySelector(s);
const REDUCE = matchMedia('(prefers-reduced-motion: reduce)').matches;
const INDEX_URL = new URL('../src/data/registry-index.json', import.meta.url).href;
// The relay runs the same read-only probe server-side, for servers that block browsers.
const RELAY_URL = new URL('../api/probe', import.meta.url).href;
const REGISTRY = 'https://registry.modelcontextprotocol.io';
const EASE_OUT = 'cubic-bezier(0.22, 1, 0.36, 1)';
const EASE_INOUT = 'cubic-bezier(0.65, 0, 0.35, 1)';
const EASE_BACK = 'cubic-bezier(0.34, 1.56, 0.64, 1)';
const RANK = { high: 0, medium: 1, low: 2, info: 3, ok: 4 };

/** Build DOM from untrusted strings, safely: children are nodes or plain text. */
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'style') n.style.cssText = v; // CSSOM, which a strict CSP allows; a style attribute it would block
    else if (k === 'dataset') Object.assign(n.dataset, v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) n.append(c instanceof Node ? c : String(c));
  return n;
}
const chev = () => el('span', { class: 'chev', 'aria-hidden': 'true' }, '›');
const glyph = (sev) => el('span', { class: `glyph ${sev}`, 'aria-hidden': 'true' });
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const fmtDate = (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
const kb = (b) => (b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`);

/* ---------- plain-language findings ---------- */

const CAPS = {
  'process execution': 'Can run other programs.',
  'process execution (python)': 'Can run other programs.',
  'dynamic code evaluation': 'Can evaluate code at runtime.',
  'filesystem writes or deletes': 'Can write or delete files.',
  'raw network sockets': 'Can open raw network connections.',
};

export function sentence(f) {
  const m = f.message ?? '';
  switch (f.check) {
    case 'undeclared-env':
      if (f.severity === 'high') return `Reads ${f.subject}, a credential its listing doesn't declare.`;
      if (f.severity === 'medium') return `Reads ${f.subject}, a credential, with no registry listing to declare it in.`;
      return `Reads the setting ${f.subject}, which its listing doesn't mention.`;
    case 'dynamic-env':
      return 'Builds an environment variable name at runtime, so it cannot be read statically.';
    case 'network-egress':
      return `Contacts ${m.replace(/^contacts /, '')}.`;
    case 'capability':
      return CAPS[m.replace(/^uses /, '')] ?? m;
    case 'install-script': {
      if (/no wheel/.test(m)) return /setup\.py/.test(m) ? 'Publishes no wheel, so installing it runs its setup.py.' : 'Publishes no wheel, so installing it runs its build code.';
      const k = /runs a (\w+) script/.exec(m)?.[1] ?? 'lifecycle';
      const dep = /^dependency (\S+)/.exec(m)?.[1];
      return dep ? `Its dependency ${dep} runs a ${k} script when installed.` : `Runs a ${k} script when it is installed.`;
    }
    case 'provenance':
      if (/repository/.test(m)) return "Doesn't link to its source code.";
      if (/integrity/.test(m)) return "Its download doesn't match the hash npm published for it.";
      if (/only one version/.test(m)) return 'Has only one published version.';
      if (/published (\d+)/.test(m)) return `Was published ${/published (\d+)/.exec(m)[1]} days ago.`;
      return m;
    case 'deprecated':
      if (/yanked/.test(m)) return `PyPI marks this release yanked: “${m.replace(/^PyPI marks .*? yanked: /, '')}”`;
      return `npm marks this version deprecated: “${m.replace(/^npm marks \S+ deprecated: /, '')}”`;
    case 'publisher-mismatch':
      return `Built from ${/built from (\S+)/.exec(m)?.[1] ?? 'another repository'}, but links to ${/points at (\S+)/.exec(m)?.[1] ?? 'a different one'}.`;
    case 'listing-status':
      return f.subject === 'deleted' ? 'The MCP registry has removed this listing.' : `The registry listing is marked ${f.subject}.`;
    case 'provenance-dropped':
      return "Earlier versions were built by CI with provenance. This one wasn't.";
    case 'known-vulnerability': {
      const v = /: (\S+?)(?: \((CVE-[^)]+)\))? — (.*?)(?:; fixed in (.+))?$/.exec(m);
      if (!v) return m;
      return `${v[1]}${v[2] ? ` (${v[2]})` : ''}: ${v[3]}${v[4] ? `. Fixed in ${v[4]}.` : ''}`;
    }
    case 'instruction-like-text': {
      const q = /: "(.*)"$/.exec(m)?.[1];
      return q ? `A tool description tries to instruct the AI: “${q}”` : m;
    }
    case 'unauthenticated':
      return 'Answers without sign-in: anyone with the URL can list its tools, and usually call them.';
    case 'custom-auth':
      return 'Uses its own sign-in (a key or token set up by hand) rather than the MCP OAuth flow.';
    case 'oauth-no-pkce':
      return "Its sign-in doesn't advertise PKCE, which OAuth 2.1 requires.";
    case 'oauth-dcr-only':
      return 'Apps can only register through Dynamic Client Registration, which MCP has deprecated.';
    case 'oauth-issuer-mismatch':
      return "Its sign-in server's metadata names a different issuer; standard clients must refuse it.";
    case 'oauth-resource-mismatch':
      return 'Its sign-in issues tokens for a different server than this one.';
    case 'oauth-metadata-missing':
      return "Requires sign-in but doesn't publish how to sign in, so standard clients can't.";
    case 'deprecated-transport':
      return 'Uses the deprecated HTTP+SSE transport, so its tools could not be listed.';
    case 'remote-not-probed':
      return /authentication/.test(m) ? 'Requires sign-in, so its tools were not listed. mcpscan uses no account.' : `Could not be probed: ${m.replace(/:.*$/, '')}.`;
    case 'pinned':
      return 'First scan from this browser: its tools are now remembered, and any change will show next time.';
    case 'tool-description-changed':
      return `Tool “${f.subject}” says something different from when you last scanned it.`;
    case 'tool-added':
      return `Tool “${f.subject}” appeared since you last scanned it.`;
    case 'tool-removed':
      return `Tool “${f.subject}” is gone since you last scanned it.`;
    case 'tool-schema-changed':
      return `Tool “${f.subject}” takes different inputs since you last scanned it.`;
    case 'multiple-listings':
      return `${m.match(/^(\d+)/)?.[1] ?? 'Several'} registry listings point at this package.`;
    default:
      return m.charAt(0).toUpperCase() + m.slice(1);
  }
}

/* ---------- the model the stage and the list share ---------- */

function ledgerKey(f) {
  switch (f.check) {
    case 'undeclared-env': return f.severity === 'low' ? 'does:settings' : 'does:credentials';
    case 'dynamic-env': return 'does:settings';
    case 'network-egress': return 'does:hosts';
    case 'capability': return `does:cap:${f.message}`;
    case 'install-script': return 'does:install';
    case 'known-vulnerability': return 'does:vulns';
    case 'provenance': return /repository/.test(f.message) ? 'tells:source' : 'tells:package';
    case 'provenance-dropped': return 'tells:provenance';
    case 'publisher-mismatch': return 'tells:provenance';
    case 'listing-status': return 'tells:listing';
    case 'deprecated': return 'tells:status';
    case 'instruction-like-text': return 'tells:descriptions';
    case 'multiple-listings': return 'tells:listing';
    default: return 'tells:package';
  }
}

const worst = (fs) => fs.reduce((w, f) => (RANK[f.severity] < RANK[w] ? f.severity : w), 'info');

function buildModel(r) {
  const byKey = new Map();
  for (const f of r.findings) {
    const k = ledgerKey(f);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(f);
  }
  const names = (k) => (byKey.get(k) ?? []).map((f) => f.subject).filter(Boolean);
  const tells = [];
  const does = [];

  tells.push({ key: 'tells:listing', sev: r.listing ? 'ok' : 'info', text: r.listing ? `Listed as ${r.listing}` : 'No registry listing found', detail: r.listing ? 'Official MCP registry' : 'Nothing to check its declarations against' });
  tells.push({
    key: 'tells:declared',
    sev: 'ok',
    text: r.declared.length ? `Declares ${plural(r.declared.length, 'setting')}` : 'Declares no settings',
    detail: r.declared.length ? r.declared.slice(0, 4) : null,
  });
  const reg = r.ecosystem === 'pypi' ? 'PyPI' : 'npm';
  tells.push({ key: 'tells:provenance', sev: r.provenance ? 'ok' : 'info', text: r.provenance ? `Built by CI, with ${reg} provenance` : 'No provenance attestation' });
  for (const k of ['tells:source', 'tells:status', 'tells:descriptions', 'tells:package']) {
    if (byKey.has(k)) tells.push({ key: k, sev: worst(byKey.get(k)), text: sentence(byKey.get(k)[0]).replace(/\.$/, '') });
  }

  const creds = names('does:credentials');
  if (creds.length) does.push({ key: 'does:credentials', sev: worst(byKey.get('does:credentials')), text: `Reads ${plural(creds.length, 'credential')} it doesn't declare`, detail: creds.slice(0, 3) });
  const settings = names('does:settings');
  if (settings.length) does.push({ key: 'does:settings', sev: 'low', text: `Reads ${plural(settings.length, 'other setting')}`, detail: settings.slice(0, 3) });
  const hosts = (byKey.get('does:hosts') ?? []).map((f) => f.message.replace(/^contacts /, ''));
  if (hosts.length) does.push({ key: 'does:hosts', sev: 'info', text: `Contacts ${plural(hosts.length, 'host')}`, detail: hosts.slice(0, 3) });
  for (const [k, fs] of byKey) if (k.startsWith('does:cap:')) does.push({ key: k, sev: 'info', text: sentence(fs[0]).replace(/\.$/, '') });
  if (byKey.has('does:install')) does.push({ key: 'does:install', sev: 'high', text: sentence(byKey.get('does:install')[0]).replace(/\.$/, '') });
  if (byKey.has('does:vulns')) does.push({ key: 'does:vulns', sev: worst(byKey.get('does:vulns')), text: `Has ${plural(byKey.get('does:vulns').length, 'known vulnerability', 'known vulnerabilities')}` });
  if (!does.length) does.push({ key: 'does:none', sev: 'ok', text: 'Nothing found that reads, runs or contacts anything' });

  // Where each finding lives in the manifest (by its first evidence file).
  const fileIndex = new Map(r.files.map((f, i) => [f.path, i]));
  const hits = r.findings.map((f) => {
    const file = f.evidence?.[0]?.file;
    const row = fileIndex.has(file) ? fileIndex.get(file) : fileIndex.get('package.json') ?? -1;
    return { f, row, key: ledgerKey(f) };
  });
  return { ...r, tells, does, hits };
}

/* ---------- the stage ---------- */

const stage = $('#stage');
const manifest = $('#manifest');
const scanbar = $('#scanbar');
const drops = $('#drops');
let running = [];
let skipRequested = false;

const track = (a) => (running.push(a), a);
function finishAll() {
  skipRequested = true;
  for (const a of running) {
    try { a.finish(); } catch { /* already done */ }
  }
}

function renderLedger(ul, items) {
  ul.replaceChildren(
    ...items.map((it) =>
      el('li', { dataset: { key: it.key }, class: it.sev === 'ok' && /no |nothing/i.test(it.text) ? 'empty' : null },
        glyph(it.sev),
        el('span', {}, it.text, it.detail && el('span', { class: 'detail' }, ...[].concat(it.detail).flatMap((d, i) => [i ? ', ' : null, el('code', {}, d)]))))
    )
  );
}

function renderManifest(files, maxRows) {
  const shown = files.length > maxRows ? files.slice(0, maxRows - 1) : files;
  const rows = shown.map((f) => el('li', {}, el('span', { class: 'glyph-slot' }), el('span', { class: 'path', title: f.path }, f.path), el('span', { class: 'lines' }, f.lines)));
  if (shown.length < files.length) rows.push(el('li', { class: 'overflow' }, el('span', { class: 'glyph-slot' }), el('span', { class: 'path' }, `and ${files.length - shown.length} more files`), el('span')));
  manifest.replaceChildren(...rows);
  return shown.length;
}

function skeleton(n = 10) {
  manifest.replaceChildren(...Array.from({ length: n }, (_, i) => el('li', { class: 'skeleton', style: `opacity:${0.5 - i * 0.035}` }, el('span'), el('span', { class: 'bar', style: `width:${40 + ((i * 37) % 45)}%` }), el('span'))));
}

/** A drop of ink flies from a manifest row to its ledger entry along a curve. */
function fly(from, to, sev, delay) {
  const box = stage.getBoundingClientRect();
  const a = from.getBoundingClientRect();
  const b = to.getBoundingClientRect();
  const x1 = a.left + a.width / 2 - box.left, y1 = a.top + a.height / 2 - box.top;
  const x2 = b.left + b.width / 2 - box.left, y2 = b.top + b.height / 2 - box.top;
  const cx = (x1 + x2) / 2, cy = Math.min(y1, y2) - 56;
  const dot = el('span', { class: 'drop', style: `background:var(--${sev === 'ok' || sev === 'info' ? 'accent' : sev})` });
  drops.append(dot);
  const frames = [];
  for (let i = 0; i <= 16; i++) {
    const t = i / 16;
    const x = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * cx + t ** 2 * x2;
    const y = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * cy + t ** 2 * y2;
    frames.push({ transform: `translate(${x}px, ${y}px) scale(${0.7 + Math.sin(t * Math.PI) * 0.5})`, opacity: t < 0.08 ? t / 0.08 : t > 0.92 ? (1 - t) / 0.08 : 1 });
  }
  const anim = track(dot.animate(frames, { duration: 620, delay, easing: EASE_INOUT, fill: 'both' }));
  anim.finished.then(() => dot.remove(), () => dot.remove());
  return anim;
}

function reveal(node, delay, { y = 6, x = 0, duration = 420 } = {}) {
  return track(node.animate([{ opacity: 0, transform: `translate(${x}px, ${y}px)` }, { opacity: 1, transform: 'none' }], { duration, delay, easing: EASE_OUT, fill: 'both' }));
}

/**
 * The centrepiece. Rows arrive undeveloped; a band of ink-blue light passes down the
 * package and develops each file as it crosses it; every real finding leaves a mark
 * in its row and flies to the ledger it belongs to. Duration scales with the package.
 */
async function play(model, my) {
  running = [];
  skipRequested = false;
  drops.replaceChildren();
  // Ledgers first: they set the stage's height, and the manifest fills whatever it is.
  renderLedger($('#tells'), model.tells);
  renderLedger($('#does'), model.does);
  manifest.replaceChildren();
  const maxRows = Math.max(6, Math.floor((manifest.clientHeight - 32) / 24));
  const shown = renderManifest(model.files, maxRows);
  $('#tells-n').textContent = '';
  $('#does-n').textContent = '';

  const rows = [...manifest.children];
  const tellsLis = [...$('#tells').children];
  const doesLis = [...$('#does').children];
  const liFor = (key) => [...tellsLis, ...doesLis].find((li) => li.dataset.key === key);

  if (REDUCE) {
    for (const r of rows) (r.style.opacity = 1), r.classList.add('developed');
    for (const li of [...tellsLis, ...doesLis]) li.style.opacity = 1;
    markRows(model, rows, shown);
    return;
  }

  // A: the manifest arrives, undeveloped
  rows.forEach((r, i) => track(r.animate([{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 0.32, transform: 'none' }], { duration: 300, delay: i * 22, easing: EASE_OUT, fill: 'both' })));
  const aEnd = rows.length * 22 + 260;

  // What it tells you is read first: the label before the code.
  tellsLis.forEach((li, i) => reveal(li, aEnd + i * 90, { x: -8, y: 0 }));

  // B: the developing pass
  const list = manifest.getBoundingClientRect();
  const top = rows[0].offsetTop;
  const bottom = rows.at(-1).offsetTop + rows.at(-1).offsetHeight;
  const pass = Math.min(2200, Math.max(1100, rows.length * 80));
  const bStart = aEnd + 200;
  scanbar.style.left = `${manifest.offsetLeft}px`;
  scanbar.style.width = `${manifest.offsetWidth}px`;
  // Row offsets are measured from the stage (their positioned ancestor) — the same box the
  // bar lives in — so no extra offset. Adding the manifest's own offset once put the light
  // ~106px below the rows it was developing.
  track(scanbar.animate(
    [{ opacity: 0, transform: `translateY(${top}px)` }, { opacity: 1, offset: 0.06 }, { opacity: 1, offset: 0.94 }, { opacity: 0.0, transform: `translateY(${bottom}px)` }],
    { duration: pass, delay: bStart, easing: EASE_INOUT, fill: 'both' }
  ));
  void list;

  const landed = new Set();
  rows.forEach((r, i) => {
    const t = bStart + ((r.offsetTop + 12 - top) / Math.max(1, bottom - top)) * pass;
    const dev = track(r.animate([{ opacity: 0.32, color: 'var(--text-faint)' }, { opacity: 1, color: 'var(--text)' }], { duration: 260, delay: t, easing: EASE_OUT, fill: 'both' }));
    dev.finished.then(() => r.classList.add('developed'), () => {});

    const here = model.hits.filter((h) => (i < shown ? h.row === i : h.row >= shown));
    if (!here.length) return;
    const slot = r.querySelector('.glyph-slot');
    const g = glyph(worst(here.map((h) => h.f)));
    slot.replaceChildren(g);
    track(g.animate([{ opacity: 0, transform: `${g.classList.contains('high') ? 'rotate(45deg) ' : ''}scale(0.2)` }, { opacity: 1, transform: `${g.classList.contains('high') ? 'rotate(45deg) ' : ''}scale(0.86)` }], { duration: 280, delay: t + 60, easing: EASE_BACK, fill: 'both' }));

    for (const key of new Set(here.map((h) => h.key))) {
      const li = liFor(key);
      if (!li) continue;
      const sev = worst(here.filter((h) => h.key === key).map((h) => h.f));
      fly(slot, li.querySelector('.glyph'), sev, t + 120);
      if (!landed.has(key)) {
        landed.add(key);
        if (li.closest('#does')) reveal(li, t + 640, { x: 10, y: 0, duration: 380 });
      }
    }
  });

  // Entries with no row of their own (manifest-level facts) settle after the pass.
  const bEnd = bStart + pass;
  doesLis.filter((li) => !landed.has(li.dataset.key)).forEach((li, i) => reveal(li, bEnd + 120 + i * 80, { x: 10, y: 0 }));

  await Promise.allSettled(running.map((a) => a.finished));
  if (stale(my)) return; // a newer flow owns the stage now
  markRows(model, rows, shown);
}

function markRows(model, rows, shown) {
  rows.forEach((r, i) => {
    const here = model.hits.filter((h) => (i < shown ? h.row === i : h.row >= shown));
    if (here.length && !r.querySelector('.glyph')) r.querySelector('.glyph-slot').replaceChildren(glyph(worst(here.map((h) => h.f))));
  });
  $('#tells-n').textContent = plural(model.tells.length, 'fact');
  $('#does-n').textContent = plural(model.does.filter((d) => d.key !== 'does:none').length, 'finding');
}

/* ---------- findings list ---------- */

/** Why it matters and what to do, from the same catalog the CLI's `explain` uses. */
function explainBlock(check) {
  const r = RULES[check];
  if (!r) return null;
  return el('div', { class: 'explain' }, el('p', {}, el('b', {}, 'Why it matters. '), r.why), el('p', {}, el('b', {}, 'What to do. '), r.fix));
}

function evidenceBlock(f) {
  return (f.evidence ?? []).filter((e) => e.text).slice(0, 3).map((e) => {
    const loc = e.line ? `${e.file}:${e.line}` : e.file;
    const pre = el('pre');
    const subj = f.subject && !String(f.subject).includes(':') ? String(f.subject) : null;
    if (subj && e.text.includes(subj)) {
      const parts = e.text.split(subj);
      parts.forEach((p, i) => {
        if (i) pre.append(el('mark', {}, subj));
        pre.append(p);
      });
    } else pre.append(e.text);
    return el('div', { class: 'evidence' }, el('div', { class: 'loc' }, loc), pre);
  });
}

const where = (f) => {
  const ev = f.evidence?.[0];
  return ev?.line ? `${ev.file.split('/').pop()}:${ev.line}` : '';
};

const GROUP_TITLE = {
  'undeclared-env': (n) => `Reads ${n} settings its listing doesn't mention`,
  'network-egress': (n) => `Contacts ${n} hosts`,
  provenance: (n) => `${n} notes about how it was published`,
};

/**
 * High and medium findings stay individual: each deserves its own look. Three or more of
 * the same kind at a lower severity collapse into one row that opens to its members —
 * a wall of near-identical rows hides the finding that matters.
 */
function groupFindings(fs, allowGroups) {
  const buckets = new Map();
  for (const f of fs) {
    const k = allowGroups ? f.check : `${f.check}#${buckets.size}`;
    if (!buckets.has(k)) buckets.set(k, []);
    buckets.get(k).push(f);
  }
  const out = [];
  for (const [k, members] of buckets) {
    const check = k.split('#')[0];
    if (members.length < 3 || !allowGroups) {
      for (const f of members) {
        out.push(el('li', {}, el('details', {},
          el('summary', {}, glyph(f.severity), el('span', { class: 'what' }, sentence(f)), el('span', { class: 'where' }, where(f)), chev()),
          ...evidenceBlock(f),
          explainBlock(f.check))));
      }
      continue;
    }
    const title = (GROUP_TITLE[check] ?? ((n) => `${n} similar findings`))(members.length);
    const lines = members.map((f) => {
      const ev = f.evidence?.[0];
      return el('li', {}, f.subject && !String(f.subject).includes(':') ? el('code', {}, f.subject) : el('span', {}, sentence(f)), el('span', { class: 'where' }, ev?.line ? `${ev.file}:${ev.line}` : ''));
    });
    out.push(el('li', {}, el('details', {},
      el('summary', {}, glyph(members[0].severity), el('span', { class: 'what' }, title), el('span', { class: 'where' }, ''), chev()),
      el('ul', { class: 'members' }, ...lines),
      explainBlock(check))));
  }
  return out;
}

function renderFindings(model, { replay }) {
  const sub = model.subtitle ?? (replay
    ? `Replay of a real scan of ${model.name} ${model.version}, ${fmtDate(model.scannedAt)}. Scan your own above.`
    : `${model.name} ${model.version}, scanned in your browser just now.`);
  $('#results-sub').textContent = sub;

  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of model.findings) counts[f.severity]++;
  $('#verdict').replaceChildren(...Object.entries(counts).map(([s, n]) => el('span', {}, glyph(s), el('b', {}, n), s)));

  const groups = [
    ['Needs a look', model.findings.filter((f) => f.severity === 'high' || f.severity === 'medium')],
    ['Worth knowing', model.findings.filter((f) => f.severity === 'low')],
    ['Context', model.findings.filter((f) => f.severity === 'info')],
  ];
  const list = $('#findings');
  list.replaceChildren();
  if (!model.findings.length) {
    list.append(el('li', { class: 'group' }, model.emptyText ?? 'Nothing found. That covers what static analysis can see: the listing, the code, known advisories.'));
  }
  if (model.pinAction) list.append(model.pinAction);
  for (const [title, fs] of groups) {
    if (!fs.length) continue;
    list.append(el('li', { class: 'group' }, `${title} (${fs.length})`));
    for (const item of groupFindings(fs, title !== 'Needs a look')) list.append(item);
  }
  $('#results').hidden = false;
  if (!REDUCE) [...list.children].slice(0, 14).forEach((li, i) => reveal(li, i * 35, { y: 8, duration: 360 }));
}

/* ---------- flows ---------- */

const status = (t) => ($('#stage-status').textContent = t);
const skipBtn = $('#skip');
skipBtn.addEventListener('click', finishAll);
addEventListener('keydown', (e) => e.key === 'Escape' && finishAll());

function fromLive(r) {
  return {
    name: r.pkg.name,
    version: r.pkg.version,
    scannedAt: new Date().toISOString(),
    files: [...r.pkg.files.entries()].map(([path, b]) => ({ path, lines: b.toString().split('\n').length })),
    listing: r.listing.found ? r.entry.server.name : null,
    declared: [...r.declared.keys()],
    provenance: Boolean(r.pkg.provenance?.current),
    ecosystem: r.pkg.ecosystem ?? 'npm',
    findings: r.findings,
  };
}
function fromDemo(d) {
  return { name: d.package.name, version: d.package.version, scannedAt: d.scannedAt, files: d.files, listing: d.listing, declared: d.declared, provenance: d.package.provenance, findings: d.findings };
}

/**
 * Every flow claims a generation. Anything that wakes up after an await checks it is
 * still the current flow and stops quietly if not. Found live: typing a package before the
 * page-load replay began let both animate the same stage at once, and the replay's last
 * step overwrote the live result's status.
 */
let generation = 0;
const stale = (my) => my !== generation;

async function show(data, { replay, my }) {
  if (stale(my)) return;
  const model = data.prebuilt ? data : buildModel(data);
  $('#stage-pkg').textContent = model.label ?? `${model.name} ${model.version}`;
  // A hosted server has no code to read: the second ledger is what the scan found.
  const [tellsTitle, doesTitle] = model.ledgerTitles ?? ['What it tells you', 'What the code does'];
  $('#tells-h').firstChild.textContent = `${tellsTitle} `;
  $('#does-h').firstChild.textContent = `${doesTitle} `;
  status(replay ? `Replay of a real scan, ${fmtDate(model.scannedAt)}` : 'Reading the results…');
  skipBtn.hidden = REDUCE;
  await play(model, my);
  if (stale(my)) return;
  skipBtn.hidden = true;
  status(replay ? `Replay of a real scan, ${fmtDate(model.scannedAt)}` : model.doneText ?? `${plural(model.files.length, 'file')} read, nothing run`);
  renderFindings(model, { replay });
}

const STAGE_TEXT = {
  metadata: (p) => `Fetching ${p.name} from ${p.registry ?? 'npm'}…`,
  download: (p) => (p.total ? `Downloading ${kb(p.bytes)} of ${kb(p.total)}…` : `Downloading ${kb(p.bytes)}…`),
  unpack: () => 'Unpacking in memory…',
  registry: () => 'Looking up its registry listing…',
  checks: (p) => `Checking ${plural(p.files, 'file')}…`,
  vulnerabilities: () => 'Checking known vulnerabilities…',
  done: () => 'Done',
};

let busy = false;

/** What was typed: a hosted URL, a registry listing name, or a package. */
export function classify(q) {
  if (/^https?:\/\//i.test(q)) return 'url';
  if (!q.startsWith('@') && !/^(npm|pypi):/i.test(q) && /^[a-z0-9-]+(\.[a-z0-9-]+)+\/[^\s/]+$/i.test(q)) return 'registry';
  return 'package';
}

const HELP_TEXT = 'Nothing is installed or run, and no tool is ever called.';

/** One entry point for every kind of input. */
async function scanTarget(q) {
  const kind = classify(q);
  if (kind === 'package') return scanLive(q);
  if (busy) return;
  busy = true;
  const my = ++generation;
  const btn = $('#scan-btn');
  begin(q, btn);
  try {
    let entry = null;
    let url = q;
    if (kind === 'registry') {
      status('Looking up the listing in the MCP registry…');
      const res = await fetch(`${REGISTRY}/v0.1/servers/${encodeURIComponent(q)}/versions/latest`);
      if (res.status === 404) throw Object.assign(new Error(`No listing called “${q}” in the MCP registry.`), { code: 'not-found' });
      if (!res.ok) throw new Error(`the MCP registry answered HTTP ${res.status}`);
      entry = await res.json();
      if (stale(my)) return;
      const pkg = (entry.server.packages ?? []).find((p) => ['npm', 'pypi'].includes((p.registryType ?? '').toLowerCase()));
      if (pkg) {
        busy = false;
        const target = pkg.registryType.toLowerCase() === 'pypi' ? `pypi:${pkg.identifier}` : pkg.identifier;
        return scanLive(target, { keepUrl: q });
      }
      url = (entry.server.remotes ?? []).find((r) => r.url && !/\{/.test(r.url))?.url;
      if (!url) throw Object.assign(new Error(`“${q}” ships nothing mcpscan can scan yet (no npm or PyPI package, no fixed URL).`), { code: 'not-found' });
    }
    await scanRemoteUrl(url, { entry, my });
    if (!stale(my)) history.replaceState(null, '', `?q=${encodeURIComponent(q)}`);
  } catch (err) {
    if (!stale(my)) fail(err);
  } finally {
    end(btn);
  }
}

function begin(label, btn) {
  finishAll();
  setCurrent(null);
  const help = $('#pkg-help');
  help.classList.remove('error');
  help.textContent = HELP_TEXT;
  $('#relay-ask').hidden = true;
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  $('#stage-pkg').textContent = label;
  $('#tells').replaceChildren();
  $('#does').replaceChildren();
  $('#tells-n').textContent = '';
  $('#does-n').textContent = '';
  skipBtn.hidden = true;
  skeleton();
}

function fail(err) {
  const help = $('#pkg-help');
  help.classList.add('error');
  help.textContent = err.code === 'not-found'
    ? `${err.message} Check the spelling, or copy it from the server's install command.`
    : `The scan stopped: ${err.message}. Check your connection and try again.`;
  status('Stopped');
  $('#pkg').focus();
  manifest.replaceChildren();
}

function end(btn) {
  busy = false;
  btn.disabled = false;
  btn.textContent = 'Scan';
}

/* ---------- hosted servers ---------- */

// Pins live in this visitor's browser only: a per-viewer memory of what each server said.
const PINS_KEY = 'mcpscan-pins';
function loadBrowserPins() {
  try { return JSON.parse(localStorage.getItem(PINS_KEY) ?? '{}'); } catch { return {}; }
}
function saveBrowserPins(p) {
  try { localStorage.setItem(PINS_KEY, JSON.stringify(p)); } catch { /* private mode: nothing is remembered */ }
}
const relayAlways = () => { try { return localStorage.getItem('mcpscan-relay') === 'always'; } catch { return false; } };

/** Ask before a URL goes to the relay; resolves true when the visitor agrees, false if they move on. */
function askRelay(my, reason) {
  const box = $('#relay-ask');
  $('#relay-why').textContent = reason;
  box.hidden = false;
  $('#relay-go').focus();
  return new Promise((resolve) => {
    const go = $('#relay-go');
    let watch;
    const done = (v) => {
      clearInterval(watch);
      box.hidden = true;
      go.removeEventListener('click', onGo);
      resolve(v);
    };
    const onGo = () => {
      try { if ($('#relay-always').checked) localStorage.setItem('mcpscan-relay', 'always'); } catch { /* no storage */ }
      done(true);
    };
    go.addEventListener('click', onGo);
    watch = setInterval(() => stale(my) && done(false), 300);
  });
}

async function viaRelay(url) {
  let res;
  try {
    res = await fetch(RELAY_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }) });
  } catch {
    throw new Error('the relay is not reachable from here');
  }
  const body = await res.json().catch(() => ({ ok: false, error: `the relay answered HTTP ${res.status}` }));
  if (!body.ok) throw new Error(body.error);
  return body;
}

async function scanRemoteUrl(url, { entry, my }) {
  const host = new URL(url).host;
  status(`Asking ${host} for its tools, from your browser…`);
  let r = await inspectRemote(url, { fetchImpl: (u, i) => fetch(u, i), timeoutMs: 12000 });
  let via = 'browser';
  if (stale(my)) return;
  // A browser cannot tell "blocked by CORS" from "down": both are a bare network error.
  const blocked = !r.remote.probed && r.remote.reason === 'transport' && /fetch|network|load failed/i.test(r.remote.message);
  const authUnread = r.remote.reason === 'auth' && r.remote.auth?.unreadable;
  if (blocked || authUnread) {
    const why = blocked
      ? `${host} doesn't let web pages read its answers, or isn't answering. Most hosted servers block pages: 25 of 44 we sampled.`
      : `${host} requires sign-in, and its sign-in details can't be read from a web page.`;
    status(blocked ? 'Blocked for browsers' : 'Sign-in details blocked for browsers');
    manifest.replaceChildren();
    const btn = $('#scan-btn');
    let ok = relayAlways();
    if (!ok) {
      // A pending question must not lock the page: free the button while asking, so the
      // visitor can scan something else instead; that new scan cancels this one.
      end(btn);
      ok = await askRelay(my, why);
      if (!ok || stale(my)) return;
      busy = true;
      btn.disabled = true;
      btn.textContent = 'Scanning…';
    }
    status(`Probing ${host} through the relay…`);
    r = await viaRelay(url);
    via = 'relay';
    if (stale(my)) return;
  }

  const findings = [...listingStatus(entry), ...r.findings];
  let pinAction = null;
  if (r.remote.probed) {
    const pins = loadBrowserPins();
    const key = serverKey(url);
    const d = diffFingerprints(pins[key], await fingerprintTools(r.tools), { store: 'this browser' });
    findings.push(...d.findings);
    if (d.firstPin || !d.changed) {
      pins[key] = d.next;
      saveBrowserPins(pins);
    } else {
      // Never accepted silently: a change stays reported until the visitor accepts it.
      pinAction = el('li', { class: 'group' }, el('button', { type: 'button', class: 'chip accept' }, 'Accept these tools as the new baseline'));
      pinAction.querySelector('button').addEventListener('click', (e) => {
        const p = loadBrowserPins();
        p[key] = { ...d.next, pinnedAt: new Date().toISOString() };
        saveBrowserPins(p);
        e.target.replaceWith('Accepted. The next scan compares against the tools as they are now.');
      });
    }
  }
  findings.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  setCurrent({ target: url, pkg: null, entry, remote: r.remote, findings });
  await show(buildRemoteModel(url, r, { entry, via, findings, pinAction }), { replay: false, my });
}

/**
 * The same stage, read for a hosted server: rows are its tools, or, when it requires
 * sign-in, the sign-in checks; the ledgers are what it claims and what was found.
 */
function buildRemoteModel(url, r, { entry, via, findings, pinAction }) {
  const host = new URL(url).host;
  const rem = r.remote;
  const tells = [];
  const does = [];
  const hits = [];
  let files;
  if (entry) tells.push({ key: 'tells:listing', sev: 'ok', text: `Listed as ${entry.server.name}`, detail: 'Official MCP registry' });

  if (rem.probed) {
    const a = rem.annotations;
    const tag = (t) => (t.annotations?.readOnlyHint ? 'read-only' : t.annotations?.destructiveHint ? 'destructive' : '');
    files = r.tools.map((t) => ({ path: t.name, lines: tag(t) }));
    const idx = new Map(r.tools.map((t, i) => [t.name, i]));
    for (const f of findings) {
      const tool = String(f.subject ?? '').split(':')[0];
      const key = f.check.startsWith('tool-') || f.check === 'pinned' ? 'does:changes' : `does:${f.check}`;
      hits.push({ f, row: idx.has(tool) ? idx.get(tool) : -1, key });
    }
    const who = rem.serverInfo?.name ? `${rem.serverInfo.name}${rem.serverInfo.version ? ` ${rem.serverInfo.version}` : ''}` : host;
    tells.push({ key: 'tells:server', sev: 'ok', text: `Calls itself ${who}` });
    tells.push({ key: 'tells:era', sev: rem.era === 'modern' ? 'ok' : 'info', text: rem.era === 'modern' ? `Speaks MCP ${rem.protocolVersion}, the current revision` : `Speaks an older MCP revision${rem.protocolVersion ? ` (${rem.protocolVersion})` : ''}` });
    tells.push({ key: 'tells:tools', sev: 'ok', text: `Offers ${plural(rem.tools, 'tool')}`, detail: a.destructive ? a.destructiveNames : null });
    if (rem.tools) {
      tells.push({
        key: 'tells:annotations',
        sev: a.unannotated === rem.tools ? 'info' : 'ok',
        text: a.unannotated === rem.tools ? 'Says nothing about which tools change things' : `Marks ${a.readOnly} read-only and ${a.destructive} destructive`,
      });
    }
  } else {
    const au = rem.auth;
    const yes = (v) => (v ? 'yes' : 'no');
    files = [{ path: 'tools/list', lines: rem.reason === 'auth' ? `HTTP ${rem.detail?.status ?? 401}` : rem.reason }];
    if (au && !au.custom) {
      files.push({ path: 'sign-in metadata', lines: au.resourceMetadataUrl ? 'published' : au.unreadable ? 'unreadable' : 'missing' });
      if (au.authorizationServers?.length) files.push({ path: `sign-in server ${new URL(au.authorizationServers[0]).host}`, lines: au.server ? 'found' : 'no metadata' });
      if (au.server) {
        files.push({ path: 'PKCE (S256)', lines: yes(au.server.pkceS256) });
        files.push({ path: 'Client ID metadata documents', lines: yes(au.server.clientIdMetadataDocuments) });
        files.push({ path: 'Issuer identification', lines: yes(au.server.issParameter) });
        files.push({ path: 'Dynamic client registration', lines: yes(au.server.dynamicRegistration) });
      }
    }
    const rowFor = { 'oauth-metadata-missing': 1, 'oauth-resource-mismatch': 1, 'oauth-issuer-mismatch': 2, 'oauth-no-pkce': 3, 'oauth-dcr-only': 6, 'custom-auth': 0, 'deprecated-transport': 0, 'remote-not-probed': 0 };
    for (const f of findings) hits.push({ f, row: rowFor[f.check] ?? -1, key: `does:${f.check}` });
    const signIn = au?.custom ? 'Asks for its own key or token' : au?.server ? `Signs people in through ${new URL(au.authorizationServers[0]).host}` : 'Requires sign-in';
    tells.push({ key: 'tells:auth', sev: 'info', text: rem.reason === 'auth' ? signIn : sentence({ check: 'remote-not-probed', message: rem.message }).replace(/\.$/, '') });
  }

  const shown = new Set();
  for (const h of hits) {
    if (shown.has(h.key)) continue;
    if (h.f.severity === 'info' && !['pinned', 'unauthenticated', 'custom-auth'].includes(h.f.check)) continue;
    shown.add(h.key);
    does.push({ key: h.key, sev: h.f.severity, text: sentence(h.f).replace(/\.$/, '') });
  }
  if (!does.length) {
    const none = rem.probed
      ? 'Nothing in its tool descriptions tries to instruct the AI'
      : rem.auth?.server ? 'Its sign-in is built to the current MCP specification' : 'Nothing could be checked without its tools';
    does.push({ key: 'does:none', sev: 'ok', text: none });
  }

  const done = rem.probed ? `${plural(rem.tools, 'tool')} listed, none called` : 'Sign-in checked, no account used';
  const where = via === 'relay' ? 'through the relay' : 'from your browser';
  return {
    prebuilt: true,
    name: host,
    version: '',
    label: via === 'relay' ? `${host}, via relay` : host,
    scannedAt: new Date().toISOString(),
    files,
    tells,
    does,
    hits,
    findings,
    pinAction,
    doneText: `${done}, ${where}`,
    subtitle: `${url}, probed ${where} just now.`,
    emptyText: 'Nothing found in what the server says about itself.',
    ledgerTitles: ['What it tells you', 'What we found'],
  };
}

async function scanLive(name, { keepUrl } = {}) {
  if (busy) return;
  busy = true;
  const my = ++generation;
  finishAll();
  const btn = $('#scan-btn');
  const help = $('#pkg-help');
  help.classList.remove('error');
  help.textContent = HELP_TEXT;
  $('#relay-ask').hidden = true;
  setCurrent(null);
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  $('#stage-pkg').textContent = name;
  $('#tells').replaceChildren();
  $('#does').replaceChildren();
  $('#tells-n').textContent = '';
  $('#does-n').textContent = '';
  skipBtn.hidden = true; // an interrupted replay never reaches its own cleanup
  skeleton();
  try {
    // The registry is sometimes slow (7s measured 2026-09-28). Say who we are waiting on;
    // never time it out, since a scan without the listing would misreport every credential.
    let slow = null;
    const onProgress = (p) => {
      if (stale(my)) return;
      clearTimeout(slow);
      status(STAGE_TEXT[p.stage]?.(p) ?? '');
      if (p.stage === 'registry') slow = setTimeout(() => !stale(my) && status('Waiting on the MCP registry, which is slow right now…'), 2500);
    };
    const registry = /^pypi:/.test(name) ? 'PyPI' : 'npm';
    const r = await scanInBrowser(name, { indexUrl: INDEX_URL, onProgress: (p) => onProgress({ ...p, registry }) }).finally(() => clearTimeout(slow));
    if (!stale(my)) setCurrent(r);
    if (stale(my)) return;
    await show(fromLive(r), { replay: false, my });
    history.replaceState(null, '', `?q=${encodeURIComponent(keepUrl ?? name)}`);
  } catch (err) {
    help.classList.add('error');
    help.textContent = err.code === 'not-found'
      ? `${err.message} Check the spelling, or copy the name from the server's install command.`
      : `The scan stopped: ${err.message}. Check your connection and try again.`;
    status('Stopped');
    $('#pkg').focus();
    manifest.replaceChildren();
  } finally {
    busy = false;
    btn.disabled = false;
    btn.textContent = 'Scan';
  }
}

/**
 * People paste what their config says: "npx -y pkg", "uvx pkg", "pip install pkg". Keep
 * the package and its ecosystem; drop the launcher and any "@latest" or "==1.2" pin.
 */
export function normalizeTarget(raw) {
  let v = raw.trim();
  if (/^https?:\/\//i.test(v)) return v.split(/\s+/)[0];
  const py = /^(uvx|pipx\s+run|pip3?\s+install|uv\s+(?:tool\s+)?run)\s+/i;
  if (py.test(v)) v = `pypi:${v.replace(py, '').replace(/^(--?\S+\s+(?:\S+\s+)?)*/, '')}`;
  v = v.replace(/^npx\s+(-y\s+|--yes\s+)?/i, '').replace(/^npm:/i, '');
  return v.replace(/@latest$/, '').split(/\s+/)[0].replace(/==.*$/, '');
}

$('#scan-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const name = normalizeTarget($('#pkg').value);
  if (!name) {
    const help = $('#pkg-help');
    help.classList.add('error');
    help.textContent = 'Enter a server URL, a package or a registry name, like pypi:mcp-server-fetch.';
    $('#pkg').focus();
    return;
  }
  scanTarget(name);
});
document.querySelectorAll('.examples .chip').forEach((c) => c.addEventListener('click', () => {
  $('#pkg').value = c.dataset.pkg;
  scanTarget(c.dataset.pkg);
}));

/* ---------- theme ---------- */
// The browser chrome follows the page's chosen theme, not only the system's.
const syncChrome = () => {
  const paper = getComputedStyle(document.body).backgroundColor;
  document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute('content', paper));
};
$('.theme').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme !== 'dark';
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  try { localStorage.setItem('mcpscan-theme', dark ? 'dark' : 'light'); } catch { /* private mode */ }
  syncChrome();
});
syncChrome();

/* ---------- the registry band ---------- */
async function band() {
  const h = await (await fetch('data/registry-health.json')).json();
  $('#figure').replaceChildren(String(h.flagged), el('small', {}, ` of ${h.scanned}`));
  $('#band-method').textContent =
    `A random sample of npm-published servers in the official MCP registry, ${fmtDate(h.sampledAt)}. Across the whole registry that points to between ${h.interval[0]}% and ${h.interval[1]}%, at 95% confidence.`;
  const dots = $('#dots');
  dots.setAttribute('role', 'group');
  const note = $('#dot-note');
  const rows = [...h.rows].sort((a, b) => Number(b.flagged) - Number(a.flagged));
  dots.replaceChildren(...rows.map((r) => {
    const d = el('button', { class: `dot${r.flagged ? ' flagged' : ''}`, type: 'button', 'aria-label': `${r.name}: ${r.flagged ? `reads ${r.secrets.join(', ')} without declaring it` : 'declares what it reads'}` });
    const say = () => note.replaceChildren(el('b', {}, r.name), r.flagged ? ` reads ${r.secrets.join(', ')} without declaring it.` : ' declares what it reads.');
    d.addEventListener('pointerenter', say);
    d.addEventListener('focus', say);
    return d;
  }));
  // One tab stop for the whole grid, arrows inside it: 57 stops would trap a keyboard user.
  const all = [...dots.children];
  all.forEach((d, i) => (d.tabIndex = i ? -1 : 0));
  const COLS = 10;
  dots.addEventListener('keydown', (e) => {
    const i = all.indexOf(document.activeElement);
    if (i < 0) return;
    const step = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: COLS, ArrowUp: -COLS, Home: -i, End: all.length - 1 - i }[e.key];
    if (step === undefined) return;
    e.preventDefault();
    const next = all[Math.max(0, Math.min(all.length - 1, i + step))];
    all[i].tabIndex = -1;
    next.tabIndex = 0;
    next.focus();
  });
  if (REDUCE) return;
  const io = new IntersectionObserver((entries) => {
    if (!entries.some((e) => e.isIntersecting)) return;
    io.disconnect();
    // The number and the picture are the same fact: the figure counts up as the flagged
    // dots fill, then the rest of the sample settles in around them.
    const fig = $('#figure').firstChild;
    [...dots.children].forEach((d, i) => {
      const a = d.animate([{ opacity: 0, transform: 'scale(0.4)' }, { opacity: 1, transform: 'none' }], { duration: 380, delay: i * 45, easing: EASE_OUT, fill: 'both' });
      if (d.classList.contains('flagged')) a.finished.then(() => (fig.textContent = String(Math.min(h.flagged, i + 1))));
    });
    fig.textContent = '0';
  }, { threshold: 0.35 });
  io.observe(dots);
}

/* ---------- the one orchestrated page-load moment ---------- */
async function intro() {
  if (!REDUCE) {
    document.querySelectorAll('.hero h1 .line > span').forEach((s, i) =>
      s.animate([{ transform: 'translateY(105%)' }, { transform: 'none' }], { duration: 760, delay: 80 + i * 90, easing: EASE_OUT, fill: 'both' }));
    [$('.lede'), $('.scan-form')].forEach((n, i) => n.animate([{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'none' }], { duration: 560, delay: 320 + i * 110, easing: EASE_OUT, fill: 'both' }));
    stage.animate([{ opacity: 0, transform: 'translateY(14px) scale(0.99)' }, { opacity: 1, transform: 'none' }], { duration: 720, delay: 360, easing: EASE_OUT, fill: 'both' });
  }
  const params = new URLSearchParams(location.search);
  const q = params.get('q') ?? params.get('pkg');
  if (q) {
    $('#pkg').value = q;
    return scanTarget(normalizeTarget(q));
  }
  const my = generation;
  const demo = await (await fetch('data/demo.json')).json();
  await new Promise((r) => setTimeout(r, REDUCE ? 0 : 900));
  if (stale(my)) return; // the visitor already started their own scan
  await show(fromDemo(demo), { replay: true, my });
}

initSetup({ el, glyph, sentence, plural, scanTarget, RANK });
band();
intro();

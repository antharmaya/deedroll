/**
 * Everything the command line does, in the page: downloads of every output format, the
 * local exposure check (--local), the config audit (--installed), the checks catalog
 * (mcpscan explain) and the registry history (snapshot --status / --verify).
 *
 * The page's own helpers are passed in (init), so this module holds no second copy of them.
 */
import { toJsonV1, scanToSarif, toRegistryMeta, egressAllowlist } from '../src/output.js';
import { findMcpEndpoint, judgeLocal, COMMON_PORTS } from '../src/local-core.js';
import { parseConfigText, configFindings } from '../src/installed-core.js';
import { RULES, CHECK_GROUPS, TOOL_VERSION } from '../src/rules.js';

let h; // { el, glyph, sentence, plural, scanTarget, RANK }
let current = null; // the last live scan, in the CLI's result shape
const $ = (s) => document.querySelector(s);

export function init(helpers) {
  h = helpers;
  wireExports();
  wireLocal();
  wireConfigs();
  renderCatalog();
  loadHistory();
}

/** Called by the page after every scan: live results can be downloaded, replays cannot. */
export function setCurrent(result) {
  current = result;
  $('#exports').hidden = !result;
}

/* ---------- downloads ---------- */

function save(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h.el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function wireExports() {
  $('#exports').hidden = true;
  $('#exports').addEventListener('click', async (e) => {
    const kind = e.target.closest('[data-export]')?.dataset.export;
    if (!kind || !current) return;
    const base = `mcpscan-${String(current.pkg?.name ?? new URL(current.target.replace(/^(npm|pypi):/, 'https://x/')).host).replace(/[^a-z0-9.-]+/gi, '_')}`;
    const opts = { version: TOOL_VERSION };
    if (kind === 'json') save(`${base}.json`, JSON.stringify(await toJsonV1(current, opts), null, 2), 'application/json');
    if (kind === 'sarif') save(`${base}.sarif`, JSON.stringify(await scanToSarif([current], opts), null, 2), 'application/sarif+json');
    if (kind === 'meta') save(`${base}.registry-meta.json`, JSON.stringify(await toRegistryMeta(current, opts), null, 2), 'application/json');
    if (kind === 'egress') save(`${base}.egress.txt`, egressAllowlist(current), 'text/plain');
  });
}

/* ---------- this computer ---------- */

async function pool(items, limit, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  }));
  return out;
}

/**
 * The browser can only try common ports, but it answers the sharpest question: this page
 * is a website, so whatever it can read, any website can.
 */
async function checkPort(port) {
  const base = `http://127.0.0.1:${port}`;
  let found = null;
  try {
    found = await findMcpEndpoint(base, { timeoutMs: 2500 });
  } catch { /* unreadable */ }
  if (found?.answered) return { port, state: 'exposed', found };
  if (found?.auth) return { port, state: 'auth', found };
  if (found?.sse) return { port, state: 'sse', found };
  // Unreadable: closed, or listening but refusing web pages. An opaque request tells them apart.
  try {
    await fetch(`${base}/`, { mode: 'no-cors', signal: AbortSignal.timeout(1500) });
    return { port, state: 'listening' };
  } catch {
    return { port, state: 'closed' };
  }
}

function wireLocal() {
  const btn = $('#local-go');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const own = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname) ? Number(location.port) : null;
    const ports = COMMON_PORTS.filter((p) => p !== own);
    $('#local-status').textContent = `Trying ${ports.length} ports on this computer…`;
    const list = $('#local-results');
    list.replaceChildren();
    const results = await pool(ports, 6, checkPort);
    btn.disabled = false;
    const shown = results.filter((r) => r.state !== 'closed');
    const exposed = shown.filter((r) => r.state === 'exposed').length;
    $('#local-status').textContent = !shown.length
      ? `Nothing on the ${ports.length} usual MCP ports answered this page. If your browser asked about local network access and you declined, that is why. The command line checks every port.`
      : exposed
        ? `${h.plural(exposed, 'server')} on this computer ${exposed === 1 ? 'is' : 'are'} readable by any website you visit.`
        : `Nothing here is readable by websites. ${h.plural(shown.length, 'port')} answered in a way that keeps websites out.`;
    for (const r of shown) list.append(localRow(r));
  });
}

function localRow(r) {
  const { el, glyph, sentence } = h;
  const where = `127.0.0.1:${r.port}`;
  if (r.state === 'exposed') {
    // This page is a website and it just read the tool list: the Origin check is absent.
    const findings = judgeLocal({ ...r.found, originValidated: false });
    const names = r.found.tools.map((t) => t.name);
    return el('li', { class: 'setup-row' }, glyph('high'),
      el('div', {}, el('b', {}, `${where}: any website can reach it`),
        el('p', {}, `This page just listed its ${h.plural(names.length, 'tool')}${names.length ? `: ${names.slice(0, 6).join(', ')}${names.length > 6 ? '…' : ''}` : ''}. A website you visit could do the same, and call them.`),
        ...findings.filter((f) => f.severity !== 'info').map((f) => el('p', { class: 'why' }, sentence(f))),
        el('p', { class: 'why' }, RULES['no-origin-validation'].fix)));
  }
  const text = {
    auth: [`${where}: an MCP server that requires sign-in`, 'Websites can see it exists, but not use it without an account.'],
    sse: [`${where}: an MCP server on the deprecated SSE transport`, 'Its tools could not be listed from here.'],
    listening: [`${where}: something is listening, and it keeps websites out`, 'It may or may not be an MCP server; either way, this page cannot read it. The command line can check it directly.'],
  }[r.state];
  return el('li', { class: 'setup-row' }, glyph(r.state === 'listening' ? 'ok' : 'info'), el('div', {}, el('b', {}, text[0]), el('p', {}, text[1])));
}

/* ---------- your agents' configs ---------- */

/** A remote URL is offered for scanning only if it visibly carries no credential. */
function safeToScan(probeUrl) {
  try {
    const u = new URL(probeUrl);
    if (u.search || u.username || u.password) return null;
    if (u.pathname.split('/').some((seg) => /^[A-Za-z0-9_-]{20,}$/.test(seg))) return null;
    return `${u.origin}${u.pathname}`;
  } catch {
    return null;
  }
}

function wireConfigs() {
  const input = $('#config-files');
  const drop = $('#config-drop');
  input.addEventListener('change', () => readConfigs([...input.files]));
  for (const ev of ['dragenter', 'dragover']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); });
  for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    readConfigs([...e.dataTransfer.files]);
  });
}

async function readConfigs(files) {
  const { el, glyph, sentence } = h;
  const servers = [];
  const problems = [];
  for (const f of files) {
    if (f.size > 2 * 1024 * 1024) {
      problems.push(`${f.name}: too large to be an MCP config`);
      continue;
    }
    try {
      servers.push(...parseConfigText(await f.text(), f.name)); // values are dropped inside the parser
    } catch (err) {
      problems.push(`${f.name}: ${String(err.message).slice(0, 80)}`);
    }
  }
  $('#config-status').textContent = `${h.plural(servers.length, 'server')} in ${h.plural(files.length, 'file')}, read in this page. Nothing was uploaded.${problems.length ? ` Could not read: ${problems.join('; ')}.` : ''}`;
  const list = $('#config-results');
  list.replaceChildren(...servers.map((s) => {
    const findings = configFindings(s).filter((f) => f.check !== 'not-scanned').sort((a, b) => h.RANK[a.severity] - h.RANK[b.severity]);
    const worst = findings[0]?.severity ?? 'ok';
    const l = s.launch;
    const what = l.kind === 'npm' ? `npm package ${l.name}${l.version ? `@${l.version}` : ''}`
      : l.kind === 'pypi' ? `PyPI package ${l.name}${l.version ? ` ${l.version}` : ''}`
        : l.kind === 'remote' ? `hosted at ${l.host}` : l.kind === 'container' ? 'a container image' : `a local ${l.runtime ?? l.command ?? 'program'}`;
    const target = l.kind === 'npm' ? l.name : l.kind === 'pypi' ? `pypi:${l.name}` : l.kind === 'remote' ? safeToScan(s.probeUrl) : null;
    const action = target
      ? el('button', { type: 'button', class: 'chip', dataset: { scan: target } }, 'Scan it')
      : el('span', { class: 'why' }, l.kind === 'remote' ? 'Its URL holds a credential: scan it with the command line, which keeps it on your machine.' : 'Not scannable from here yet.');
    return el('li', { class: 'setup-row' }, glyph(worst),
      el('div', {}, el('b', {}, `${s.name}`), el('span', { class: 'meta' }, ` ${s.agent === 'unknown' ? '' : `${s.agent}, `}${what}`),
        ...findings.map((f) => el('p', { class: 'why' }, sentence(f))), action));
  }));
  list.onclick = (e) => {
    const t = e.target.closest('[data-scan]')?.dataset.scan;
    if (!t) return;
    $('#pkg').value = t;
    window.scrollTo({ top: 0, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    h.scanTarget(t);
  };
}

/* ---------- the catalog ---------- */

function renderCatalog() {
  const { el, glyph } = h;
  const total = Object.keys(RULES).length;
  $('#catalog summary').textContent = `Every check mcpscan makes (${total})`;
  $('#catalog-body').replaceChildren(...CHECK_GROUPS.map(([title, ids]) =>
    el('section', {}, el('h3', {}, title), el('dl', {}, ...ids.flatMap((id) => [
      el('dt', {}, glyph(RULES[id].level === 'high' ? 'high' : RULES[id].level), el('code', { translate: 'no' }, id), ` ${RULES[id].title}`),
      el('dd', {}, el('p', {}, el('b', {}, 'Why it matters. '), RULES[id].why), el('p', {}, el('b', {}, 'What to do. '), RULES[id].fix)),
    ])))));
}

/* ---------- the registry history ---------- */

const HISTORY = new URL('../history/', import.meta.url).href;
const sha256 = async (bytes) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');

async function loadHistory() {
  const { el } = h;
  const body = $('#history-body');
  let lines;
  try {
    const res = await fetch(`${HISTORY}chain.jsonl`, { cache: 'no-store' });
    if (!res.ok) throw new Error(String(res.status));
    lines = (await res.text()).split('\n').filter(Boolean);
  } catch {
    body.replaceChildren(el('p', { class: 'setup-status' }, 'The record is not available from here right now.'));
    return;
  }
  const chain = lines.map((l) => JSON.parse(l));
  const last = chain.at(-1);
  const first = chain[0];
  const stat = (label, value) => el('div', {}, el('dt', {}, label), el('dd', {}, value));
  const stats = el('dl', { class: 'history-stats' },
    stat('Days recorded', String(chain.length)),
    stat('Since', first.date),
    stat('Listings, latest day', last.listings.toLocaleString('en')),
    stat('Hosted servers answering', `${last.probed} of ${Math.min(500, last.endpoints)}`));
  const diff = el('div', { class: 'history-diff' });
  const diffFile = last.files.find((f) => f.file.endsWith('.diff.json'));
  if (diffFile) {
    try {
      const d = await (await fetch(`${HISTORY}${diffFile.file}`)).json();
      const list = (label, items, fmt = (x) => x) => items.length ? el('div', {}, el('h3', {}, `${label} (${items.length})`), el('ul', {}, ...items.slice(0, 8).map((x) => el('li', {}, el('code', { translate: 'no' }, fmt(x)))), items.length > 8 ? el('li', {}, `and ${items.length - 8} more`) : null)) : null;
      diff.append(el('p', {}, `Since ${d.since}:`),
        list('Removed or deprecated by the registry', d.status.filter((x) => x.to !== 'active'), (x) => `${x.name}: ${x.from} → ${x.to}`),
        list('Changed what they declare', d.declarations, (x) => `${x.name} ${x.from} → ${x.to}`),
        list('Moved their endpoint', d.endpoints, (x) => `${x.name}: ${x.to.join(', ')}`),
        list('New listings', d.added),
        list('Gone from the registry', d.removed));
    } catch { /* the stats still stand */ }
  } else {
    diff.append(el('p', {}, 'This is the first day of the record, so there is nothing to compare yet. From tomorrow, this shows what changed.'));
  }
  const verifyBtn = el('button', { type: 'button', class: 'btn' }, 'Verify it in your browser');
  const verdict = el('p', { class: 'setup-status', 'aria-live': 'polite' });
  verifyBtn.addEventListener('click', async () => {
    verifyBtn.disabled = true;
    verdict.textContent = 'Checking every link in the chain…';
    for (let i = 1; i < lines.length; i++) {
      if (chain[i].prev !== (await sha256(new TextEncoder().encode(lines[i - 1])))) {
        verdict.textContent = `The chain is broken at ${chain[i].date}: that day does not match the one before it.`;
        verifyBtn.disabled = false;
        return;
      }
    }
    const f = last.files[0];
    verdict.textContent = `Links intact. Downloading ${f.file} (${Math.round(f.bytes / 1048576 * 10) / 10} MB) to check its hash…`;
    const got = new Uint8Array(await (await fetch(`${HISTORY}${f.file}`)).arrayBuffer());
    const ok = (await sha256(got)) === f.sha256;
    verdict.textContent = ok
      ? `Verified in your browser: ${h.plural(chain.length, 'day')}, every link intact, and ${f.file} matches the hash recorded on ${last.date}.`
      : `${f.file} does not match the hash recorded on ${last.date}.`;
    verifyBtn.disabled = false;
  });
  body.replaceChildren(stats, diff, el('div', { class: 'history-verify' }, verifyBtn, verdict,
    el('p', { class: 'setup-note' }, 'Everything is public: ', el('a', { href: `${HISTORY}chain.jsonl` }, 'chain.jsonl'), ' lists every file and its hash.')));
}

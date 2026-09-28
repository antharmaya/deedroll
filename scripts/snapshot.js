#!/usr/bin/env node
/**
 * The registry history: one snapshot a day, append-only, hash-chained.
 *
 * Why: a hosted server can rewrite what its tools tell the model after people approved it,
 * and the registry "does not provide data durability guarantees". Only a record kept at
 * the time can show what a listing declared, or what a server's tools said, on a given day.
 *
 * Each run writes, under $MCPSCAN_ARCHIVE (default ./archive):
 *   registry/YYYY-MM-DD.jsonl.gz   every latest listing: declarations, endpoints, status
 *   registry/YYYY-MM-DD.diff.json  what changed since the previous snapshot
 *   tools/YYYY-MM-DD.jsonl.gz      tool lists of a rotating slice of hosted servers
 *   chain.jsonl                    one line per run: file hashes + the hash of the line before
 *
 * Usage:
 *   node scripts/snapshot.js [--tools 500]   take today's snapshot (skips if one exists)
 *   node scripts/snapshot.js --status        the last runs, and a warning if the record went stale
 *   node scripts/snapshot.js --verify        re-hash every file and check the chain
 */
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { mkdirSync, writeFileSync, readFileSync, existsSync, appendFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { inspectRemote } from '../src/remote-scan.js';
import { fingerprintTools } from '../src/pins-core.js';

const ARCHIVE = resolve(process.env.MCPSCAN_ARCHIVE ?? new URL('../archive', import.meta.url).pathname);
const REGISTRY = 'https://registry.modelcontextprotocol.io/v0.1/servers';
const CHAIN = join(ARCHIVE, 'chain.jsonl');
const today = new Date().toISOString().slice(0, 10);
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const log = (...a) => console.log(new Date().toISOString(), ...a);

const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(name);
  return i < 0 ? dflt : args[i + 1] ?? true;
};

/* ---------- the chain ---------- */

function readChain() {
  if (!existsSync(CHAIN)) return [];
  return readFileSync(CHAIN, 'utf8').split('\n').filter(Boolean).map((line) => ({ line, entry: JSON.parse(line) }));
}

function appendChain(entry) {
  const chain = readChain();
  const prev = chain.length ? sha256(chain.at(-1).line) : null;
  appendFileSync(CHAIN, `${JSON.stringify({ ...entry, prev })}\n`);
}

/* ---------- registry ---------- */

/** The declarations a listing makes: what the history is for. Everything else is noise. */
function reduce(item) {
  const s = item.server ?? {};
  const o = item._meta?.['io.modelcontextprotocol.registry/official'] ?? {};
  return {
    name: s.name,
    version: s.version,
    description: s.description,
    repository: s.repository?.url ?? null,
    status: o.status ?? null,
    statusChangedAt: o.statusChangedAt ?? null,
    publishedAt: o.publishedAt ?? null,
    updatedAt: o.updatedAt ?? null,
    packages: (s.packages ?? []).map((p) => ({
      type: (p.registryType ?? '').toLowerCase(),
      id: p.identifier,
      version: p.version ?? null,
      transport: p.transport?.type ?? null,
      env: (p.environmentVariables ?? []).map((e) => ({ name: e.name, secret: Boolean(e.isSecret), required: Boolean(e.isRequired) })),
    })),
    remotes: (s.remotes ?? []).map((r) => ({ type: r.type, url: r.url, headers: (r.headers ?? []).map((h) => h.name) })),
  };
}

async function walkRegistry() {
  const out = [];
  let cursor = null;
  let pages = 0;
  for (;;) {
    const u = new URL(REGISTRY);
    u.searchParams.set('limit', '100');
    u.searchParams.set('version', 'latest');
    if (cursor) u.searchParams.set('cursor', cursor);
    let res;
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        res = await fetch(u, { signal: AbortSignal.timeout(60000) });
        if (res.ok) break;
      } catch {
        res = null;
      }
      await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
    }
    if (!res?.ok) throw new Error(`registry page ${pages} failed (${res?.status ?? 'no answer'}); snapshot not written`);
    const body = await res.json();
    for (const item of body.servers ?? []) out.push(reduce(item));
    pages++;
    cursor = body.metadata?.nextCursor;
    if (!cursor) break;
  }
  return { listings: out, pages };
}

function previousSnapshot() {
  const dir = join(ARCHIVE, 'registry');
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl\.gz$/.test(f) && !f.startsWith(today)).sort();
  if (!files.length) return null;
  const rows = gunzipSync(readFileSync(join(dir, files.at(-1)))).toString('utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  return { date: files.at(-1).slice(0, 10), rows };
}

/** What changed between two snapshots: the part people read. */
export function diffSnapshots(before, after) {
  const key = (r) => r.name;
  const a = new Map(before.map((r) => [key(r), r]));
  const b = new Map(after.map((r) => [key(r), r]));
  const added = [];
  const removed = [];
  const status = [];
  const declarations = [];
  const endpoints = [];
  for (const [k, r] of b) {
    const old = a.get(k);
    if (!old) {
      added.push(k);
      continue;
    }
    if (old.status !== r.status) status.push({ name: k, from: old.status, to: r.status });
    const env = (x) => JSON.stringify(x.packages.map((p) => [p.type, p.id, p.env.map((e) => e.name).sort()]));
    if (env(old) !== env(r)) declarations.push({ name: k, from: old.version, to: r.version });
    const eps = (x) => JSON.stringify(x.remotes.map((e) => e.url).sort());
    if (eps(old) !== eps(r)) endpoints.push({ name: k, from: old.remotes.map((e) => e.url), to: r.remotes.map((e) => e.url) });
  }
  for (const k of a.keys()) if (!b.has(k)) removed.push(k);
  return { added, removed, status, declarations, endpoints };
}

/* ---------- hosted tools, a rotating slice ---------- */

/**
 * Probe a slice of hosted endpoints, rotating daily so every endpoint comes round. At most
 * one request stream per host at a time, a few hosts in parallel: polite by construction.
 */
async function toolsSlice(listings, n) {
  const endpoints = [...new Set(listings.flatMap((l) => l.remotes.map((r) => r.url)).filter((u) => u && !/\{/.test(u)))].sort();
  if (!endpoints.length || n <= 0) return { rows: [], total: endpoints.length };
  const day = Math.floor(Date.now() / 86400000);
  const start = (day * n) % endpoints.length;
  const slice = Array.from({ length: Math.min(n, endpoints.length) }, (_, i) => endpoints[(start + i) % endpoints.length]);
  const byHost = new Map();
  for (const url of slice) {
    const h = new URL(url).host;
    if (!byHost.has(h)) byHost.set(h, []);
    byHost.get(h).push(url);
  }
  const queues = [...byHost.values()];
  const rows = [];
  const worker = async () => {
    for (let q = queues.shift(); q; q = queues.shift()) {
      for (const url of q) {
        const at = new Date().toISOString();
        try {
          const r = await inspectRemote(url, { timeoutMs: 10000, auth: false });
          const row = { url, at, probed: r.remote.probed, reason: r.remote.reason ?? null, era: r.remote.era ?? null, protocolVersion: r.remote.protocolVersion ?? null };
          if (r.remote.probed) row.tools = await fingerprintTools(r.tools);
          rows.push(row);
        } catch (err) {
          rows.push({ url, at, probed: false, reason: 'error', error: String(err.message).slice(0, 120) });
        }
      }
    }
  };
  await Promise.all(Array.from({ length: 8 }, worker));
  return { rows, total: endpoints.length };
}

/* ---------- commands ---------- */

function writeGz(path, rows) {
  const bytes = gzipSync(Buffer.from(`${rows.map((r) => JSON.stringify(r)).join('\n')}\n`), { level: 9 });
  writeFileSync(path, bytes);
  return { file: path.slice(ARCHIVE.length + 1), sha256: sha256(bytes), bytes: bytes.length, count: rows.length };
}

async function take() {
  mkdirSync(join(ARCHIVE, 'registry'), { recursive: true });
  mkdirSync(join(ARCHIVE, 'tools'), { recursive: true });
  const target = join(ARCHIVE, 'registry', `${today}.jsonl.gz`);
  if (existsSync(target)) {
    log(`snapshot for ${today} already exists; nothing to do`);
    return;
  }
  const t0 = Date.now();
  const { listings, pages } = await walkRegistry();
  listings.sort((x, y) => String(x.name).localeCompare(String(y.name)));
  const files = [writeGz(target, listings)];

  const prev = previousSnapshot();
  let summary = 'first snapshot';
  if (prev) {
    const d = diffSnapshots(prev.rows, listings);
    const diffBytes = Buffer.from(`${JSON.stringify({ since: prev.date, ...d }, null, 1)}\n`);
    const diffPath = join(ARCHIVE, 'registry', `${today}.diff.json`);
    writeFileSync(diffPath, diffBytes);
    files.push({ file: diffPath.slice(ARCHIVE.length + 1), sha256: sha256(diffBytes), bytes: diffBytes.length, count: null });
    summary = `since ${prev.date}: +${d.added.length} -${d.removed.length} listings, ${d.status.length} status, ${d.declarations.length} declaration, ${d.endpoints.length} endpoint changes`;
  }

  const n = Number(flag('--tools', 500));
  const tools = await toolsSlice(listings, n);
  if (tools.rows.length) files.push(writeGz(join(ARCHIVE, 'tools', `${today}.jsonl.gz`), tools.rows));

  appendChain({ date: today, took: Math.round((Date.now() - t0) / 1000), pages, listings: listings.length, endpoints: tools.total, probed: tools.rows.filter((r) => r.probed).length, files });
  log(`snapshot ${today}: ${listings.length} listings (${pages} pages), ${summary}; tools for ${tools.rows.length} of ${tools.total} endpoints (${tools.rows.filter((r) => r.probed).length} answered); ${Math.round((Date.now() - t0) / 1000)} s`);
}

function status() {
  const chain = readChain();
  if (!chain.length) {
    console.log(`no snapshots yet in ${ARCHIVE}`);
    process.exitCode = 1;
    return;
  }
  for (const { entry: e } of chain.slice(-7)) {
    console.log(`${e.date}  ${String(e.listings).padStart(6)} listings  ${String(e.probed ?? 0).padStart(4)}/${e.endpoints ?? 0} endpoints answered  ${e.took}s  ${e.files.map((f) => `${f.file} ${Math.round(f.bytes / 1024)}kB`).join(', ')}`);
  }
  const last = chain.at(-1).entry.date;
  const ageH = (Date.now() - Date.parse(`${last}T00:00:00Z`)) / 3600000;
  if (ageH > 48) {
    console.log(`STALE: the last snapshot is from ${last} (${Math.round(ageH)} h ago). Check: systemctl --user status mcpscan-snapshot.timer`);
    process.exitCode = 1;
  } else console.log(`ok: ${chain.length} snapshot(s), last ${last}`);
}

function verify() {
  const chain = readChain();
  let ok = true;
  chain.forEach(({ entry }, i) => {
    const expected = i ? sha256(chain[i - 1].line) : null;
    if (entry.prev !== expected) {
      ok = false;
      console.log(`BROKEN CHAIN at ${entry.date}: prev does not match the line before`);
    }
    for (const f of entry.files) {
      const p = join(ARCHIVE, f.file);
      if (!existsSync(p)) {
        ok = false;
        console.log(`MISSING ${f.file}`);
      } else if (sha256(readFileSync(p)) !== f.sha256) {
        ok = false;
        console.log(`ALTERED ${f.file}`);
      }
    }
  });
  console.log(ok ? `verified: ${chain.length} snapshot(s), every file and link intact` : 'verification FAILED');
  process.exitCode = ok ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (args.includes('--status')) status();
  else if (args.includes('--verify')) verify();
  else take().catch((err) => {
    log(`snapshot FAILED: ${err.message}`);
    process.exitCode = 1;
  });
}

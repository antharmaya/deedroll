#!/usr/bin/env node
/**
 * Build the MCP ledger from the daily archive (scripts/snapshot.js): a timeline per server,
 * a search index, and 64 shards the Worker serves at /api/servers.
 *
 *   node scripts/build-ledger.js                 fold any new snapshot days into the saved state
 *   node scripts/build-ledger.js --rebuild       replay every snapshot from scratch
 *   node scripts/build-ledger.js --upload [bkt]  then publish changed files to R2 (ledger/...)
 *
 * The snapshots are the source of truth; this is a view of them. --rebuild must always give
 * the same result as the nightly fold (test/ledger.test.js holds it to that).
 */
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { isCredentialName } from '../src/checks.js';
import { emptyLedger, foldDay, foldProbes, foldScans, toShards, fromShards, publicRecord, indexEntry, searchFiles, SHARDS, LEDGER_VERSION } from '../src/ledger.js';

const ARCHIVE = resolve(process.env.DEEDROLL_ARCHIVE ?? new URL('../archive', import.meta.url).pathname);
const STATE = join(ARCHIVE, 'ledger', 'state');
const PUBLIC = join(ARCHIVE, 'ledger', 'public');
const args = process.argv.slice(2);
const log = (...a) => console.log(new Date().toISOString(), 'ledger:', ...a);

const readGzLines = (path) => gunzipSync(readFileSync(path)).toString('utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const writeAtomic = (path, text) => {
  writeFileSync(`${path}.tmp`, text);
  renameSync(`${path}.tmp`, path);
};
const days = () => readdirSync(join(ARCHIVE, 'registry')).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl\.gz$/.test(f)).map((f) => f.slice(0, 10)).sort();

/**
 * A fingerprint of the code that decides what a fact is. Found live 2026-10-01: a credential-
 * rule fix applied only to scans folded after it, so the saved state kept 18 stale verdicts
 * until a manual --rebuild. When this changes, the next run rebuilds from the snapshots (~4 s).
 */
const RULES_HASH = createHash('sha256')
  .update(readFileSync(new URL('../src/checks.js', import.meta.url)))
  .update(readFileSync(new URL('../src/ledger.js', import.meta.url)))
  .digest('hex').slice(0, 16);

function loadState() {
  const metaPath = join(STATE, 'meta.json');
  if (args.includes('--rebuild') || !existsSync(metaPath)) return emptyLedger();
  const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
  if (meta.version !== LEDGER_VERSION) return emptyLedger(); // a new format replays from the snapshots
  if (meta.rules !== RULES_HASH) {
    log('the rules changed since the last build: rebuilding from the snapshots');
    return emptyLedger();
  }
  const shards = readdirSync(STATE).filter((f) => /^[0-9a-f]{2}\.json$/.test(f)).map((f) => JSON.parse(readFileSync(join(STATE, f), 'utf8')));
  return fromShards(meta, shards);
}

/** Package scans (scripts/scan-packages.js), oldest first. */
function scans() {
  const path = join(ARCHIVE, 'scans', 'packages.jsonl');
  if (!existsSync(path)) return [];
  // The credential rule is re-applied here, not trusted from scan time: a fix to the rule then
  // reaches every past scan without re-scanning (as build-web-data does for the sample).
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    .map((x) => (x.reads ? { ...x, reads: x.reads.map((r) => ({ ...r, cred: isCredentialName(r.n) })) } : x))
    .sort((a, b) => a.at.localeCompare(b.at));
}

function build() {
  const ledger = loadState();
  const todo = days().filter((d) => !ledger.last || d > ledger.last);
  const pending = scans().filter((x) => x.at > ledger.scansThrough);
  // One order for both modes: each day's snapshot, then the scans made that day. A rebuild and
  // the nightly fold walk the same sequence, so they give the same ledger.
  const scanDays = new Map();
  for (const x of pending) {
    const d = x.at.slice(0, 10);
    if (!scanDays.has(d)) scanDays.set(d, []);
    scanDays.get(d).push(x);
  }
  for (const d of [...new Set([...todo, ...scanDays.keys()])].sort()) {
    if (todo.includes(d)) {
      foldDay(ledger, d, readGzLines(join(ARCHIVE, 'registry', `${d}.jsonl.gz`)));
      const tools = join(ARCHIVE, 'tools', `${d}.jsonl.gz`);
      if (existsSync(tools)) foldProbes(ledger, d, readGzLines(tools));
      log(`folded ${d}: ${ledger.servers.size} servers`);
    }
    // A scan waits until its own day's snapshot is folded: matched against an older day's
    // listings it would find no package version and be skipped for good.
    if (scanDays.has(d) && ledger.last && d <= ledger.last) {
      foldScans(ledger, d, scanDays.get(d));
      ledger.scansThrough = scanDays.get(d).at(-1).at;
      log(`folded ${scanDays.get(d).length} package scans from ${d}`);
    }
  }
  if (!todo.length && !pending.length) log(`nothing new (last ${ledger.last})`);

  mkdirSync(STATE, { recursive: true });
  mkdirSync(join(PUBLIC, 'servers'), { recursive: true });
  const shards = toShards(ledger);
  for (let i = 0; i < SHARDS; i++) {
    const k = i.toString(16).padStart(2, '0');
    const recs = shards.get(k) ?? {};
    writeAtomic(join(STATE, `${k}.json`), JSON.stringify({ servers: recs }));
    writeAtomic(join(PUBLIC, 'servers', `${k}.json`), JSON.stringify({ version: LEDGER_VERSION, shard: k, servers: Object.fromEntries(Object.entries(recs).map(([n, r]) => [n, publicRecord(r)])) }));
  }
  const meta = { version: LEDGER_VERSION, start: ledger.start, last: ledger.last, servers: ledger.servers.size, shards: SHARDS, builtAt: new Date().toISOString() };
  const index = { ...meta, entries: [...ledger.servers.values()].map(indexEntry).sort((a, b) => a.n.localeCompare(b.n)) };
  writeAtomic(join(PUBLIC, 'index.json'), JSON.stringify(index));
  // What the Worker searches (see searchFiles in src/ledger.js for why three texts, not one).
  const search = searchFiles(index.entries, meta.builtAt);
  writeAtomic(join(PUBLIC, 'search-names.txt'), search.names);
  writeAtomic(join(PUBLIC, 'search-descs.txt'), search.descs);
  writeAtomic(join(PUBLIC, 'search-entries.txt'), search.entries);
  writeAtomic(join(PUBLIC, 'meta.json'), JSON.stringify(meta));
  // Written last: if a run dies before this line, the next run re-folds the day, which is a no-op.
  writeAtomic(join(STATE, 'meta.json'), JSON.stringify({ version: LEDGER_VERSION, start: ledger.start, last: ledger.last, scansThrough: ledger.scansThrough, rules: RULES_HASH }));
  log(`wrote ${SHARDS} shards and the index (${index.entries.length} servers, record ${ledger.start} → ${ledger.last})`);
}

/** Publish public files whose content changed since the last upload, one wrangler call each. */
function upload(bucket) {
  const statePath = join(ARCHIVE, 'ledger', 'uploaded.json');
  const done = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {};
  const files = ['meta.json', 'index.json', 'search-names.txt', 'search-descs.txt', 'search-entries.txt', ...readdirSync(join(PUBLIC, 'servers')).filter((f) => f.endsWith('.json')).map((f) => `servers/${f}`)];
  let sent = 0;
  for (const f of files.reverse()) { // meta last, so it never points at shards not yet uploaded
    const path = join(PUBLIC, f);
    const hash = createHash('sha256').update(readFileSync(path)).digest('hex');
    if (done[f] === hash) continue;
    const type = f.endsWith('.txt') ? 'text/plain; charset=utf-8' : 'application/json';
    execFileSync('npx', ['--yes', 'wrangler@4', 'r2', 'object', 'put', `${bucket}/ledger/${f}`, '--file', path, '--content-type', type, '--remote'], { stdio: ['ignore', 'ignore', 'pipe'], timeout: 180000 });
    done[f] = hash;
    writeAtomic(statePath, JSON.stringify(done, null, 1));
    sent++;
  }
  log(`uploaded ${sent} of ${files.length} files to ${bucket}/ledger/`);
}

build();
if (args.includes('--upload')) {
  const i = args.indexOf('--upload');
  const bucket = process.env.DEEDROLL_R2_BUCKET ?? (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : null);
  if (!bucket) {
    console.error('set DEEDROLL_R2_BUCKET, or pass the bucket: --upload mcpscan-history');
    process.exit(2);
  }
  upload(bucket);
}

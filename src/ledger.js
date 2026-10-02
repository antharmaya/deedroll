/**
 * The ledger: a git-like timeline for every MCP server, folded from the daily registry
 * snapshots and the hosted-tool probes (scripts/snapshot.js).
 *
 * Pure and environment-free, so the nightly build (Node) and the Worker serving the API share
 * one definition. The snapshots stay the source of truth: everything here can be rebuilt from
 * them, which is why the storage underneath is cheap to change (cofounder plan v2, appendix).
 */

export const LEDGER_VERSION = 1;
export const SHARDS = 64;

/** FNV-1a, 32-bit: a stable, synchronous shard key. Not security-relevant, only placement. */
export function shardOf(name) {
  let h = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return (h % SHARDS).toString(16).padStart(2, '0');
}

const pkgKey = (p) => `${p.type}:${p.id}`;
const sorted = (xs) => [...xs].sort();
const minus = (a, b) => a.filter((x) => !b.includes(x));

/**
 * What changed in one listing between two days, as a list of plain facts. Empty when nothing
 * a reader would care about changed (fields like updatedAt alone are not a change).
 */
export function diffListing(prev, cur) {
  const changes = [];
  for (const field of ['version', 'description', 'status', 'repository']) {
    if ((prev[field] ?? null) !== (cur[field] ?? null)) changes.push({ field, from: prev[field] ?? null, to: cur[field] ?? null });
  }

  const pa = new Map((prev.packages ?? []).map((p) => [pkgKey(p), p]));
  const pb = new Map((cur.packages ?? []).map((p) => [pkgKey(p), p]));
  const addedPkgs = minus(sorted(pb.keys()), [...pa.keys()]);
  const removedPkgs = minus(sorted(pa.keys()), [...pb.keys()]);
  if (addedPkgs.length || removedPkgs.length) changes.push({ field: 'packages', added: addedPkgs, removed: removedPkgs });
  for (const [k, p] of pb) {
    const old = pa.get(k);
    if (!old) continue;
    const names = (x) => sorted((x.env ?? []).map((e) => e.name));
    const secrets = (x) => sorted((x.env ?? []).filter((e) => e.secret).map((e) => e.name));
    const added = minus(names(p), names(old));
    const removed = minus(names(old), names(p));
    const nowSecret = minus(secrets(p), secrets(old)).filter((n) => !added.includes(n));
    const noLongerSecret = minus(secrets(old), secrets(p)).filter((n) => !removed.includes(n));
    if (added.length || removed.length || nowSecret.length || noLongerSecret.length) {
      changes.push({ field: 'settings', package: k, added, removed, ...(nowSecret.length ? { nowSecret } : {}), ...(noLongerSecret.length ? { noLongerSecret } : {}) });
    }
  }

  const urls = (x) => sorted((x.remotes ?? []).map((r) => r.url));
  const addedUrls = minus(urls(cur), urls(prev));
  const removedUrls = minus(urls(prev), urls(cur));
  if (addedUrls.length || removedUrls.length) changes.push({ field: 'endpoints', added: addedUrls, removed: removedUrls });
  const ra = new Map((prev.remotes ?? []).map((r) => [r.url, r]));
  for (const r of cur.remotes ?? []) {
    const old = ra.get(r.url);
    if (!old) continue;
    const added = minus(sorted(r.headers ?? []), old.headers ?? []);
    const removed = minus(sorted(old.headers ?? []), r.headers ?? []);
    if (added.length || removed.length) changes.push({ field: 'headers', url: r.url, added, removed });
  }
  return changes;
}

/** A fresh ledger state: one record per server name ever seen. */
export function emptyLedger() {
  return { version: LEDGER_VERSION, start: null, last: null, scansThrough: '', servers: new Map() };
}

/**
 * Fold one day's full registry snapshot into the ledger. Days must arrive in order; a day
 * already folded is ignored, so re-running a night is harmless.
 */
export function foldDay(ledger, date, listings) {
  if (ledger.last && date <= ledger.last) return ledger;
  const seen = new Set();
  for (const cur of listings) {
    if (!cur?.name) continue;
    seen.add(cur.name);
    const rec = ledger.servers.get(cur.name);
    if (!rec) {
      // "seen" is when the ledger first saw it, not when it was published: the record began
      // on ledger.start, and a listing present that day may be much older (publishedAt says).
      ledger.servers.set(cur.name, { name: cur.name, firstSeen: date, lastSeen: date, gone: null, latest: cur, probes: {}, log: [{ date, kind: 'seen', version: cur.version ?? null }] });
      continue;
    }
    if (rec.gone) {
      rec.log.push({ date, kind: 'back', version: cur.version ?? null });
      rec.gone = null;
    }
    const changes = diffListing(rec.latest, cur);
    if (changes.length) rec.log.push({ date, kind: 'changed', changes });
    rec.latest = cur;
    rec.lastSeen = date;
  }
  for (const rec of ledger.servers.values()) {
    if (!rec.gone && !seen.has(rec.name)) {
      rec.gone = date;
      rec.log.push({ date, kind: 'gone' });
    }
  }
  ledger.start ??= date;
  ledger.last = date;
  return ledger;
}

/**
 * Fold one day's hosted-tool probes. A probe enters the log only when its result differs from
 * the last one for that endpoint: first probe, reachable or not, tool set or text changed.
 */
export function foldProbes(ledger, date, rows) {
  const byUrl = new Map();
  for (const rec of ledger.servers.values()) for (const r of rec.latest.remotes ?? []) {
    if (!byUrl.has(r.url)) byUrl.set(r.url, []);
    byUrl.get(r.url).push(rec);
  }
  for (const row of rows) {
    const summary = {
      date,
      probed: Boolean(row.probed),
      reason: row.reason ?? null,
      tools: row.tools ? Object.keys(row.tools).length : null,
      fingerprint: row.tools ?? null,
    };
    for (const rec of byUrl.get(row.url) ?? []) {
      const prev = rec.probes[row.url];
      const entry = probeChange(prev, summary);
      if (entry) rec.log.push({ date, kind: 'probe', url: row.url, ...entry });
      rec.probes[row.url] = summary;
    }
  }
  return ledger;
}

function probeChange(prev, cur) {
  if (!prev) return { probed: cur.probed, reason: cur.reason, tools: cur.tools, first: true };
  if (prev.probed !== cur.probed || prev.reason !== cur.reason) return { probed: cur.probed, reason: cur.reason, tools: cur.tools };
  if (!cur.fingerprint || !prev.fingerprint) return null;
  const a = prev.fingerprint, b = cur.fingerprint;
  const added = Object.keys(b).filter((t) => !(t in a)).sort();
  const removed = Object.keys(a).filter((t) => !(t in b)).sort();
  const described = Object.keys(b).filter((t) => t in a && a[t].description !== b[t].description).sort();
  const reshaped = Object.keys(b).filter((t) => t in a && a[t].schema !== b[t].schema).sort();
  if (!added.length && !removed.length && !described.length && !reshaped.length) return null;
  return { probed: true, reason: null, tools: cur.tools, added, removed, descriptionChanged: described, inputsChanged: reshaped };
}

/** The key of one package version, shared by the batch scanner and the ledger. */
export const packageKey = (type, id, version) => `${type}:${id}@${version ?? 'latest'}`;

/**
 * What one package's scan means for one listing: its reads are judged against what *that*
 * listing declares (two listings can ship the same package and declare it differently).
 */
export function signalOf(summary, listingPkg) {
  if (summary.error) {
    // A listing that names a package or version its registry doesn't have is a fact worth
    // keeping: installing from that listing fails, and an unclaimed name can be registered by
    // anyone. Recorded as what was observed, nothing more.
    const missing = /not found|has no release|not in this registry|\b404\b/i.test(summary.error);
    return { version: summary.version ?? null, scanned: summary.at.slice(0, 10), error: summary.error, ...(missing ? { missing: true } : {}) };
  }
  const declared = new Set((listingPkg.env ?? []).map((e) => e.name));
  // A name seen only inside a string (example code, instructions text) is not a read.
  const reads = summary.reads.filter((r) => !r.txt && !declared.has(r.n));
  return {
    version: summary.version,
    scanned: summary.at.slice(0, 10),
    undeclared: reads.filter((r) => r.cred && !r.doc).map((r) => ({ n: r.n, at: r.at })),
    readmeOnly: reads.filter((r) => r.cred && r.doc).map((r) => r.n),
    settings: reads.filter((r) => !r.cred).map((r) => r.n),
    hosts: summary.hosts,
    caps: summary.caps,
    install: summary.install,
    vulns: summary.vulns.length,
    provenance: summary.provenance,
    flags: [...new Set((summary.other ?? []).map((o) => o.c).filter((c) => FLAG_CHECKS.includes(c)))].sort(),
    files: summary.files,
  };
}

/**
 * Package-level findings worth carrying into the ledger: a tool description that instructs the
 * AI, a name like an official server's, a release that stopped publishing with provenance (the
 * pattern a stolen publish token leaves), a publisher mismatch, a deprecated version.
 */
const FLAG_CHECKS = ['instruction-like-text', 'typosquat', 'provenance-dropped', 'publisher-mismatch', 'deprecated'];

function signalChange(prev, cur) {
  if (cur.error) return null;
  if (!prev || prev.error) return { first: true, undeclared: cur.undeclared.map((r) => r.n), readmeOnly: cur.readmeOnly, hosts: cur.hosts.length, caps: cur.caps, install: cur.install.length, vulns: cur.vulns, flags: cur.flags };
  const diff = (a, b) => ({ added: b.filter((x) => !a.includes(x)).sort(), removed: a.filter((x) => !b.includes(x)).sort() });
  const out = {};
  const sets = {
    undeclared: [prev.undeclared.map((r) => r.n), cur.undeclared.map((r) => r.n)],
    readmeOnly: [prev.readmeOnly, cur.readmeOnly],
    hosts: [prev.hosts, cur.hosts],
    caps: [prev.caps, cur.caps],
    install: [prev.install, cur.install],
    flags: [prev.flags ?? [], cur.flags ?? []],
  };
  for (const [k, [a, b]] of Object.entries(sets)) {
    const d = diff(a, b);
    if (d.added.length || d.removed.length) out[k] = d;
  }
  if (prev.vulns !== cur.vulns) out.vulns = { from: prev.vulns, to: cur.vulns };
  if (prev.provenance !== cur.provenance) out.provenance = { from: prev.provenance, to: cur.provenance };
  return Object.keys(out).length ? out : null;
}

/**
 * Same-day scan entries are kept in package order, so a day folded in one batch or several
 * (the nightly build folds scans as they arrive) gives the same log as a full rebuild.
 */
function insertScanned(log, entry) {
  let i = log.length;
  while (i > 0 && log[i - 1].kind === 'scanned' && log[i - 1].date === entry.date && log[i - 1].package > entry.package) i--;
  log.splice(i, 0, entry);
}

/**
 * Fold package scans (scripts/scan-packages.js) into every server that ships the scanned
 * package version. A 'scanned' entry is logged on the first scan and whenever the facts
 * change: a release that starts reading a credential, contacting a host, running an
 * install script. A new version with identical facts adds nothing (its release is already
 * logged by 'changed').
 */
export function foldScans(ledger, date, summaries) {
  if (!summaries.length) return ledger;
  const byKey = new Map(summaries.map((x) => [x.key, x]));
  for (const rec of ledger.servers.values()) {
    if (rec.gone) continue;
    for (const p of rec.latest.packages ?? []) {
      const s = byKey.get(packageKey(p.type, p.id, p.version));
      if (!s) continue;
      const id = `${p.type}:${p.id}`;
      const cur = signalOf(s, p);
      rec.signals ??= {};
      const entry = signalChange(rec.signals[id], cur);
      if (entry) insertScanned(rec.log, { date, kind: 'scanned', package: id, version: cur.version, ...entry });
      rec.signals[id] = cur;
    }
  }
  return ledger;
}

/** A record as published: probes keep their latest summary only, without the fingerprint. */
export function publicRecord(rec) {
  const probes = Object.fromEntries(Object.entries(rec.probes).map(([url, p]) => [url, { date: p.date, probed: p.probed, reason: p.reason, tools: p.tools }]));
  return { name: rec.name, firstSeen: rec.firstSeen, lastSeen: rec.lastSeen, gone: rec.gone, latest: rec.latest, signals: rec.signals ?? {}, probes, log: rec.log };
}

/** One line of the search index: enough to list and filter, nothing more. */
export function indexEntry(rec) {
  const l = rec.latest;
  const last = rec.log.at(-1);
  return {
    n: rec.name,
    d: (l.description ?? '').slice(0, 140),
    v: l.version ?? null,
    p: [...new Set((l.packages ?? []).map((p) => p.type))],
    h: (l.remotes ?? []).length > 0,
    s: l.status ?? null,
    c: last?.date ?? rec.firstSeen,
    g: rec.gone,
    x: Object.values(rec.signals ?? {}).reduce((n, sig) => n + (sig.undeclared?.length ?? 0), 0),
    m: Object.values(rec.signals ?? {}).some((sig) => sig.missing),
  };
}

/** Search the index: exact name, then name prefix, then name contains, then description. */
export function searchIndex(entries, q, limit = 25) {
  const needle = String(q ?? '').trim().toLowerCase();
  if (!needle) return [];
  const scored = [];
  for (const e of entries) {
    const n = e.n.toLowerCase();
    const rank = n === needle ? 0 : n.startsWith(needle) || n.split('/').pop().startsWith(needle) ? 1 : n.includes(needle) ? 2 : (e.d ?? '').toLowerCase().includes(needle) ? 3 : -1;
    if (rank >= 0) scored.push([rank, e]);
  }
  scored.sort((a, b) => a[0] - b[0] || (a[1].g ? 1 : 0) - (b[1].g ? 1 : 0) || a[1].n.localeCompare(b[1].n));
  return scored.slice(0, limit).map(([, e]) => e);
}

/**
 * The search store: three parallel texts, one line per server, in index order.
 * - names: lowercased registry names (ASCII, about 1 MB), searched first;
 * - descs: lowercased descriptions folded to ASCII, searched only to fill remaining slots;
 * - entries: the index entries as JSON lines, sliced, never parsed whole.
 * Kept apart and ASCII because a single string holding any non-Latin text is stored two bytes
 * per character, which made every indexOf pass over the old combined 11 MB text ~5 ms.
 * The tradeoff: words in non-Latin scripts inside descriptions are not searchable.
 */
const fold = (s) => s.toLowerCase().replace(/[^\x20-\x7e]/g, ' ');
export function searchFiles(entries, stamp = 'unstamped') {
  // Line 0 of every file is the build stamp: files are uploaded one at a time, so a reader must
  // only combine three files whose stamps match, or line N would name different servers.
  const wrap = (lines) => `\n#${stamp}\n${lines.join('\n')}\n`;
  return {
    names: wrap(entries.map((e) => fold(e.n))),
    descs: wrap(entries.map((e) => fold(e.d ?? ''))),
    entries: wrap(entries.map((e) => JSON.stringify(e))),
  };
}

function lineStarts(text) {
  const starts = [];
  for (let i = text.indexOf('\n'); i !== -1 && i < text.length - 1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return Int32Array.from(starts);
}

/** Index the three texts once (a Worker does this per isolate, not per request). */
export function searchStore({ names, descs, entries }) {
  const stamp = (t) => t.slice(1, t.indexOf('\n', 1));
  const stamps = new Set([stamp(names), stamp(descs), stamp(entries)]);
  if (stamps.size !== 1) return null; // mid-upload: the caller keeps its previous store
  return { stamp: [...stamps][0].slice(1), names, descs, entries, nameStarts: lineStarts(names), descStarts: lineStarts(descs), entryStarts: lineStarts(entries) };
}

function lineOf(starts, offset) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid; else hi = mid - 1;
  }
  return lo;
}

const lineText = (text, starts, i) => text.slice(starts[i], text.indexOf('\n', starts[i]));

/** Same order as searchIndex, over the search store. */
export function searchLedger(store, q, limit = 25) {
  const needle = fold(String(q ?? '').trim());
  if (!needle.trim() || needle.includes('\n')) return [];
  const picked = new Map(); // line -> rank
  const scanNames = (pattern, offset, cap) => {
    let n = 0;
    for (let i = store.names.indexOf(pattern); i !== -1 && n < cap; i = store.names.indexOf(pattern, i + 1)) {
      const line = lineOf(store.nameStarts, i + offset);
      if (line === 0 || picked.has(line)) continue;
      const name = lineText(store.names, store.nameStarts, line);
      const rank = name === needle ? 0 : name.startsWith(needle) || name.split('/').pop().startsWith(needle) ? 1 : 2;
      picked.set(line, rank);
      n++;
    }
  };
  scanNames(`\n${needle}\n`, 1, 1);
  scanNames(`\n${needle}`, 1, limit * 4);
  scanNames(`/${needle}`, 0, limit * 4);
  scanNames(needle, 0, limit * 8);
  if (picked.size < limit) {
    let n = 0;
    for (let i = store.descs.indexOf(needle); i !== -1 && n < limit * 4; i = store.descs.indexOf(needle, i + 1)) {
      const line = lineOf(store.descStarts, i);
      if (line !== 0 && !picked.has(line)) { picked.set(line, 3); n++; }
    }
  }
  return [...picked.entries()]
    .map(([line, rank]) => [rank, JSON.parse(lineText(store.entries, store.entryStarts, line))])
    .sort((a, b) => a[0] - b[0] || (a[1].g ? 1 : 0) - (b[1].g ? 1 : 0) || a[1].n.localeCompare(b[1].n))
    .slice(0, limit)
    .map(([, e]) => e);
}

/** Serialise and restore a ledger (the nightly build keeps its state between runs). */
export function toShards(ledger) {
  const shards = new Map();
  for (const rec of ledger.servers.values()) {
    const k = shardOf(rec.name);
    if (!shards.has(k)) shards.set(k, {});
    shards.get(k)[rec.name] = rec;
  }
  return shards;
}

export function fromShards(meta, shardObjects) {
  const ledger = { version: meta.version, start: meta.start, last: meta.last, scansThrough: meta.scansThrough ?? '', servers: new Map() };
  for (const obj of shardObjects) for (const [name, rec] of Object.entries(obj.servers ?? obj)) ledger.servers.set(name, rec);
  return ledger;
}

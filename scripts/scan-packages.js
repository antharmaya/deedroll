#!/usr/bin/env node
/**
 * Scan every distinct npm and PyPI package the MCP registry points at, once per version,
 * without running any of it. Feeds the ledger's per-server signals (src/ledger.js).
 *
 *   node scripts/scan-packages.js [--limit 1500] [--concurrency 6]
 *
 * Reads the newest registry snapshot. A package is scanned on its own (no listing), so what
 * is stored is package fact: what its code reads, contacts and can do, install scripts,
 * provenance, known vulnerabilities. Whether a read is *declared* is a property of each
 * listing, and the ledger works it out from these facts plus that listing's declarations.
 *
 * Order each night: new versions of packages already scanned (that is where changes are
 * caught), then packages never scanned, then failures older than a week. One line per scan is
 * appended to archive/scans/packages.jsonl; the newest line per package version wins.
 */
import { readFileSync, readdirSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { scan } from '../src/index.js';
import { isCredentialName } from '../src/checks.js';
import { packageKey } from '../src/ledger.js';

const ARCHIVE = resolve(process.env.DEEDROLL_ARCHIVE ?? new URL('../archive', import.meta.url).pathname);
const OUT = join(ARCHIVE, 'scans', 'packages.jsonl');
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? Number(args[i + 1]) : dflt;
};
const LIMIT = opt('--limit', 1500);
const CONCURRENCY = opt('--concurrency', 6);
const RETRY_AFTER_DAYS = 7;
const log = (...a) => console.log(new Date().toISOString(), 'scan-packages:', ...a);
// The code that decides what a scan reports. A summary made under other rules is stale: the
// ledger re-judges stored facts on every rebuild, but some judgements (is this mention inside a
// string?) can only be made from the source, so those packages are scanned again.
export const SCAN_RULES = createHash('sha256')
  .update(['checks.js', 'docs.js'].map((f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8')).join('\0'))
  .digest('hex').slice(0, 12);
// A batch of ~14,000 packages would add ~2.7 GB of cached tarballs (measured ~190 KB each).
process.env.DEEDROLL_NO_CACHE ??= '1';

/** The facts kept from one scan: compact, and only what a ledger reader needs. */
export function summarize(type, id, requested, r) {
  const f = r.findings;
  const pick = (check) => f.filter((x) => x.check === check);
  const where = (x) => (x.evidence?.[0]?.line ? `${x.evidence[0].file}:${x.evidence[0].line}` : x.evidence?.[0]?.file ?? null);
  return {
    key: packageKey(type, id, requested),
    type,
    id,
    version: r.pkg?.version ?? requested ?? null,
    at: new Date().toISOString(),
    rules: SCAN_RULES,
    files: r.pkg?.files?.size ?? 0,
    integrityOk: r.pkg?.integrityOk ?? null,
    provenance: Boolean(r.pkg?.provenance?.current),
    reads: pick('undeclared-env').map((x) => ({ n: x.subject, cred: isCredentialName(x.subject), doc: Boolean(x.documented), at: where(x), ...(x.inText ? { txt: true } : {}) })),
    dynamicEnv: pick('dynamic-env').length,
    hosts: [...new Set(pick('network-egress').map((x) => x.message.replace(/^contacts /, '')))],
    caps: [...new Set(pick('capability').map((x) => x.message.replace(/^uses /, '')))],
    install: pick('install-script').map((x) => x.message),
    vulns: pick('known-vulnerability').map((x) => ({ s: x.severity, m: x.message })),
    other: f.filter((x) => !['undeclared-env', 'dynamic-env', 'network-egress', 'capability', 'install-script', 'known-vulnerability'].includes(x.check))
      .map((x) => ({ c: x.check, s: x.severity, x: x.subject ?? null })),
  };
}

function latestSnapshot() {
  const dir = join(ARCHIVE, 'registry');
  const f = readdirSync(dir).filter((x) => /^\d{4}-\d{2}-\d{2}\.jsonl\.gz$/.test(x)).sort().at(-1);
  return gunzipSync(readFileSync(join(dir, f))).toString('utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

function loadDone() {
  const done = new Map();
  if (!existsSync(OUT)) return done;
  for (const line of readFileSync(OUT, 'utf8').split('\n')) {
    if (!line) continue;
    const s = JSON.parse(line);
    done.set(s.key, s);
  }
  return done;
}

async function main() {
  mkdirSync(join(ARCHIVE, 'scans'), { recursive: true });
  const done = loadDone();
  const scannedIds = new Set([...done.values()].filter((s) => !s.error).map((s) => `${s.type}:${s.id}`));
  const wanted = new Map();
  for (const l of latestSnapshot()) for (const p of l.packages ?? []) {
    if (p.type !== 'npm' && p.type !== 'pypi') continue;
    wanted.set(packageKey(p.type, p.id, p.version), { type: p.type, id: p.id, version: p.version ?? null });
  }
  const now = Date.now();
  const stale = (s) => s.error && now - Date.parse(s.at) > RETRY_AFTER_DAYS * 86400000;
  const updates = [], fresh = [], retries = [], oldRules = [], oldRulesQuiet = [];
  for (const [key, p] of wanted) {
    const prev = done.get(key);
    if (prev && !prev.error && prev.rules !== SCAN_RULES) {
      // Packages whose stored reads a rule change can alter go first.
      (prev.reads?.some((r) => r.cred && !r.doc) ? oldRules : oldRulesQuiet).push(p);
      continue;
    }
    if (prev && !stale(prev)) continue;
    if (prev) retries.push(p);
    else if (scannedIds.has(`${p.type}:${p.id}`)) updates.push(p);
    else fresh.push(p);
  }
  const queue = [...updates, ...fresh, ...oldRules, ...retries, ...oldRulesQuiet].slice(0, LIMIT);
  log(`${wanted.size} package versions in the registry; ${done.size} already recorded; scanning ${queue.length} (${updates.length} new versions, ${fresh.length} never scanned, ${oldRules.length + oldRulesQuiet.length} under older rules (${oldRules.length} with credential reads), ${retries.length} retries pending)`);

  let ok = 0, failed = 0;
  const worker = async () => {
    for (let p = queue.shift(); p; p = queue.shift()) {
      const target = `${p.type}:${p.id}`;
      try {
        const r = await scan(target, { version: p.version ?? 'latest', lookup: false, osv: true });
        appendFileSync(OUT, `${JSON.stringify(summarize(p.type, p.id, p.version, r))}\n`);
        ok++;
      } catch (err) {
        appendFileSync(OUT, `${JSON.stringify({ key: packageKey(p.type, p.id, p.version), type: p.type, id: p.id, version: p.version, at: new Date().toISOString(), error: String(err.message).slice(0, 160) })}\n`);
        failed++;
      }
      if ((ok + failed) % 100 === 0) log(`${ok + failed} done (${failed} failed)`);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  log(`finished: ${ok} scanned, ${failed} failed`);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();

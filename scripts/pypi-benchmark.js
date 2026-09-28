#!/usr/bin/env node
/**
 * Scan a seeded random sample of PyPI-backed registry listings, by listing name, and
 * report what worked: the adapter's honest coverage, not a showcase.
 * Usage: node scripts/pypi-benchmark.js [n=40] [seed=20260928]
 */
import { scan } from '../src/index.js';
import { loadIndex } from '../src/lookup.js';

const N = Number(process.argv[2] ?? 40);
let seed = Number(process.argv[3] ?? 20260928);
const rand = () => ((seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296);

const index = loadIndex();
const listings = [...new Set(Object.values(index.pypi).map((names) => names[0]))].sort();
for (let i = listings.length - 1; i > 0; i--) {
  const j = Math.floor(rand() * (i + 1));
  [listings[i], listings[j]] = [listings[j], listings[i]];
}

const rows = [];
for (const name of listings.slice(0, N)) {
  const t = Date.now();
  try {
    const r = await scan(name, { osv: true });
    const bySev = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of r.findings) bySev[f.severity]++;
    rows.push({
      name,
      ok: Boolean(r.pkg?.files),
      pkg: r.pkg ? `${r.pkg.name}@${r.pkg.version}` : null,
      ecosystem: r.pkg?.ecosystem ?? 'npm',
      kind: r.pkg?.artifact?.kind ?? null,
      files: r.pkg?.files?.size ?? 0,
      provenance: r.pkg?.provenance?.state ?? null,
      checks: [...new Set(r.findings.filter((f) => f.severity !== 'info').map((f) => `${f.severity}:${f.check}`))],
      bySev,
      ms: Date.now() - t,
    });
  } catch (err) {
    rows.push({ name, ok: false, error: err.message.slice(0, 120), ms: Date.now() - t });
  }
  const r = rows.at(-1);
  process.stderr.write(`${r.ok ? 'ok ' : 'ERR'} ${String(r.ms).padStart(6)}ms ${name} ${r.error ?? `${r.kind} ${r.files} files ${r.checks.join(' ')}`}\n`);
}

const ok = rows.filter((r) => r.ok);
const count = (f) => rows.reduce((m, r) => (f(r) ? m + 1 : m), 0);
console.log(JSON.stringify({
  sampled: rows.length,
  scanned: ok.length,
  readAsPypi: count((r) => r.ecosystem === 'pypi'),
  readAsNpm: count((r) => r.ok && r.ecosystem === 'npm'),
  errors: rows.filter((r) => r.error).map((r) => `${r.name}: ${r.error}`),
  wheel: count((r) => r.kind === 'wheel'),
  sdistOnly: count((r) => r.kind === 'sdist'),
  provenance: { present: count((r) => r.ecosystem === 'pypi' && r.provenance === 'present'), absent: count((r) => r.ecosystem === 'pypi' && r.provenance === 'absent'), unknown: count((r) => r.ecosystem === 'pypi' && r.provenance === 'unknown') },
  withHigh: count((r) => r.bySev?.high > 0),
  undeclaredCredential: count((r) => r.checks?.some((c) => c === 'high:undeclared-env')),
  medianMs: ok.map((r) => r.ms).sort((a, b) => a - b)[Math.floor(ok.length / 2)],
  rows,
}, null, 2));

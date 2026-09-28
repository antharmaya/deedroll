#!/usr/bin/env node
/**
 * Data the web page ships with, generated from real results — never hand-written.
 *   web/data/demo.json             a real scan, replayed on page load (labelled as a replay)
 *   web/data/registry-health.json  the published sample, with the current credential rule
 * Usage: node scripts/build-web-data.js [npm name for the demo]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { scanInBrowser } from '../src/browser.js';
import { isCredentialName } from '../src/checks.js';

const demoName = process.argv[2] ?? 'pretrip-mcp';
const index = readFileSync(new URL('../src/data/registry-index.json', import.meta.url));
const fetchImpl = (u, i) => (u === 'index' ? Promise.resolve(new Response(index)) : fetch(u, i));

const r = await scanInBrowser(demoName, { indexUrl: 'index', fetchImpl });
const demo = {
  scannedAt: new Date().toISOString(),
  package: { name: r.pkg.name, version: r.pkg.version, sha256: r.pkg.sha256, tarballBytes: r.pkg.tarballBytes, provenance: r.pkg.provenance?.current ?? false },
  files: [...r.pkg.files.entries()].map(([path, b]) => ({ path, lines: b.toString().split('\n').length })),
  listing: r.listing.found ? r.entry.server.name : null,
  declared: [...r.declared.keys()],
  findings: r.findings,
};
writeFileSync(new URL('../web/data/demo.json', import.meta.url), `${JSON.stringify(demo, null, 2)}\n`);

const f = JSON.parse(readFileSync(new URL('../findings.json', import.meta.url), 'utf8'));
const ok = f.rows.filter((x) => !x.error);
const rows = ok.map((x) => {
  const secrets = (x.undeclaredSecrets ?? []).filter(isCredentialName);
  return { name: x.name, publisher: x.publisher, flagged: secrets.length > 0, secrets };
});
const k = rows.filter((x) => x.flagged).length;
const n = rows.length;
const z = 1.96, p = k / n, d = 1 + (z * z) / n, c = p + (z * z) / (2 * n), m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
const health = {
  sampledAt: f.scannedAt, seed: f.seed, population: f.populationSize, sampled: f.sampled, scanned: n, flagged: k,
  publishersFlagged: new Set(rows.filter((x) => x.flagged).map((x) => x.publisher)).size,
  interval: [Math.round(((c - m) / d) * 100), Math.round(((c + m) / d) * 100)],
  rows,
};
writeFileSync(new URL('../web/data/registry-health.json', import.meta.url), `${JSON.stringify(health, null, 2)}\n`);
console.log(`demo: ${demo.package.name}@${demo.package.version}, ${demo.files.length} files, ${demo.findings.length} findings, listing ${demo.listing}`);
console.log(`health: ${k}/${n} flagged (${Math.round(p * 100)}%), CI ${health.interval.join('-')}%, ${health.publishersFlagged} publishers`);

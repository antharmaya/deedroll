#!/usr/bin/env node
/**
 * Build the npm-package -> registry-listing index shipped in src/data/.
 *
 * Why it exists: the official registry's `search` matches listing names only, so it
 * cannot answer "which listing ships the npm package pretrip-mcp?" (the answer is
 * agency.kesey/pretrip). This walks every latest listing once and inverts it.
 *
 * Separate from collect-population.js on purpose: that file is the frozen frame the
 * published sample was drawn from, and must not change under it.
 *
 * This is the manual, live walk, for the copy bundled in src/data/ (the npm package and the
 * site fallback). The site itself is served a fresh index every night: scripts/build-ledger.js
 * writes the same shape from the day's snapshot (scripts/ledger-views.js).
 *
 * Usage: node scripts/build-index.js [maxPages]
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { registryIndexOf } from './ledger-views.js';

const MAX_PAGES = Number(process.argv[2] ?? 1000);
const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';

const records = []; // the ledger's record shape, enough for registryIndexOf
let cursor = null;
let pages = 0;

while (pages < MAX_PAGES) {
  const url = new URL(REGISTRY);
  url.searchParams.set('limit', '100');
  url.searchParams.set('version', 'latest'); // skip the thousands of superseded version rows
  if (cursor) url.searchParams.set('cursor', cursor);
  const res = await fetch(url);
  if (!res.ok) {
    process.stderr.write(`\npage ${pages}: ${res.status}; stopping\n`);
    break;
  }
  const body = await res.json();
  for (const s of body.servers ?? []) {
    if (!s.server?.name) continue;
    const packages = (s.server.packages ?? []).map((p) => ({ type: (p.registryType ?? '').toLowerCase(), id: p.identifier }));
    records.push({ name: s.server.name, gone: null, latest: { packages } });
  }
  pages++;
  process.stderr.write(`\rpages ${pages} · listings ${records.length}`);
  cursor = body.metadata?.nextCursor;
  if (!cursor) break;
}
process.stderr.write('\n');

const { listings, index, pypi } = registryIndexOf(records, {});
mkdirSync(new URL('../src/data/', import.meta.url), { recursive: true });
writeFileSync(
  new URL('../src/data/registry-index.json', import.meta.url),
  `${JSON.stringify({ builtAt: new Date().toISOString(), complete: !cursor, listings, index, pypi }, null, 0)}\n`
);
console.log(`listings ${listings} · npm packages ${Object.keys(index).length} · pypi packages ${Object.keys(pypi).length} · ${cursor ? 'INCOMPLETE (page cap)' : 'complete'}`);

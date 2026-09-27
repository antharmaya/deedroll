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
 * Usage: node scripts/build-index.js [maxPages]
 */
import { writeFileSync, mkdirSync } from 'node:fs';

const MAX_PAGES = Number(process.argv[2] ?? 1000);
const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';

const index = {}; // npm identifier -> [registry names]
let cursor = null;
let pages = 0;
let listings = 0;

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
    listings++;
    for (const p of s.server?.packages ?? []) {
      if ((p.registryType ?? '').toLowerCase() !== 'npm' || !p.identifier) continue;
      (index[p.identifier] ??= []).includes(s.server.name) || index[p.identifier].push(s.server.name);
    }
  }
  pages++;
  process.stderr.write(`\rpages ${pages} · listings ${listings} · npm packages ${Object.keys(index).length}`);
  cursor = body.metadata?.nextCursor;
  if (!cursor) break;
}
process.stderr.write('\n');

mkdirSync(new URL('../src/data/', import.meta.url), { recursive: true });
writeFileSync(
  new URL('../src/data/registry-index.json', import.meta.url),
  `${JSON.stringify({ builtAt: new Date().toISOString(), complete: !cursor, listings, index }, null, 0)}\n`
);
console.log(`listings ${listings} · npm packages ${Object.keys(index).length} · ${cursor ? 'INCOMPLETE (page cap)' : 'complete'}`);

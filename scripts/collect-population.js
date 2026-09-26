#!/usr/bin/env node
/**
 * Page through the official MCP registry once and cache every npm-backed server.
 *
 * Kept separate from the sweep so sampling never re-walks the registry, and so the
 * population a sample was drawn from is a file you can point at later.
 *
 * Usage: node scripts/collect-population.js [maxPages]
 */
import { writeFileSync } from 'node:fs';

const MAX_PAGES = Number(process.argv[2] ?? 100);
const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';

const latest = new Map(); // server name -> { name, npm, declaredEnvCount }
let cursor = null;
let pages = 0;
let totalEntries = 0;

while (pages < MAX_PAGES) {
  const url = new URL(REGISTRY);
  url.searchParams.set('limit', '100');
  if (cursor) url.searchParams.set('cursor', cursor);

  const res = await fetch(url);
  if (!res.ok) {
    process.stderr.write(`\npage ${pages}: ${res.status} ${res.statusText}; stopping\n`);
    break;
  }
  const body = await res.json();
  const servers = body.servers ?? [];
  totalEntries += servers.length;

  for (const s of servers) {
    const sv = s.server;
    const npm = (sv.packages ?? []).filter((p) => (p.registryType ?? '').toLowerCase() === 'npm');
    if (npm.length === 0) continue;
    // Registry returns every published version; keep the newest we see per name.
    latest.set(sv.name, {
      name: sv.name,
      npm: npm[0].identifier,
      npmVersion: npm[0].version ?? null,
      declaredEnvCount: npm.reduce((n, p) => n + (p.environmentVariables?.length ?? 0), 0),
      publisher: sv.name.split('/')[0],
    });
  }

  pages++;
  process.stderr.write(`\rpages ${pages} · entries ${totalEntries} · npm-backed servers ${latest.size}`);
  cursor = body.metadata?.nextCursor;
  if (!cursor) break;
}
process.stderr.write('\n');

const population = [...latest.values()];
const publishers = new Set(population.map((p) => p.publisher));
writeFileSync(
  new URL('../population.json', import.meta.url),
  `${JSON.stringify({ collectedAt: new Date().toISOString(), pages, totalEntries, population }, null, 2)}\n`
);

console.log(`
  registry entries walked      ${totalEntries}
  npm-backed servers (unique)  ${population.length}
  distinct publishers          ${publishers.size}
  pages fetched                ${pages}${cursor ? ' (more remain)' : ' (reached the end)'}
`);

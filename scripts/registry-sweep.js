#!/usr/bin/env node
/**
 * Scan a sample of the official MCP registry and tally what the entries declare
 * against what their packages actually read.
 *
 * Usage: node scripts/registry-sweep.js [sampleSize]
 * Writes findings.json next to the summary it prints.
 */
import { writeFileSync } from 'node:fs';
import { scan } from '../src/index.js';

const SAMPLE = Number(process.argv[2] ?? 25);
const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';

async function collectNpmBacked(target) {
  const seen = new Map();
  let cursor = null;
  let pages = 0;
  while (seen.size < target && pages < 20) {
    const url = new URL(REGISTRY);
    url.searchParams.set('limit', '100');
    if (cursor) url.searchParams.set('cursor', cursor);
    const body = await (await fetch(url)).json();
    for (const s of body.servers ?? []) {
      const sv = s.server;
      const npm = (sv.packages ?? []).filter((p) => (p.registryType ?? '').toLowerCase() === 'npm');
      if (npm.length && !seen.has(sv.name)) seen.set(sv.name, sv);
      if (seen.size >= target) break;
    }
    cursor = body.metadata?.nextCursor;
    pages++;
    if (!cursor) break;
  }
  return [...seen.keys()];
}

const names = await collectNpmBacked(SAMPLE);
process.stderr.write(`scanning ${names.length} npm-backed servers\n`);

const rows = [];
for (const name of names) {
  try {
    const r = await scan(name);
    const high = r.findings.filter((f) => f.severity === 'high');
    const undeclaredSecrets = r.findings.filter(
      (f) => f.check === 'undeclared-env' && f.severity === 'high'
    );
    rows.push({
      name,
      pkg: r.pkg ? `${r.pkg.name}@${r.pkg.version}` : null,
      declaredEnvCount: r.declared.size,
      undeclaredSecrets: undeclaredSecrets.map((f) => f.message.match(/reads (\w+)/)?.[1]),
      high: high.length,
      findings: r.findings.length,
    });
    process.stderr.write(undeclaredSecrets.length ? 'X' : '.');
  } catch (err) {
    rows.push({ name, error: err.message });
    process.stderr.write('!');
  }
}
process.stderr.write('\n');

const scanned = rows.filter((r) => !r.error);
const declaresNothing = scanned.filter((r) => r.declaredEnvCount === 0);
const withUndeclaredSecret = scanned.filter((r) => (r.undeclaredSecrets ?? []).length > 0);

writeFileSync(
  new URL('../findings.json', import.meta.url),
  `${JSON.stringify({ scannedAt: new Date().toISOString(), rows }, null, 2)}\n`
);

console.log(`
  MCP registry sample — ${new Date().toISOString().slice(0, 10)}

  servers scanned                       ${scanned.length}
  declare no environment variables      ${declaresNothing.length}
  read a credential they never declare  ${withUndeclaredSecret.length}
  errored                               ${rows.length - scanned.length}
`);
for (const r of withUndeclaredSecret) {
  console.log(`  ${r.name}  →  ${r.undeclaredSecrets.join(', ')}`);
}

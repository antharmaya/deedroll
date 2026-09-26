#!/usr/bin/env node
/**
 * Scan a RANDOM sample of the npm-backed servers cached by collect-population.js
 * and tally declared-vs-actual credential use.
 *
 * Random, because the registry's own order groups a publisher's servers together —
 * an alphabetical sample counted one publisher's 17 near-identical servers as 17
 * independent data points. Publisher-level counts are reported alongside
 * server-level ones for the same reason.
 *
 * Usage: node scripts/registry-sweep.js [sampleSize] [seed]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { scan } from '../src/index.js';

const SAMPLE = Number(process.argv[2] ?? 60);
const SEED = Number(process.argv[3] ?? 20260926);

/** mulberry32 — seeded so a published number can be reproduced exactly. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function sampleWithout(arr, n, random) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, Math.min(n, copy.length));
}

/** Wilson score interval — honest for small samples, unlike normal approximation. */
function wilson(successes, total, z = 1.96) {
  if (total === 0) return [0, 0];
  const p = successes / total;
  const d = 1 + (z * z) / total;
  const centre = p + (z * z) / (2 * total);
  const margin = z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total));
  return [Math.max(0, (centre - margin) / d), Math.min(1, (centre + margin) / d)];
}

const pop = JSON.parse(readFileSync(new URL('../population.json', import.meta.url), 'utf8'));
const chosen = sampleWithout(pop.population, SAMPLE, rng(SEED));
process.stderr.write(`sampling ${chosen.length} of ${pop.population.length} npm-backed servers (seed ${SEED})\n`);

const rows = [];
for (const entry of chosen) {
  try {
    const r = await scan(entry.name);
    const sev = (s) => r.findings.filter((f) => f.severity === s);
    const undeclaredSecrets = r.findings
      .filter((f) => f.check === 'undeclared-env' && f.severity === 'high')
      .map((f) => f.subject)
      .filter(Boolean);
    rows.push({
      name: entry.name,
      publisher: entry.publisher,
      pkg: r.pkg ? `${r.pkg.name}@${r.pkg.version}` : null,
      declaredEnvCount: r.declared.size,
      undeclaredSecrets,
      installScript: r.findings.some((f) => f.check === 'install-script' && f.severity === 'high'),
      noRepository: r.findings.some((f) => f.check === 'provenance' && /repository/.test(f.message)),
      high: sev('high').length,
    });
    process.stderr.write(undeclaredSecrets.length ? 'X' : '.');
  } catch (err) {
    rows.push({ name: entry.name, publisher: entry.publisher, error: err.message });
    process.stderr.write('!');
  }
}
process.stderr.write('\n');

const ok = rows.filter((r) => !r.error);
const pubs = (list) => new Set(list.map((r) => r.publisher)).size;
const declaresNothing = ok.filter((r) => r.declaredEnvCount === 0);
const undeclared = ok.filter((r) => (r.undeclaredSecrets ?? []).length > 0);
const installScripts = ok.filter((r) => r.installScript);
const noRepo = ok.filter((r) => r.noRepository);
const [lo, hi] = wilson(undeclared.length, ok.length);
const pct = (n) => `${((n / ok.length) * 100).toFixed(0)}%`;

writeFileSync(
  new URL('../findings.json', import.meta.url),
  `${JSON.stringify(
    { scannedAt: new Date().toISOString(), seed: SEED, populationSize: pop.population.length, sampled: rows.length, rows },
    null,
    2
  )}\n`
);

console.log(`
  MCP registry — random sample, ${new Date().toISOString().slice(0, 10)}
  population: ${pop.population.length} npm-backed servers (${pop.totalEntries} registry entries walked) · seed ${SEED}

  scanned successfully                  ${ok.length}   across ${pubs(ok)} publishers
  declare no environment variables      ${declaresNothing.length} (${pct(declaresNothing.length)})  ${pubs(declaresNothing)} publishers
  read a credential they never declare  ${undeclared.length} (${pct(undeclared.length)})  ${pubs(undeclared)} publishers
      95% CI                            ${(lo * 100).toFixed(0)}% – ${(hi * 100).toFixed(0)}%
  run an install script                 ${installScripts.length} (${pct(installScripts.length)})
  no repository field                   ${noRepo.length} (${pct(noRepo.length)})
  errored                               ${rows.length - ok.length}
`);

for (const r of undeclared.slice(0, 15)) {
  console.log(`  ${r.name}  →  ${r.undeclaredSecrets.slice(0, 6).join(', ')}${r.undeclaredSecrets.length > 6 ? ` (+${r.undeclaredSecrets.length - 6})` : ''}`);
}

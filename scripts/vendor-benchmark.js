#!/usr/bin/env node
/**
 * Scan the MCP servers that real vendors publish on npm, to find where mcpscan is
 * wrong on production code: false positives, tools it cannot see, packages it chokes on.
 * It grades the scanner, not the vendors. Nothing is installed or run.
 *
 * The list was verified against npm on 2026-09-27 (every name resolves; weekly
 * downloads from api.npmjs.org). Usage: node scripts/vendor-benchmark.js [--deps]
 *
 * --deps also follows each vendor's own dependencies, and records bytes and seconds,
 * so the cost of turning that on by default is measured rather than guessed.
 */
import { writeFileSync } from 'node:fs';
import { scan } from '../src/index.js';
import { extractTools } from '../src/tools.js';

const DEPS = process.argv.includes('--deps');

export const VENDORS = [
  ['Microsoft', '@playwright/mcp'],
  ['Microsoft', '@azure/mcp'],
  ['Stripe', '@stripe/mcp'],
  ['Sentry', '@sentry/mcp-server'],
  ['Supabase', '@supabase/mcp-server-supabase'],
  ['Notion', '@notionhq/notion-mcp-server'],
  ['Cloudflare', '@cloudflare/mcp-server-cloudflare'],
  ['Neon', '@neondatabase/mcp-server-neon'],
  ['MongoDB', 'mongodb-mcp-server'],
  ['Upstash', '@upstash/context7-mcp'],
  ['Firecrawl', 'firecrawl-mcp'],
  ['Exa', 'exa-mcp-server'],
  ['Brave', '@brave/brave-search-mcp-server'],
  ['Browserbase', '@browserbasehq/mcp-server-browserbase'],
  ['HubSpot', '@hubspot/mcp-server'],
  ['Shopify', '@shopify/dev-mcp'],
  ['PayPal', '@paypal/mcp'],
  ['Heroku', '@heroku/mcp-server'],
  ['Netlify', '@netlify/mcp'],
  ['Elastic', '@elastic/mcp-server-elasticsearch'],
  ['Apify', '@apify/actors-mcp-server'],
  ['Pinecone', '@pinecone-database/mcp'],
  ['Twilio', '@twilio-alpha/mcp'],
  ['LaunchDarkly', '@launchdarkly/mcp-server'],
  ['Sanity', '@sanity/mcp-server'],
  ['MCP reference', '@modelcontextprotocol/server-github'],
  ['MCP reference', '@modelcontextprotocol/server-everything'],
];

async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: limit }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    })
  );
  return out;
}

const rows = await pool(VENDORS, 4, async ([vendor, name]) => {
  try {
    const started = Date.now();
    const r = await scan(`npm:${name}`, { deps: DEPS });
    const ms = Date.now() - started;
    const { tools } = extractTools(r.pkg.files); // the scanned files themselves: no second download
    const by = (check) => r.findings.filter((f) => f.check === check);
    const caps = by('capability').map((f) => f.message.replace(/^uses /, ''));
    return {
      vendor,
      name,
      version: r.pkg.version,
      files: r.pkg.files.size,
      tools: tools.length,
      high: r.findings.filter((f) => f.severity === 'high').length,
      medium: r.findings.filter((f) => f.severity === 'medium').length,
      undeclaredCredentials: by('undeclared-env').filter((f) => f.severity !== 'low').map((f) => f.subject),
      installScripts: by('install-script').map((f) => f.message),
      deprecated: by('deprecated').length > 0,
      noRepository: by('provenance').some((f) => /repository/.test(f.message)),
      capabilities: caps,
      egressHosts: by('network-egress').length,
      ms,
      bytes: (r.pkg.tarballBytes ?? 0) + (r.pkg.dependencies ?? []).reduce((n, d) => n + (d.tarballBytes ?? 0), 0),
      depsFollowed: r.deps?.followed ?? 0,
      depsSkipped: r.deps?.skipped ?? [],
    };
  } catch (err) {
    return { vendor, name, error: err.message.slice(0, 160) };
  }
});

writeFileSync(
  new URL(DEPS ? '../vendor-benchmark-deps.json' : '../vendor-benchmark.json', import.meta.url),
  `${JSON.stringify({ scannedAt: new Date().toISOString(), rows }, null, 2)}\n`
);

const cap = (r, needle, tag) => (r.capabilities?.some((c) => c.includes(needle)) ? tag : '·');
console.log(`\n  ${'VENDOR'.padEnd(14)} ${'PACKAGE'.padEnd(40)} ${'FILES'.padStart(5)} ${'TOOLS'.padStart(5)}  CAPS  H  M  NOTES`);
for (const r of rows) {
  if (r.error) {
    console.log(`  ${r.vendor.padEnd(14)} ${r.name.padEnd(40)}  ERROR ${r.error}`);
    continue;
  }
  const caps = cap(r, 'process', 'x') + cap(r, 'filesystem', 'w') + cap(r, 'dynamic', 'e') + (r.egressHosts ? 'n' : '·');
  const notes = [
    r.deprecated && 'DEPRECATED',
    r.installScripts.length && 'install-script',
    r.noRepository && 'no-repo',
    r.undeclaredCredentials.length && `creds:${r.undeclaredCredentials.length}`,
    r.tools === 0 && 'NO TOOLS FOUND',
  ]
    .filter(Boolean)
    .join(' ');
  console.log(
    `  ${r.vendor.padEnd(14)} ${r.name.slice(0, 40).padEnd(40)} ${String(r.files).padStart(5)} ${String(r.tools).padStart(5)}  ${caps}  ${r.high}  ${r.medium}  ${notes}`
  );
}
const ok = rows.filter((r) => !r.error);
const mb = ok.reduce((n, r) => n + r.bytes, 0) / 1048576;
const secs = ok.reduce((n, r) => n + r.ms, 0) / 1000;
console.log(`\n  ${ok.length}/${rows.length} scanned · tools found in ${ok.filter((r) => r.tools > 0).length}/${ok.length} · caps: x=exec w=writes e=eval n=network`);
console.log(`  ${DEPS ? 'with --deps' : 'top-level only'}: ${mb.toFixed(1)} MB downloaded · ${secs.toFixed(1)} s summed scan time · ${ok.reduce((n, r) => n + r.depsFollowed, 0)} dependencies followed\n`);
for (const r of ok) for (const s of r.depsSkipped) console.log(`  skipped ${s.name} (${r.name}): ${s.reason}`);

#!/usr/bin/env node
/**
 * The browser adapter must agree with the CLI exactly: same files, same hash, same
 * listing, same findings. Uses the network, so it lives here rather than in the
 * offline test suite. Usage: node scripts/browser-parity.js [npm names...]
 */
import { readFileSync } from 'node:fs';
import { scanInBrowser } from '../src/browser.js';
import { scan } from '../src/index.js';

const names = process.argv.slice(2).length ? process.argv.slice(2) : ['pretrip-mcp', '@upstash/context7-mcp', '@modelcontextprotocol/server-filesystem', 'pypi:srclight'];
const index = readFileSync(new URL('../src/data/registry-index.json', import.meta.url));
const fetchImpl = (u, i) => (u === 'index' ? Promise.resolve(new Response(index)) : fetch(u, i));
const key = (fs) => fs.map((f) => `${f.check}:${f.subject ?? f.message.slice(0, 40)}`).sort().join('|');

let ok = true;
for (const n of names) {
  const b = await scanInBrowser(n, { indexUrl: 'index', fetchImpl });
  const c = await scan(/^pypi:/.test(n) ? n : `npm:${n}`);
  const same = b.pkg.sha256 === c.pkg.sha256 && b.pkg.files.size === c.pkg.files.size && b.listing.found === Boolean(c.entry) && key(b.findings) === key(c.findings);
  ok &&= same;
  console.log(`${same ? 'same' : 'DIFFERENT'}  ${n}  (${b.pkg.files.size} files, ${b.findings.length} findings)`);
}
process.exit(ok ? 0 : 1);

#!/usr/bin/env node
/**
 * Assemble site/ for the Worker's static assets: the page (web/) and the engine it imports
 * (src/), plus security headers. The Content-Security-Policy pins the one inline script by
 * hash, so injected script cannot run even if something untrusted reached the DOM.
 *
 * The registry band's figures are written into site/web/index.html from the data on disk (the
 * archive's chain and the ledger's meta.json), so a visitor without JavaScript sees real, dated
 * numbers; with JavaScript the page replaces them from the live /history/ and /api/servers.
 * Usage: node scripts/build-site.js
 */
import { cpSync, rmSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { recordText, censusText, sampleText } from '../web/census-text.js';

const root = new URL('../', import.meta.url);
const out = new URL('../site/', import.meta.url);
rmSync(out, { recursive: true, force: true });
mkdirSync(out);
cpSync(new URL('web/', root), new URL('web/', out), { recursive: true, filter: (p) => !p.endsWith('.md') });
cpSync(new URL('src/', root), new URL('src/', out), { recursive: true });

const archive = resolve(process.env.DEEDROLL_ARCHIVE ?? new URL('../archive', import.meta.url).pathname);
const html = fillBand(readFileSync(new URL('web/index.html', root), 'utf8'));
writeFileSync(new URL('web/index.html', out), html);
const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => `'sha256-${createHash('sha256').update(m[1]).digest('base64')}'`);
const csp = [
  "default-src 'self'",
  `script-src 'self' ${inline.join(' ')}`,
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  // The page talks to npm, PyPI, the MCP registry, OSV.dev and whatever MCP server the
  // visitor names (any https host), plus this computer for the local exposure check.
  "connect-src 'self' https: http://127.0.0.1:* http://localhost:*",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');
writeFileSync(new URL('_headers', out), `/*
  Content-Security-Policy: ${csp}
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  Permissions-Policy: camera=(), microphone=(), geolocation=()
`);
console.log(`site/ built; CSP pins ${inline.length} inline script(s)`);

/** Replace the text inside the element with this id (leaf elements only). */
function fill(page, id, text) {
  const re = new RegExp(`(<[a-z0-9]+[^>]*\\sid="${id}"[^>]*>)[^<]*(</)`);
  if (!re.test(page)) throw new Error(`build-site: no #${id} in web/index.html`);
  const safe = String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return page.replace(re, (_, open, close) => `${open}${safe}${close}`);
}

function fillBand(page) {
  const chainPath = join(archive, 'chain.jsonl');
  const metaPath = join(archive, 'ledger', 'public', 'meta.json');
  if (existsSync(chainPath)) {
    const lines = readFileSync(chainPath, 'utf8').split('\n').filter(Boolean);
    const last = JSON.parse(lines.at(-1));
    const diffFile = last.files.find((f) => f.file.endsWith('.diff.json'));
    const diff = diffFile && existsSync(join(archive, diffFile.file)) ? JSON.parse(readFileSync(join(archive, diffFile.file), 'utf8')) : null;
    const t = recordText(last, lines.length, diff);
    page = fill(fill(page, 'figure', t.figure), 'census-when', t.when);
    if (diff) page = fill(fill(fill(page, 'census-added', t.added), 'census-declared', t.declared), 'census-moved', t.moved);
    console.log(`band: registry record of ${last.date}, ${t.figure} listings`);
  } else console.warn(`band: no ${chainPath}; the page shows dashes until its script loads the record`);
  const meta = existsSync(metaPath) ? JSON.parse(readFileSync(metaPath, 'utf8')) : null;
  if (meta?.census?.scanned) {
    const c = censusText(meta.census, meta.builtAt);
    page = fill(fill(fill(fill(page, 'creds-pct', c.pct), 'creds-line', c.line), 'creds-more', c.more), 'ledger-built', c.built);
    console.log(`band: census of ${meta.census.date}: ${c.pct}, ${meta.census.undeclared} of ${meta.census.scanned}`);
  } else console.warn(`band: no census in ${metaPath}; run scripts/build-ledger.js first`);
  const h = JSON.parse(readFileSync(new URL('web/data/registry-health.json', root), 'utf8'));
  const st = sampleText(h);
  return fill(fill(page, 'sample-summary', st.summary), 'band-method', st.method);
}

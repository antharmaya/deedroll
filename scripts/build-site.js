#!/usr/bin/env node
/**
 * Assemble site/ for the Worker's static assets: the page (web/) and the engine it imports
 * (src/), plus security headers. The Content-Security-Policy pins the one inline script by
 * hash, so injected script cannot run even if something untrusted reached the DOM.
 * Usage: node scripts/build-site.js
 */
import { cpSync, rmSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const root = new URL('../', import.meta.url);
const out = new URL('../site/', import.meta.url);
rmSync(out, { recursive: true, force: true });
mkdirSync(out);
cpSync(new URL('web/', root), new URL('web/', out), { recursive: true, filter: (p) => !p.endsWith('.md') });
cpSync(new URL('src/', root), new URL('src/', out), { recursive: true });

const html = readFileSync(new URL('web/index.html', root), 'utf8');
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

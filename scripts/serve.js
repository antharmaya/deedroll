#!/usr/bin/env node
/**
 * Serve the package root so web/ can import the real engine from ../src: the page runs
 * the same code as the CLI. Also serves the probe relay at POST /api/probe, for hosted
 * servers that do not let web pages read their answers (src/relay-core.js).
 * Zero dependencies. Usage: node scripts/serve.js [port]
 */
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { handleProbe, createLimiter } from '../src/relay-core.js';
import { guardedFetch } from '../src/relay-node.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PORT = Number(process.argv[2] ?? 4173);
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
  '.svg': 'image/svg+xml',
  '.md': 'text/markdown; charset=utf-8',
};

const limiter = createLimiter();

async function readBody(req, cap = 4096) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > cap) throw new Error('too large');
  }
  return body;
}

createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/api/probe') {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' });
      return res.end();
    }
    let parsed;
    try {
      parsed = JSON.parse(await readBody(req));
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: false, error: 'Send JSON: {"url": "https://…"}' }));
    }
    const out = await handleProbe(parsed, { fetchImpl: guardedFetch, limiter, caller: req.socket.remoteAddress ?? 'anon' });
    res.writeHead(out.status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    return res.end(JSON.stringify(out.body));
  }
  if (path === '/') {
    res.writeHead(302, { location: '/web/' });
    return res.end();
  }
  // The registry history, read-only from archive/, as the Worker serves it from R2.
  if (path.startsWith('/history/')) {
    const file = normalize(join(ROOT, 'archive', path.slice('/history/'.length)));
    if (!file.startsWith(join(ROOT, 'archive'))) {
      res.writeHead(403);
      return res.end();
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { 'content-type': file.endsWith('.gz') ? 'application/gzip' : file.endsWith('.json') ? 'application/json' : 'application/x-ndjson', 'cache-control': 'no-store' });
      return res.end(body);
    } catch {
      res.writeHead(404);
      return res.end();
    }
  }
  let file = normalize(join(ROOT, path));
  if (!file.startsWith(ROOT) || file.split(sep).includes('node_modules')) {
    res.writeHead(403);
    return res.end();
  }
  try {
    if ((await stat(file)).isDirectory()) file = join(file, 'index.html');
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  }
}).listen(PORT, () => console.log(`deedroll web: http://localhost:${PORT}/web/`));

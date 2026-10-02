/**
 * deedroll on Cloudflare Workers: the page and engine (static assets), the probe relay
 * (/api/probe), the registry history (/history/*, read-only from R2), the ledger
 * (/api/servers), and ways to follow one server: /badge/<name>.json and /feed/<name>.atom.
 *
 * SSRF on Workers: there is no DNS pinning here, so every relay fetch refuses private IP
 * literals and local names, resolves hostnames through Cloudflare's DNS-over-HTTPS first
 * and refuses any private answer, and never follows redirects. Workers' own egress cannot
 * route to a customer's private network without an explicit binding (Tunnel/VPC), which
 * this Worker does not have; the checks are the first line, not the only one.
 */
import { handleProbe, privateAddress, refusedHost, createLimiter } from '../src/relay-core.js';
import { searchStore, searchLedger, shardOf } from '../src/ledger.js';
import { badgeOf, atomFeed } from '../src/feeds.js';

const fallbackLimit = createLimiter({ max: 20, windowMs: 60 * 1000 });
const IP = /^(\d+\.){3}\d+$|:/;

async function resolvesPrivate(host) {
  for (const type of ['A', 'AAAA']) {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, { headers: { accept: 'application/dns-json' } });
    if (!res.ok) continue;
    const body = await res.json();
    for (const a of body.Answer ?? []) if ((a.type === 1 || a.type === 28) && privateAddress(a.data)) return a.data;
  }
  return null;
}

/** The relay's fetch on Workers. */
async function guardedFetch(url, init = {}) {
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new TypeError('the relay only fetches https');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (IP.test(host)) {
    if (privateAddress(host)) throw new TypeError(`${host} is a private address; the relay does not probe private networks`);
  } else {
    const refused = refusedHost(host);
    if (refused) throw new TypeError(`the relay does not probe ${refused}`);
    const priv = await resolvesPrivate(host);
    if (priv) throw new TypeError(`${host} resolves to a private address; the relay does not probe private networks`);
  }
  const headers = new Headers(init.headers ?? {});
  headers.set('user-agent', 'deedroll-relay/0.1 (read-only MCP discovery probe)');
  return fetch(url, { ...init, headers, redirect: 'manual' });
}

const TYPES = { '.gz': 'application/gzip', '.json': 'application/json; charset=utf-8', '.jsonl': 'application/x-ndjson; charset=utf-8' };

async function history(path, env) {
  const key = path.replace(/^\/history\/?/, '');
  if (!key || key.includes('..')) return new Response('Not found', { status: 404 });
  const obj = await env.HISTORY.get(key);
  if (!obj) return new Response('Not found', { status: 404 });
  const ext = (key.match(/(\.[a-z]+)$/) ?? [])[1] ?? '';
  // Dated files never change once written; the chain grows daily.
  const immutable = /\d{4}-\d{2}-\d{2}/.test(key);
  return new Response(obj.body, {
    headers: {
      'content-type': TYPES[ext] ?? 'application/octet-stream',
      'cache-control': immutable ? 'public, max-age=31536000, immutable' : 'public, max-age=300',
      'access-control-allow-origin': '*',
      etag: obj.httpEtag,
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // One canonical address. Links already sent out (disclosure emails, posts) point at the old
    // workers.dev host and at mcpscan.antharmaya.com (the name before deedroll), so those keep
    // answering, with a permanent redirect for anything readable. POSTs are left alone: a page
    // opened before the move still talks to its own relay.
    const canonical = env.CANONICAL_HOST;
    // Plain http is never served. Found live 2026-10-02: the page opened over http:// had no
    // crypto.subtle (browsers keep it to secure contexts), so every package scan failed at the
    // integrity check with "can't access property digest". The zone does not force https.
    if (url.protocol === 'http:' && (request.method === 'GET' || request.method === 'HEAD')) {
      const host = url.hostname.endsWith('.workers.dev') || (env.FORMER_HOSTS ?? '').split(',').map((h) => h.trim()).includes(url.hostname) ? canonical ?? url.hostname : url.hostname;
      return new Response(null, { status: 301, headers: { location: `https://${host}${url.pathname}${url.search}` } });
    }
    const former = (env.FORMER_HOSTS ?? '').split(',').map((h) => h.trim()).filter(Boolean);
    const moved = url.hostname.endsWith('.workers.dev') || former.includes(url.hostname);
    if (canonical && url.hostname !== canonical && moved && (request.method === 'GET' || request.method === 'HEAD')) {
      return new Response(null, {
        status: 301,
        headers: { location: `https://${canonical}${url.pathname}${url.search}`, 'access-control-allow-origin': '*' },
      });
    }
    if (url.pathname === '/') return Response.redirect(`${url.origin}/web/`, 302);

    if (url.pathname === '/api/probe') {
      if (request.method !== 'POST') return new Response(null, { status: 405, headers: { allow: 'POST' } });
      const ip = request.headers.get('cf-connecting-ip') ?? 'anon';
      const ok = env.PROBE_LIMIT ? (await env.PROBE_LIMIT.limit({ key: ip })).success : fallbackLimit(ip);
      let body;
      try {
        const text = await request.text();
        if (text.length > 4096) throw new Error('too large');
        body = JSON.parse(text);
      } catch {
        return Response.json({ ok: false, error: 'Send JSON: {"url": "https://…"}' }, { status: 400 });
      }
      const out = await handleProbe(body, { fetchImpl: guardedFetch, limiter: () => ok });
      return Response.json(out.body, { status: out.status, headers: { 'cache-control': 'no-store' } });
    }

    if (url.pathname === '/api/servers' || url.pathname.startsWith('/api/servers/')) {
      if (request.method !== 'GET' && request.method !== 'HEAD') return new Response(null, { status: 405, headers: { allow: 'GET, HEAD' } });
      return cached(request, () => servers(url, env));
    }

    if (url.pathname.startsWith('/badge/') || url.pathname.startsWith('/feed/')) {
      if (request.method !== 'GET' && request.method !== 'HEAD') return new Response(null, { status: 405, headers: { allow: 'GET, HEAD' } });
      return cached(request, () => follow(url, env));
    }

    if (url.pathname.startsWith('/history/')) {
      if (request.method !== 'GET' && request.method !== 'HEAD') return new Response(null, { status: 405 });
      return history(url.pathname, env);
    }

    return noInjection(await env.ASSETS.fetch(request));
  },
};

/**
 * The antharmaya.com zone has Cloudflare Web Analytics on, which injects a beacon script into
 * every HTML page. The page's CSP already blocks it, but a scanner that promises no third-party
 * scripts should not carry the tag at all. Cloudflare leaves `no-transform` responses unmodified.
 */
function noInjection(res) {
  if (!(res.headers.get('content-type') ?? '').includes('text/html')) return res;
  const out = new Response(res.body, res);
  const cc = out.headers.get('cache-control');
  out.headers.set('cache-control', cc ? `${cc}, no-transform` : 'no-transform');
  // This host only (no includeSubDomains): browsers go straight to https from the second visit.
  out.headers.set('strict-transport-security', 'max-age=31536000');
  return out;
}

/* ---------- the ledger API: /api/servers ---------- */

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=600' };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });

// Per isolate: the search texts are indexed once and kept for ten minutes. A set whose build
// stamps disagree (mid-upload) is refused and the previous one kept.
let ledgerStore = null;
let ledgerAt = 0;
async function store(env) {
  if (ledgerStore && Date.now() - ledgerAt < 10 * 60 * 1000) return ledgerStore;
  const keys = ['search-names.txt', 'search-descs.txt', 'search-entries.txt', 'meta.json'];
  const [names, descs, entries, meta] = await Promise.all(keys.map((k) => env.HISTORY.get(`ledger/${k}`)));
  if (!names || !descs || !entries || !meta) return ledgerStore;
  const next = searchStore({ names: await names.text(), descs: await descs.text(), entries: await entries.text() });
  if (next) {
    next.meta = await meta.json();
    ledgerStore = next;
    ledgerAt = Date.now();
  }
  return ledgerStore;
}

/** One server's record from its shard: the record, null when absent, undefined when R2 is down. */
async function recordOf(name, env) {
  const obj = await env.HISTORY.get(`ledger/servers/${shardOf(name)}.json`);
  if (!obj) return undefined;
  const shard = await obj.json();
  return shard.servers?.[name] ?? null;
}

async function servers(url, env) {
  const name = decodeURIComponent(url.pathname.slice('/api/servers/'.length));
  if (url.pathname.startsWith('/api/servers/') && name) {
    if (name.length > 200) return json({ error: 'name too long' }, 400);
    const record = await recordOf(name, env);
    if (record === undefined) return json({ error: 'the ledger is not available right now' }, 503);
    if (!record) return json({ error: `no server called "${name}" in the ledger`, hint: 'search with /api/servers?q=' }, 404);
    return json({ name, record });
  }
  const s = await store(env);
  if (!s) return json({ error: 'the ledger is not available right now' }, 503);
  const ledger = { start: s.meta.start, last: s.meta.last, servers: s.meta.servers, builtAt: s.meta.builtAt };
  const q = url.searchParams.get('q');
  if (!q) return json({ ledger, usage: { search: '/api/servers?q=github', server: '/api/servers/<registry name>' } });
  const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit')) || 25));
  return json({ query: q, ledger, results: searchLedger(s, q.slice(0, 100), limit) });
}

/** /badge/<registry name>.json (shields.io endpoint) and /feed/<registry name>.atom. */
async function follow(url, env) {
  const badge = url.pathname.startsWith('/badge/');
  const [prefix, ext] = badge ? ['/badge/', '.json'] : ['/feed/', '.atom'];
  if (!url.pathname.endsWith(ext)) return json({ error: `use ${prefix}<registry name>${ext}` }, 404);
  const name = decodeURIComponent(url.pathname.slice(prefix.length, -ext.length));
  if (!name || name.length > 200) return json({ error: 'bad name' }, 400);
  const record = await recordOf(name, env);
  if (record === undefined) return json({ error: 'the ledger is not available right now' }, 503);
  // A badge for an unknown name still renders (as "not in the registry"), so a README never
  // shows a broken image; the feed answers 404.
  if (badge) return json(badgeOf(record));
  if (!record) return json({ error: `no server called "${name}" in the ledger` }, 404);
  return new Response(atomFeed(record, `https://${env.CANONICAL_HOST ?? url.host}`), {
    headers: { 'content-type': 'application/atom+xml; charset=utf-8', 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=3600' },
  });
}

/** Serve from the edge cache when we can: a repeated query costs no Worker CPU. */
async function cached(request, produce) {
  const cache = caches.default;
  const hit = await cache.match(request);
  if (hit) return hit;
  const res = await produce();
  if (res.status === 200) await cache.put(request, res.clone());
  return res;
}

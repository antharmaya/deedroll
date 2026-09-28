/**
 * mcpscan on Cloudflare Workers: the page and engine (static assets), the probe relay
 * (/api/probe) and the registry history (/history/*, read-only from R2).
 *
 * SSRF on Workers: there is no DNS pinning here, so every relay fetch refuses private IP
 * literals and local names, resolves hostnames through Cloudflare's DNS-over-HTTPS first
 * and refuses any private answer, and never follows redirects. Workers' own egress cannot
 * route to a customer's private network without an explicit binding (Tunnel/VPC), which
 * this Worker does not have; the checks are the first line, not the only one.
 */
import { handleProbe, privateAddress, refusedHost, createLimiter } from '../src/relay-core.js';

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
  headers.set('user-agent', 'mcpscan-relay/0.1 (read-only MCP discovery probe)');
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

    if (url.pathname.startsWith('/history/')) {
      if (request.method !== 'GET' && request.method !== 'HEAD') return new Response(null, { status: 405 });
      return history(url.pathname, env);
    }

    return env.ASSETS.fetch(request);
  },
};

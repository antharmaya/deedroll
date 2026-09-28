/**
 * The relay's fetch for Node: every connection resolves the hostname once, refuses it if
 * any address is private, and connects to the vetted address. Checking a name and then
 * letting fetch resolve it again would leave a gap (DNS rebinding: the second answer can
 * be 127.0.0.1); pinning the lookup closes it.
 */
import https from 'node:https';
import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import { Readable } from 'node:stream';
import { privateAddress } from './relay-core.js';

export class RefusedDestination extends Error {}

async function vetted(hostname) {
  const all = await lookup(hostname, { all: true, verbatim: true });
  if (!all.length) throw new RefusedDestination(`${hostname} does not resolve`);
  const bad = all.find((a) => privateAddress(a.address));
  if (bad) throw new RefusedDestination(`${hostname} resolves to a private address; the relay does not probe private networks`);
  return all[0];
}

/** A minimal fetch: https only, pinned to vetted addresses, no redirects followed. */
export function guardedFetch(url, init = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(url);
    } catch (err) {
      return reject(new TypeError(`invalid URL: ${err.message}`));
    }
    if (u.protocol !== 'https:') return reject(new TypeError('the relay only fetches https'));
    // Node does not call a custom lookup for IP-literal hosts, so a pinned lookup alone
    // never sees them. Every URL reaching here may come from a hostile server's own
    // metadata (an OAuth "authorization server" of https://10.0.0.5/), so vet literals too.
    const literal = u.hostname.replace(/^\[|\]$/g, '');
    if (isIP(literal) && privateAddress(literal)) return reject(new TypeError(`${literal} is a private address; the relay does not probe private networks`));
    const headers = init.headers instanceof Headers ? Object.fromEntries(init.headers) : { ...(init.headers ?? {}) };
    const req = https.request(
      u,
      {
        method: init.method ?? 'GET',
        headers: { 'user-agent': 'mcpscan-relay/0.1 (read-only MCP discovery probe)', ...headers },
        lookup: (hostname, opts, cb) => {
          vetted(hostname).then(
            (a) => (opts?.all ? cb(null, [a]) : cb(null, a.address, a.family)),
            (err) => cb(err)
          );
        },
      },
      (res) => {
        const h = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) v.forEach((x) => h.append(k, x));
          else if (v != null) h.set(k, String(v));
        }
        const empty = res.statusCode === 204 || res.statusCode === 304 || init.method === 'HEAD';
        resolve(new Response(empty ? null : Readable.toWeb(res), { status: res.statusCode, headers: h }));
      }
    );
    if (init.signal) {
      if (init.signal.aborted) req.destroy(init.signal.reason);
      init.signal.addEventListener('abort', () => req.destroy(init.signal.reason), { once: true });
    }
    req.on('error', (err) => reject(err instanceof RefusedDestination ? new TypeError(err.message) : err));
    if (init.body) req.write(init.body);
    req.end();
  });
}

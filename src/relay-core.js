/**
 * The probe relay, host-neutral. Most hosted MCP servers do not let a web page read their
 * answers (CORS; 25 of 44 sampled on 2026-09-28), so the page can ask a relay to run the
 * same read-only probe server-side. One handler; each host (the local dev server, a
 * Cloudflare Worker) supplies its own guarded fetch.
 *
 * A relay is an open door to "fetch this URL for me", so it only ever:
 *   - accepts one https URL, no credentials in it, no headers from the caller;
 *   - runs inspectRemote: discovery requests only (tools/list, initialize, public OAuth
 *     metadata), never tools/call;
 *   - refuses private, loopback and link-local destinations (the host's fetchImpl
 *     enforces this on every connection, including redirects' targets, which are never
 *     followed anyway);
 *   - rate-limits per caller, and keeps nothing: no URL, no result is stored.
 */
import { inspectRemote } from './remote-scan.js';

const MAX_URL = 2048;

/** Literal hosts that must never be probed, before any DNS: a first, cheap line of defence. */
export function refusedHost(hostname) {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa')) return 'a local name';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':')) return privateAddress(h) ? 'a private address' : null;
  return null;
}

/** IPv6 text to 16 bytes, or null. Handles "::", embedded IPv4 and zone ids. */
export function ipv6Bytes(text) {
  let t = text.toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  const v4tail = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(t);
  if (v4tail) {
    const q = v4tail.slice(1).map(Number);
    if (q.some((n) => n > 255)) return null;
    t = `${t.slice(0, v4tail.index)}${((q[0] << 8) | q[1]).toString(16)}:${((q[2] << 8) | q[3]).toString(16)}`;
  }
  const halves = t.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.flatMap((g) => [parseInt(g, 16) >> 8, parseInt(g, 16) & 255]);
}

function privateV4([p, q, r]) {
  return (
    p === 0 || p === 10 || p === 127 || p >= 224 ||
    (p === 100 && q >= 64 && q <= 127) || // carrier-grade NAT
    (p === 169 && q === 254) || // link-local, cloud metadata (169.254.169.254)
    (p === 172 && q >= 16 && q <= 31) ||
    (p === 192 && q === 168) ||
    (p === 192 && q === 0 && r === 0) ||
    (p === 198 && (q === 18 || q === 19))
  );
}

/**
 * True for addresses a public relay must never reach. IPv6 is parsed, not pattern-matched:
 * the URL parser rewrites [::ffff:127.0.0.1] as [::ffff:7f00:1], which a textual check
 * missed (found in testing on 2026-09-28: the relay tried to connect to 127.0.0.1:443).
 * Every IPv6 form that embeds an IPv4 address is checked against the IPv4 rules.
 */
export function privateAddress(ip) {
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (v4) return privateV4(v4.slice(1).map(Number));
  const b = ipv6Bytes(ip);
  if (!b) return true; // unparseable: refuse
  const zero = (from, to) => b.slice(from, to).every((x) => x === 0);
  if (zero(0, 16) || (zero(0, 15) && b[15] === 1)) return true; // :: and ::1
  if ((b[0] & 0xfe) === 0xfc || (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) || b[0] === 0xff) return true; // unique-local, link-local, multicast
  if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return privateV4(b.slice(12)); // IPv4-mapped
  if (zero(0, 12)) return privateV4(b.slice(12)); // IPv4-compatible (deprecated)
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return true; // NAT64 reaches IPv4 behind it
  if (b[0] === 0x20 && b[1] === 0x02) return privateV4(b.slice(2, 6)); // 6to4 embeds an IPv4 address
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0 && b[3] === 0) return true; // Teredo
  return false;
}

/** Validate what the page sent; returns the URL string or an error message. */
export function validateTarget(raw) {
  if (typeof raw !== 'string' || !raw || raw.length > MAX_URL) return { error: 'Send one URL.' };
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { error: 'That is not a URL.' };
  }
  if (u.protocol !== 'https:') return { error: 'The relay only probes https URLs.' };
  if (u.username || u.password) return { error: 'Remove the credentials from the URL; the relay never sends any.' };
  const refused = refusedHost(u.hostname);
  if (refused) return { error: `The relay does not probe ${refused}. Use the command line for servers on your own network.` };
  u.hash = '';
  return { url: u.toString() };
}

/** A fixed-window limiter per caller. In memory: good enough for one process. */
export function createLimiter({ max = 30, windowMs = 10 * 60 * 1000 } = {}) {
  const hits = new Map();
  return (key, now = Date.now()) => {
    const list = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (list.length >= max) {
      hits.set(key, list);
      return false;
    }
    list.push(now);
    hits.set(key, list);
    if (hits.size > 10000) hits.clear(); // bounded memory under abuse
    return true;
  };
}

/**
 * @param {unknown} body  the parsed JSON the page sent: { url }
 * @returns {Promise<{status: number, body: object}>}
 */
export async function handleProbe(body, { fetchImpl, limiter, caller = 'anon' }) {
  if (limiter && !limiter(caller)) return { status: 429, body: { ok: false, error: 'Too many probes from here in the last few minutes. Try again shortly, or use the command line.' } };
  const t = validateTarget(body?.url);
  if (t.error) return { status: 400, body: { ok: false, error: t.error } };
  try {
    const r = await inspectRemote(t.url, { fetchImpl });
    return { status: 200, body: { ok: true, via: 'relay', ...r } };
  } catch (err) {
    return { status: 502, body: { ok: false, error: `The probe failed: ${String(err?.message ?? err).slice(0, 200)}` } };
  }
}

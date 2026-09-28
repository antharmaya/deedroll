/**
 * Read-only probe of a hosted (remote) MCP server over Streamable HTTP.
 *
 * Only discovery is ever sent (`tools/list`, and `initialize` for older servers), never
 * `tools/call`, so no tool can run. Nothing runs locally, but it is an outbound
 * connection: the server sees the request. Built to be pointed at servers that may be
 * hostile:
 *   - a hard timeout and a response-size cap, so a server cannot stream forever;
 *   - redirects are not followed: fetch would carry the request (and any credential)
 *     to wherever the server points, so a redirect ends the probe and is reported;
 *   - credentials are opt-in, resolved only from ${VAR} references, and sent only to
 *     the server's own origin.
 *
 * Two protocol eras. Revision 2026-07-28 made MCP stateless: no `initialize`, no
 * session; every request carries its version in `_meta` and in headers. Servers on
 * 2025-11-25 and earlier need the `initialize` handshake. The probe is "dual-era" as the
 * spec prescribes (basic/transports/streamable-http#backward-compatibility): a modern
 * request first; a 4xx whose body is a recognised modern error means modern (retry with
 * a supported version); anything else means legacy, so fall back to `initialize`. A
 * server that answers neither but opens an event stream on GET is the deprecated
 * HTTP+SSE transport, reported rather than probed.
 */

export const MODERN_VERSION = '2026-07-28';
const LEGACY_VERSION = '2025-06-18';
const MODERN_ERRORS = new Set([-32020, -32021, -32022]); // HeaderMismatch, MissingRequiredClientCapability, UnsupportedProtocolVersion
const CLIENT = { name: 'mcpscan', version: '0.1.0' };
const TIMEOUT_MS = 15000;
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_PAGES = 20;

export class ProbeError extends Error {
  constructor(kind, message, detail = {}) {
    super(message);
    this.kind = kind; // 'auth' | 'redirect' | 'transport' | 'protocol' | 'timeout' | 'too-large' | 'legacy-sse'
    this.detail = detail;
  }
}

/** Read a body with a byte cap; a server that sends more is cut off, not trusted. */
async function readCapped(res) {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BYTES) {
      await reader.cancel().catch(() => {});
      throw new ProbeError('too-large', `response exceeded ${MAX_BYTES / 1048576} MB`);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  return new TextDecoder('utf-8').decode(all);
}

/** A JSON-RPC reply may arrive as JSON or inside a server-sent-events stream. */
export function parseRpcBody(text, contentType, id) {
  if (/text\/event-stream/i.test(contentType ?? '')) {
    for (const event of text.split(/\r?\n\r?\n/)) {
      const data = event
        .split(/\r?\n/)
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.slice(5).replace(/^ /, ''))
        .join('\n');
      if (!data) continue;
      let msg;
      try {
        msg = JSON.parse(data);
      } catch {
        continue;
      }
      if (msg && msg.id === id) return msg;
    }
    throw new ProbeError('protocol', `no JSON-RPC response with id ${id} in the event stream`);
  }
  let msg;
  try {
    msg = JSON.parse(text);
  } catch {
    throw new ProbeError('protocol', `response is not JSON (content-type ${contentType ?? 'none'})`);
  }
  const found = Array.isArray(msg) ? msg.find((m) => m.id === id) : msg;
  if (!found) throw new ProbeError('protocol', `no JSON-RPC response with id ${id}`);
  return found;
}

/** The JSON-RPC error in a 4xx body, if it is one; null otherwise. */
function errorIn(text) {
  try {
    const msg = JSON.parse(text);
    return typeof msg?.error?.code === 'number' ? msg.error : null;
  } catch {
    return null;
  }
}

/** Newest modern version in a server's `supported` list, or null if it only speaks legacy ones. */
function newestModern(supported) {
  return [...(supported ?? [])].filter((v) => /^\d{4}-\d{2}-\d{2}$/.test(v) && v >= MODERN_VERSION).sort().at(-1) ?? null;
}

/**
 * @param {string} url
 * @param {{headers?: object, fetchImpl?: Function, timeoutMs?: number}} [opts]
 * @returns {Promise<{era: 'modern'|'legacy', serverInfo, protocolVersion, tools: object[], pages: number, truncated: boolean}>}
 */
export async function probeRemote(url, { headers = {}, fetchImpl = globalThis.fetch, timeoutMs = TIMEOUT_MS } = {}) {
  const origin = new URL(url).origin;
  let nextId = 1;

  /** One POST. Throws for what ends a probe in any era; returns the rest for the caller to judge. */
  async function send(body, extra = {}) {
    let res;
    try {
      res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers, ...extra },
        body: JSON.stringify(body),
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      if (err?.name === 'TimeoutError' || err?.name === 'AbortError') throw new ProbeError('timeout', `no response within ${timeoutMs / 1000}s`);
      throw new ProbeError('transport', err.message);
    }
    if (res.status >= 300 && res.status < 400) {
      const to = res.headers.get('location') ?? '?';
      let toOrigin = to;
      try {
        toOrigin = new URL(to, url).origin;
      } catch {
        /* keep raw */
      }
      throw new ProbeError('redirect', `server redirected to ${toOrigin}; not followed (a redirect would carry the request elsewhere)`, {
        crossOrigin: toOrigin !== origin,
      });
    }
    if (res.status === 401 || res.status === 403) {
      const www = res.headers.get('www-authenticate') ?? '';
      const meta = /resource_metadata="?([^",\s]+)/i.exec(www)?.[1] ?? null;
      throw new ProbeError('auth', `requires authentication (HTTP ${res.status}${/bearer/i.test(www) ? ', bearer/OAuth' : ''})`, {
        status: res.status,
        resourceMetadata: meta,
        bearer: /bearer/i.test(www),
      });
    }
    const text = res.status === 202 ? '' : await readCapped(res);
    return { status: res.status, headers: res.headers, text };
  }

  const reply = (r, id) => {
    const msg = parseRpcBody(r.text, r.headers.get('content-type'), id);
    if (msg.error) throw new ProbeError('protocol', `JSON-RPC error ${msg.error.code}: ${String(msg.error.message).slice(0, 120)}`);
    return msg.result;
  };

  async function listTools(call) {
    const tools = [];
    let cursor;
    let pages = 0;
    let first = null;
    do {
      const result = await call(cursor);
      first ??= result;
      tools.push(...(result?.tools ?? []));
      cursor = result?.nextCursor;
      pages++;
    } while (cursor && pages < MAX_PAGES);
    return { tools, pages, truncated: Boolean(cursor), first };
  }

  // ---- modern: stateless, version in _meta and headers ----
  const modernCall = (version) => async (cursor) => {
    const id = nextId++;
    const body = {
      jsonrpc: '2.0',
      id,
      method: 'tools/list',
      params: {
        ...(cursor ? { cursor } : {}),
        _meta: {
          'io.modelcontextprotocol/protocolVersion': version,
          'io.modelcontextprotocol/clientInfo': CLIENT,
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    };
    const r = await send(body, { 'mcp-protocol-version': version, 'mcp-method': 'tools/list' });
    if (r.status >= 400) {
      const err = errorIn(r.text);
      const modern = err && (MODERN_ERRORS.has(err.code) || (r.status === 404 && err.code === -32601));
      throw Object.assign(new ProbeError('protocol', `HTTP ${r.status}${err ? `, JSON-RPC ${err.code}` : ''}`), { modern, rpc: err, status: r.status });
    }
    return reply(r, id);
  };

  let modernFailure = null;
  try {
    let version = MODERN_VERSION;
    let listed;
    try {
      listed = await listTools(modernCall(version));
    } catch (err) {
      // A modern server that wants another modern version says which.
      const retry = err.modern && err.rpc?.code === -32022 ? newestModern(err.rpc.data?.supported) : null;
      if (!retry || retry === version) throw err;
      version = retry;
      listed = await listTools(modernCall(version));
    }
    // A pre-2026 stateless server can answer a bare tools/list too; only a modern one sets resultType.
    const era = listed.first?.resultType ? 'modern' : 'legacy';
    return { era, serverInfo: listed.first?._meta?.['io.modelcontextprotocol/serverInfo'] ?? null, protocolVersion: era === 'modern' ? version : null, tools: listed.tools, pages: listed.pages, truncated: listed.truncated };
  } catch (err) {
    if (!(err instanceof ProbeError) || !['protocol', 'transport'].includes(err.kind)) throw err;
    if (err.modern) {
      if (err.status === 404 && err.rpc?.code === -32601) return { era: 'modern', serverInfo: null, protocolVersion: MODERN_VERSION, tools: [], pages: 1, truncated: false };
      throw new ProbeError('protocol', `modern MCP server refused the probe: ${err.message}${err.rpc?.data?.supported ? ` (supports ${err.rpc.data.supported.join(', ')})` : ''}`);
    }
    modernFailure = err;
  }

  // ---- legacy: initialize handshake, session header ----
  let sessionId = null;
  let negotiated = null;
  const legacyHeaders = () => ({ ...(sessionId ? { 'mcp-session-id': sessionId } : {}), ...(negotiated ? { 'mcp-protocol-version': negotiated } : {}) });

  const initId = nextId++;
  const init = await send({ jsonrpc: '2.0', id: initId, method: 'initialize', params: { protocolVersion: LEGACY_VERSION, capabilities: {}, clientInfo: CLIENT } });
  if (init.status === 404 || init.status === 405 || init.status === 400) {
    // Neither era answered a POST. The deprecated HTTP+SSE transport opens a GET stream
    // whose first event names the endpoint to POST to.
    if (await looksLikeLegacySse(url, fetchImpl, timeoutMs)) {
      throw new ProbeError('legacy-sse', 'server uses the deprecated HTTP+SSE transport (2024-11-05); its tools were not listed', { transport: 'sse' });
    }
    throw new ProbeError('transport', `HTTP ${init.status} to POST: not an MCP endpoint in any protocol era (modern attempt: ${modernFailure?.message ?? 'n/a'})`);
  }
  if (init.status >= 400) throw new ProbeError('transport', `HTTP ${init.status}`);
  sessionId = init.headers.get('mcp-session-id');
  const initResult = reply(init, initId);
  negotiated = initResult?.protocolVersion ?? LEGACY_VERSION;
  await send({ jsonrpc: '2.0', method: 'notifications/initialized' }, legacyHeaders());

  const listed = await listTools(async (cursor) => {
    const id = nextId++;
    const r = await send({ jsonrpc: '2.0', id, method: 'tools/list', params: cursor ? { cursor } : {} }, legacyHeaders());
    if (r.status >= 400) throw new ProbeError('transport', `HTTP ${r.status}`);
    return reply(r, id);
  });
  return { era: 'legacy', serverInfo: initResult?.serverInfo ?? null, protocolVersion: negotiated, tools: listed.tools, pages: listed.pages, truncated: listed.truncated };
}

/** GET the URL and read just enough to see an SSE `endpoint` event; never more than 64 kB. */
async function looksLikeLegacySse(url, fetchImpl, timeoutMs) {
  try {
    const res = await fetchImpl(url, { method: 'GET', headers: { accept: 'text/event-stream' }, redirect: 'manual', signal: AbortSignal.timeout(Math.min(timeoutMs, 8000)) });
    if (!res.ok || !/text\/event-stream/i.test(res.headers.get('content-type') ?? '')) return false;
    const reader = res.body?.getReader();
    if (!reader) return false;
    let text = '';
    while (text.length < 65536) {
      const { done, value } = await reader.read();
      if (done) break;
      text += new TextDecoder().decode(value);
      if (/event:\s*endpoint/.test(text)) break;
    }
    await reader.cancel().catch(() => {});
    return /event:\s*endpoint/.test(text);
  } catch {
    return false;
  }
}

/**
 * Resolve ${VAR} header references from the environment for an opt-in authenticated
 * probe. Literal values never reach here (the config parser drops them).
 */
export function resolveHeaderRefs(template, env = globalThis.process?.env ?? {}) {
  const out = {};
  const missing = [];
  for (const [k, v] of Object.entries(template ?? {})) {
    let ok = true;
    const val = String(v).replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_, name, dflt) => {
      if (env[name] !== undefined && env[name] !== '') return env[name];
      if (dflt !== undefined) return dflt;
      ok = false;
      missing.push(name);
      return '';
    });
    if (ok) out[k] = val;
  }
  return { headers: out, missing };
}

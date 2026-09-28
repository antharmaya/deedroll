/**
 * Read-only probe of a hosted (remote) MCP server over Streamable HTTP.
 *
 * Only `initialize`, `notifications/initialized` and `tools/list` are ever sent — never
 * `tools/call` — so no tool can run. Nothing runs locally, but it is an outbound
 * connection: the server sees the request. Built to be pointed at servers that may be
 * hostile:
 *   - a hard timeout and a response-size cap, so a server cannot stream forever;
 *   - redirects are not followed: fetch would carry the request (and any credential)
 *     to wherever the server points, so a redirect ends the probe and is reported;
 *   - credentials are opt-in, resolved only from ${VAR} references, and sent only to
 *     the server's own origin.
 */

const PROTOCOL_VERSION = '2025-06-18';
const TIMEOUT_MS = 15000;
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_PAGES = 20;

export class ProbeError extends Error {
  constructor(kind, message, detail = {}) {
    super(message);
    this.kind = kind; // 'auth' | 'redirect' | 'transport' | 'protocol' | 'timeout' | 'too-large'
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
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
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

/**
 * @param {string} url
 * @param {{headers?: object, fetchImpl?: Function, timeoutMs?: number}} [opts]
 * @returns {Promise<{serverInfo, protocolVersion, tools: object[], pages: number}>}
 */
export async function probeRemote(url, { headers = {}, fetchImpl = globalThis.fetch, timeoutMs = TIMEOUT_MS } = {}) {
  const origin = new URL(url).origin;
  let sessionId = null;
  let negotiated = null;
  let nextId = 1;

  async function post(body, { expectReply = true } = {}) {
    const h = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...headers,
    };
    if (sessionId) h['mcp-session-id'] = sessionId;
    if (negotiated) h['mcp-protocol-version'] = negotiated;

    let res;
    try {
      res = await fetchImpl(url, {
        method: 'POST',
        headers: h,
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
      });
    }
    if (res.status === 404 || res.status === 405) {
      throw new ProbeError('transport', `HTTP ${res.status} to POST: not a Streamable HTTP endpoint (legacy SSE servers are not probed)`);
    }
    if (!res.ok && res.status !== 202) throw new ProbeError('transport', `HTTP ${res.status}`);

    const sid = res.headers.get('mcp-session-id');
    if (sid) sessionId = sid;
    if (!expectReply) {
      await readCapped(res).catch(() => '');
      return null;
    }
    const text = await readCapped(res);
    const msg = parseRpcBody(text, res.headers.get('content-type'), body.id);
    if (msg.error) throw new ProbeError('protocol', `JSON-RPC error ${msg.error.code}: ${String(msg.error.message).slice(0, 120)}`);
    return msg.result;
  }

  const init = await post({
    jsonrpc: '2.0',
    id: nextId++,
    method: 'initialize',
    params: {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'mcpscan', version: '0.1.0' },
    },
  });
  negotiated = init?.protocolVersion ?? PROTOCOL_VERSION;
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, { expectReply: false });

  const tools = [];
  let cursor;
  let pages = 0;
  do {
    const result = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: cursor ? { cursor } : {} });
    tools.push(...(result?.tools ?? []));
    cursor = result?.nextCursor;
    pages++;
  } while (cursor && pages < MAX_PAGES);

  return { serverInfo: init?.serverInfo ?? null, protocolVersion: negotiated, tools, pages, truncated: Boolean(cursor) };
}

/**
 * Resolve ${VAR} header references from the environment for an opt-in authenticated
 * probe. Literal values never reach here (the config parser drops them).
 */
export function resolveHeaderRefs(template, env = process.env) {
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

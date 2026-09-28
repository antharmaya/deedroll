/**
 * MCP servers running on your own machine or network, found and judged. Platform-neutral:
 * the CLI (--local) finds every listening port from the operating system; the browser page
 * can only try common ports on this computer, but it answers the sharper question: can a
 * website reach them?
 *
 * The risk is concrete. Local dev servers often bind every interface and skip sign-in,
 * and the MCP specification requires servers to validate the Origin header "to prevent
 * DNS rebinding attacks" (basic/transports/streamable-http). One that does not can be
 * driven by any website its user visits: the class behind the MCP Inspector RCE
 * (CVE-2025-49596), which the NSA MCP guidance cites. The NSA lists "unauthenticated MCP
 * servers" first among what to scan your network for.
 */
import { probeRemote, ProbeError } from './remote.js';

/** Ports MCP servers and their tooling commonly listen on (6274/6277: MCP Inspector). */
export const COMMON_PORTS = [3000, 3001, 3333, 4000, 5000, 5173, 6274, 6277, 7000, 8000, 8001, 8080, 8081, 8765, 8787, 8888, 9000, 9090];
const PATHS = ['/mcp', '/', '/sse', '/api/mcp'];
export const FOREIGN_ORIGIN = 'https://origin-check.mcpscan.invalid';

/**
 * Is there an MCP server at this base URL? Tries the usual endpoint paths; stops at the
 * first that answers as MCP. Returns null when nothing there speaks MCP.
 */
export async function findMcpEndpoint(base, { fetchImpl = globalThis.fetch, timeoutMs = 3000 } = {}) {
  for (const path of PATHS) {
    const url = `${base.replace(/\/$/, '')}${path}`;
    try {
      const r = await probeRemote(url, { fetchImpl, timeoutMs });
      return { url, answered: true, era: r.era, protocolVersion: r.protocolVersion, serverInfo: r.serverInfo, tools: r.tools };
    } catch (err) {
      if (!(err instanceof ProbeError)) continue;
      if (err.kind === 'auth') return { url, answered: false, auth: true, detail: err.detail };
      if (err.kind === 'legacy-sse') return { url, answered: false, sse: true };
      if (err.kind === 'timeout') return null; // something is there but not answering: not ours to guess
    }
  }
  return null;
}

/** Send the same discovery request as a foreign website would. True when it is refused. */
export async function validatesOrigin(url, { fetchImpl = globalThis.fetch, timeoutMs = 3000 } = {}) {
  try {
    await probeRemote(url, { fetchImpl, timeoutMs, headers: { origin: FOREIGN_ORIGIN } });
    return false; // it answered a request from another site
  } catch (err) {
    if (err instanceof ProbeError && (err.kind === 'auth' || err.detail?.status === 403 || /HTTP 403/.test(err.message))) return true;
    return err instanceof ProbeError ? true : null;
  }
}

const allInterfaces = (bind) => ['0.0.0.0', '::', '*', '[::]'].includes(String(bind));

/**
 * Findings for one local server.
 * @param {{url, bind?, answered, auth?, sse?, tools?, originValidated?: boolean|null, process?: string}} s
 */
export function judgeLocal(s) {
  const where = new URL(s.url).host;
  const open = s.answered && !s.auth;
  const who = s.process ? ` (${s.process})` : '';
  const out = [];
  if (s.bind && allInterfaces(s.bind)) {
    out.push({
      check: 'local-network-exposed',
      severity: open ? 'high' : 'medium',
      message: open
        ? `listens on every network interface (${s.bind}) with no sign-in${who}: anyone on your network can list and call its tools`
        : `listens on every network interface (${s.bind})${who}: reachable from other machines on your network; the MCP specification says local servers should bind to localhost`,
      evidence: [{ file: where, line: 0, text: `bound to ${s.bind}` }],
    });
  }
  if (open && s.originValidated === false) {
    out.push({
      check: 'no-origin-validation',
      severity: 'high',
      message: `answers requests that carry another website's Origin${who}: any site you visit can drive it through DNS rebinding; the MCP specification requires servers to reject them`,
      evidence: [{ file: where, line: 0, text: `Origin: ${FOREIGN_ORIGIN} was answered` }],
    });
  }
  if (open) {
    out.push({
      check: 'unauthenticated',
      severity: 'info',
      message: `answers without sign-in: anything that can reach it can list its ${s.tools?.length ?? 0} tool(s), and usually call them`,
      evidence: [{ file: where, line: 0, text: 'tools/list answered with no credentials' }],
    });
  }
  if (s.sse) {
    out.push({
      check: 'deprecated-transport',
      severity: 'low',
      message: 'uses the HTTP+SSE transport, deprecated since 2025-03-26; tools not listed',
      evidence: [{ file: where, line: 0, text: 'GET opened an event stream with an endpoint event' }],
    });
  }
  return out;
}

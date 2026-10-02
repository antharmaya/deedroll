/**
 * Everything knowable about a hosted MCP server without an account, as one pure step:
 * probe (both protocol eras), what its tools say, what they declare about themselves, and
 * for a server that requires sign-in, how that sign-in is built. No pins here: the CLI
 * keeps pins on disk and the browser in the visitor's own storage; both call this.
 *
 * Web platform APIs only, so the browser page, the local relay and a hosted relay run the
 * same code.
 */
import { probeRemote, ProbeError } from './remote.js';
import { inspectAuth } from './auth.js';
import { checkToolTexts, SEVERITY_ORDER } from './checks.js';

/** What the tools declare about themselves (MCP tool annotations). Declarations, not proof. */
export function annotationSummary(tools) {
  const s = { readOnly: 0, destructive: 0, openWorld: 0, unannotated: 0, destructiveNames: [] };
  for (const t of tools) {
    const a = t.annotations ?? {};
    if (!Object.keys(a).length) s.unannotated++;
    if (a.readOnlyHint === true) s.readOnly++;
    if (a.destructiveHint === true && a.readOnlyHint !== true) {
      s.destructive++;
      if (s.destructiveNames.length < 8) s.destructiveNames.push(t.name);
    }
    if (a.openWorldHint === true) s.openWorld++;
  }
  return s;
}

/**
 * @returns {Promise<{target, remote: object, tools: object[], findings: object[]}>}
 */
export async function inspectRemote(url, { headers = {}, fetchImpl = globalThis.fetch, timeoutMs, auth = true } = {}) {
  const host = new URL(url).host;
  let probe;
  try {
    probe = await probeRemote(url, { headers, fetchImpl, timeoutMs });
  } catch (err) {
    if (!(err instanceof ProbeError)) throw err;
    const remote = { url, probed: false, reason: err.kind, message: err.message, detail: err.detail };
    const findings = [];
    if (err.kind === 'legacy-sse') {
      findings.push({
        check: 'deprecated-transport',
        severity: 'low',
        message: 'uses the HTTP+SSE transport, deprecated since 2025-03-26 and eligible for removal; tools not listed',
        evidence: [{ file: host, line: 0, text: 'GET opened an event stream with an endpoint event' }],
      });
      return { target: url, remote, tools: [], findings };
    }
    if (err.kind === 'auth' && auth) {
      const a = await inspectAuth(url, { resourceMetadata: err.detail?.resourceMetadata ?? null, bearer: err.detail?.bearer !== false, fetchImpl });
      remote.auth = a.auth;
      findings.push(...a.findings);
    }
    const severity = err.kind === 'redirect' && err.detail?.crossOrigin ? 'medium' : 'info';
    findings.push({
      check: 'remote-not-probed',
      severity,
      message: err.kind === 'auth' ? `${err.message}: its tools were not listed (deedroll uses no account)` : `${err.message}: tools not listed, so nothing was checked`,
      evidence: [{ file: host, line: 0, text: err.kind }],
    });
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    return { target: url, remote, tools: [], findings };
  }

  const findings = checkToolTexts(probe.tools.map((t) => ({ name: t.name, description: String(t.description ?? ''), file: host, line: 0 })));
  const annotations = annotationSummary(probe.tools);
  findings.push({
    check: 'unauthenticated',
    severity: 'info',
    message: `answers without sign-in: anyone who has the URL can list its ${probe.tools.length} tool(s), and usually call them`,
    evidence: [{ file: host, line: 0, text: 'tools/list answered with no credentials' }],
  });
  if (probe.truncated) {
    findings.push({
      check: 'tools-truncated',
      severity: 'info',
      message: 'tools/list kept paginating past the page limit; later tools were not seen',
      evidence: [{ file: host, line: 0, text: `${probe.pages} pages` }],
    });
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return {
    target: url,
    remote: {
      url,
      probed: true,
      era: probe.era,
      serverInfo: probe.serverInfo,
      protocolVersion: probe.protocolVersion,
      tools: probe.tools.length,
      toolNames: probe.tools.map((t) => t.name),
      annotations,
      auth: { required: false },
    },
    tools: probe.tools,
    findings,
  };
}

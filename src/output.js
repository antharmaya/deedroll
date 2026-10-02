/**
 * Machine-readable output: the v1 JSON envelope and SARIF, built from the same scan
 * result so the two can never disagree. Pure: shared by the CLI and the browser page.
 */
import { SCHEMA, withIds, fingerprint } from './rules.js';
import { toSarif } from './sarif.js';

const packageOf = (pkg) =>
  pkg ? { ecosystem: pkg.ecosystem ?? 'npm', name: pkg.name, version: pkg.version, sha256: pkg.sha256 ?? null, ...(pkg.artifact ? { file: pkg.artifact.filename } : {}) } : null;

/** One scan (package or remote) as a v1 document. */
export async function toJsonV1(result, { version }) {
  return {
    schema: SCHEMA,
    tool: { name: 'deedroll', version },
    target: result.target,
    package: packageOf(result.pkg),
    listing: result.entry ? { name: result.entry.server?.name ?? null } : null,
    declaredEnv: [...(result.declared?.keys() ?? [])],
    ...(result.remote ? { remote: result.remote } : {}),
    ...(result.disclosure ? { disclosure: result.disclosure } : {}),
    findings: await withIds(result.findings),
  };
}

/** `--installed`: every configured server, each with its own findings. */
export async function installedToJsonV1(result, { version }) {
  return {
    schema: SCHEMA,
    tool: { name: 'deedroll', version },
    ...result,
    servers: await Promise.all(result.servers.map(async (s) => ({ ...s, findings: await withIds(s.findings) }))),
  };
}

export function scanToSarif(results, { version }) {
  return toSarif(results.map((r) => ({ target: r.target, package: packageOf(r.pkg), findings: r.findings })), { version });
}

/** Reverse-DNS key for the registry `_meta` block: a domain Antharmaya controls. */
export const META_KEY = 'com.antharmaya/deedroll';

/**
 * The block a subregistry injects into a server.json `_meta`, as the official registry's
 * aggregator guide describes ("a subregistry could inject … security scan results").
 * Compact on purpose: counts and pointers, not evidence text, so it fits in a listing;
 * the full report is the v1 JSON.
 */
export async function toRegistryMeta(result, { version, scannedAt = new Date().toISOString() }) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) counts[f.severity]++;
  const findings = await Promise.all(
    result.findings
      .filter((f) => f.severity !== 'info')
      .map(async (f) => {
        const ev = f.evidence?.[0];
        return { id: await fingerprint(f), check: f.check, severity: f.severity, ...(f.subject ? { subject: f.subject } : {}), ...(ev?.file ? { at: ev.line ? `${ev.file}:${ev.line}` : ev.file } : {}) };
      })
  );
  return {
    [META_KEY]: {
      schema: SCHEMA,
      tool: { name: 'deedroll', version },
      scannedAt,
      target: result.target,
      package: packageOf(result.pkg),
      ...(result.remote ? { remote: { probed: Boolean(result.remote.probed), era: result.remote.era ?? null, protocolVersion: result.remote.protocolVersion ?? null, tools: result.remote.tools ?? null } } : {}),
      counts,
      findings,
    },
  };
}

/**
 * `--egress`: the hosts a server's code names, as a starting allowlist for an egress proxy
 * (the NSA MCP guidance recommends "a filtering outgoing proxy … with specific resource
 * URLs"). Static, so a starting point: a server can build other hostnames at runtime.
 */
export function egressAllowlist(result) {
  const name = result.pkg ? `${result.pkg.name}@${result.pkg.version}` : result.target;
  const hosts = new Set();
  for (const f of result.findings ?? []) if (f.check === 'network-egress') hosts.add(f.message.replace(/^contacts /, ''));
  for (const r of result.entry?.server?.remotes ?? []) {
    try { hosts.add(new URL(r.url).hostname); } catch { /* templated */ }
  }
  if (result.remote?.url) hosts.add(new URL(result.remote.url).hostname);
  const dynamic = (result.findings ?? []).some((f) => f.check === 'dynamic-env');
  return [
    `# Hosts ${name} names in its code or listing, for an egress allowlist.`,
    '# Static: a server can build other hostnames at runtime, so treat this as a starting point',
    '# and watch the proxy log for anything else.',
    ...(dynamic ? ['# Note: it also builds environment variable names at runtime; check its config for URLs.'] : []),
    ...(hosts.size ? [...hosts].sort() : ['# (no external hosts found in the code)']),
    '',
  ].join('\n');
}


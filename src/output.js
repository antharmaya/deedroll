/**
 * Machine-readable output: the v1 JSON envelope and SARIF, built from the same scan
 * result so the two can never disagree. Pure: shared by the CLI and the browser page.
 */
import { SCHEMA, withIds } from './rules.js';
import { toSarif } from './sarif.js';

const packageOf = (pkg) =>
  pkg ? { ecosystem: pkg.ecosystem ?? 'npm', name: pkg.name, version: pkg.version, sha256: pkg.sha256 ?? null, ...(pkg.artifact ? { file: pkg.artifact.filename } : {}) } : null;

/** One scan (package or remote) as a v1 document. */
export async function toJsonV1(result, { version }) {
  return {
    schema: SCHEMA,
    tool: { name: 'mcpscan', version },
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
    tool: { name: 'mcpscan', version },
    ...result,
    servers: await Promise.all(result.servers.map(async (s) => ({ ...s, findings: await withIds(s.findings) }))),
  };
}

export function scanToSarif(results, { version }) {
  return toSarif(results.map((r) => ({ target: r.target, package: packageOf(r.pkg), findings: r.findings })), { version });
}

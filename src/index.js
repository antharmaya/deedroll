import { fetchRegistryEntry, fetchNpmPackage, declaredEnvVars, npmIdentifiers } from './sources.js';
import { runAllChecks, SEVERITY_ORDER } from './checks.js';
import { checkDisclosure } from './disclosure.js';
import { createTypeSafeJudge } from './judge.js';

/** Official server package names, used only for the typosquat check. */
export const OFFICIAL_NAMES = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/sdk',
  '@modelcontextprotocol/inspector',
];

/**
 * Scan one MCP server.
 *
 * @param {string} target  a registry name ("io.github.owner/server") or "npm:<pkg>"
 * @param {object} [opts]
 * @param {boolean} [opts.semantic]  also judge whether descriptions disclose capabilities.
 *   Off by default: the static checks are deterministic and offline, and stay that way.
 * @param {object} [opts.judge]      a judge (see judge.js); defaults to TypeSafe
 * @returns {Promise<{target, pkg, entry, declared, findings, disclosure?}>}
 */
export async function scan(target, { version = 'latest', semantic = false, judge = null } = {}) {
  let entry = null;
  let npmName = null;
  let npmVersion = version;

  if (target.startsWith('npm:')) {
    npmName = target.slice(4);
  } else {
    entry = await fetchRegistryEntry(target);
    if (!entry) throw new Error(`not found in the MCP registry: ${target}`);
    const ids = npmIdentifiers(entry);
    if (ids.length === 0) {
      return {
        target,
        entry,
        pkg: null,
        declared: declaredEnvVars(entry),
        findings: [
          {
            check: 'no-package',
            severity: 'info',
            message: 'registry entry ships no npm package (remote-only server); nothing to scan statically',
            evidence: [{ file: 'registry', line: 0, text: entry.server.name }],
          },
        ],
      };
    }
    npmName = ids[0].identifier;
    if (version === 'latest' && ids[0].version) npmVersion = ids[0].version;
  }

  const pkg = await fetchNpmPackage(npmName, npmVersion);
  const declared = declaredEnvVars(entry);
  const findings = runAllChecks({ pkg, entry, declared, officialNames: OFFICIAL_NAMES });

  if (!semantic) return { target, entry, pkg, declared, findings };

  const result = await checkDisclosure({
    pkg,
    entry,
    findings,
    judge: judge ?? createTypeSafeJudge(),
  });
  const merged = [...findings, ...result.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
  return { target, entry, pkg, declared, findings: merged, disclosure: result.disclosure };
}

export { fetchRegistryEntry, fetchNpmPackage, declaredEnvVars, npmIdentifiers };
export { checkDisclosure, DEFAULT_THRESHOLDS } from './disclosure.js';
export { createTypeSafeJudge, JudgeConfigError } from './judge.js';
export { extractTools } from './tools.js';
export * from './checks.js';

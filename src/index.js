import { fetchRegistryEntry, fetchNpmPackage, declaredEnvVars, npmIdentifiers } from './sources.js';
import { runAllChecks } from './checks.js';

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
 * @returns {Promise<{target, pkg, entry, declared, findings}>}
 */
export async function scan(target, { version = 'latest' } = {}) {
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

  return { target, entry, pkg, declared, findings };
}

export { fetchRegistryEntry, fetchNpmPackage, declaredEnvVars, npmIdentifiers };
export * from './checks.js';

import { fetchRegistryEntry, fetchNpmPackage, declaredEnvVars, npmIdentifiers } from './sources.js';
import { fetchPypiPackage } from './pypi.js';
import { packageIdentifiers, listingStatus } from './model.js';

export { listingStatus } from './model.js';
import { runAllChecks, SEVERITY_ORDER } from './checks.js';
import { checkDisclosure } from './disclosure.js';
import { createTypeSafeJudge } from './judge.js';
import { expandDependencies, mergeDependencies } from './deps.js';
import { findListing } from './lookup.js';
import { checkKnownVulnerabilities } from './osv.js';
import { inspectRemote } from './remote-scan.js';
import { loadPins, savePins, diffPins, serverKey } from './pins.js';

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
/**
 * @param {boolean} [opts.lookup]  for npm: targets, find the registry listing that ships the package
 * @param {boolean} [opts.osv]     look up known vulnerabilities (sends package names + versions to OSV.dev)
 */
export async function scan(
  target,
  { version = 'latest', semantic = false, judge = null, deps = false, lookup = true, osv = true, ...opts } = {}
) {
  let entry = null;
  let npmName = null;
  let npmVersion = version;
  let ecosystem = 'npm';

  if (target.startsWith('npm:')) {
    npmName = target.slice(4);
  } else if (target.startsWith('pypi:')) {
    npmName = target.slice(5);
    ecosystem = 'pypi';
  } else {
    entry = await fetchRegistryEntry(target);
    if (!entry) throw new Error(`not found in the MCP registry: ${target}`);
    let ids = npmIdentifiers(entry);
    if (ids.length === 0 && packageIdentifiers(entry, 'pypi').length) {
      ids = packageIdentifiers(entry, 'pypi');
      ecosystem = 'pypi';
    }
    if (ids.length === 0) {
      // Remote-only listing (57% of the registry, 2026-09-28): probe its endpoint instead.
      const remote = (entry.server.remotes ?? []).find((r) => r.url && !/\{/.test(r.url));
      if (remote) {
        const r = await scanRemote(remote.url, { pinsFile: opts.pinsFile, fetchImpl: opts.fetchImpl });
        const findings = [...listingStatus(entry), ...r.findings];
        const templated = (entry.server.remotes ?? []).filter((x) => /\{/.test(x.url ?? '')).length;
        if (templated) {
          findings.push({ check: 'not-scanned', severity: 'info', message: `${templated} more endpoint(s) need values filled in (templated URL); not probed`, evidence: [{ file: 'registry', line: 0, text: entry.server.name }] });
        }
        findings.sort((x, y) => SEVERITY_ORDER[x.severity] - SEVERITY_ORDER[y.severity]);
        return { ...r, target, entry, pkg: null, declared: declaredEnvVars(entry), remote: { ...r.remote, url: remote.url }, findings };
      }
      return {
        target,
        entry,
        pkg: null,
        declared: declaredEnvVars(entry),
        findings: [
          {
            check: 'no-package',
            severity: 'info',
            message: 'registry entry ships no npm or PyPI package; nothing to scan statically',
            evidence: [{ file: 'registry', line: 0, text: entry.server.name }],
          },
        ],
      };
    }
    npmName = ids[0].identifier;
    if (version === 'latest' && ids[0].version) npmVersion = ids[0].version;
  }

  let pkg = ecosystem === 'pypi' ? await fetchPypiPackage(npmName, npmVersion) : await fetchNpmPackage(npmName, npmVersion);
  let depInfo = null;
  if (deps && ecosystem === 'npm') {
    // Off by default: it costs downloads (measured in scripts/vendor-benchmark.js --deps).
    const expanded = await expandDependencies(pkg);
    pkg = mergeDependencies(pkg, expanded.deps);
    depInfo = { followed: pkg.dependencies.length, skipped: expanded.skipped, capped: expanded.capped };
  }
  // An npm: target may still have a registry listing; without it, "undeclared" has
  // nothing to be judged against. The registry's own search cannot find it by package.
  let listing = entry ? { found: true, source: 'target', listings: [entry.server.name] } : null;
  if (!entry && lookup) {
    const hit = await findListing(npmName, { ecosystem });
    entry = hit.entry;
    listing = { found: Boolean(hit.entry), source: hit.source, listings: hit.listings, indexBuiltAt: hit.indexBuiltAt };
  }

  const declared = declaredEnvVars(entry);
  const findings = [...listingStatus(entry), ...runAllChecks({ pkg, entry, declared, officialNames: OFFICIAL_NAMES })];

  if (listing?.listings?.length > 1) {
    findings.push({
      check: 'multiple-listings',
      severity: 'info',
      message: `${listing.listings.length} registry listings point at this package: ${listing.listings.slice(0, 4).join(', ')}`,
      evidence: [{ file: 'registry', line: 0, text: listing.listings.join(', ').slice(0, 140) }],
    });
  }

  let vulns = null;
  if (osv) {
    const coords = [{ name: pkg.name, version: pkg.version, ecosystem }, ...(pkg.dependencies ?? []).map((d) => ({ name: d.name, version: d.version }))];
    const res = await checkKnownVulnerabilities(coords);
    findings.push(...res.findings);
    vulns = { checked: res.checked, error: res.error ?? null };
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  if (!semantic) return { target, entry, pkg, declared, findings, deps: depInfo, listing, vulns };

  const result = await checkDisclosure({
    pkg,
    entry,
    findings,
    judge: judge ?? createTypeSafeJudge(),
  });
  const merged = [...findings, ...result.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
  return { target, entry, pkg, declared, findings: merged, disclosure: result.disclosure, deps: depInfo, listing, vulns };
}

/**
 * Probe a hosted MCP server read-only (inspectRemote, shared with the browser and the
 * relay), then compare with the pinned state on disk. Pins are only written on a first
 * probe, an unchanged probe, or an explicit --update-pins: never when something changed.
 */
export async function scanRemote(url, { headers = {}, updatePins = false, pinsFile, fetchImpl } = {}) {
  const r = await inspectRemote(url, { headers, fetchImpl });
  if (!r.remote.probed) return { target: url, remote: r.remote, findings: r.findings };

  const findings = [...r.findings];
  const pins = loadPins(pinsFile);
  const key = serverKey(url);
  const d = await diffPins(pins[key], r.tools);
  findings.push(...d.findings);
  if (d.firstPin || !d.changed) {
    pins[key] = d.next;
    savePins(pins, pinsFile);
  } else if (updatePins) {
    pins[key] = { ...d.next, pinnedAt: new Date().toISOString() };
    savePins(pins, pinsFile);
    findings.push({
      check: 'pins-updated',
      severity: 'info',
      message: `accepted ${d.findings.length} change(s) and re-pinned (--update-pins)`,
      evidence: [{ file: 'pins.json', line: 0, text: key }],
    });
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return { target: url, remote: { ...r.remote, firstPin: d.firstPin, changed: d.changed }, findings };
}

export { fetchRegistryEntry, fetchNpmPackage, declaredEnvVars, npmIdentifiers };
export { checkDisclosure, buildDisclosureRequest, applyJudgments, DEFAULT_THRESHOLDS } from './disclosure.js';
export { buildAgentRequest, createAgentJudge, requestId, AGENT_RULES } from './agent-judge.js';
export { createTypeSafeJudge, JudgeConfigError } from './judge.js';
export { extractTools } from './tools.js';
export { selectDependencies, vendorToken } from './deps.js';
export { resolveVersion, provenanceHistory } from './sources.js';
export { findListing, searchTerms } from './lookup.js';
export { checkKnownVulnerabilities } from './osv.js';
export { probeRemote, resolveHeaderRefs, ProbeError, parseRpcBody } from './remote.js';
export { diffPins, fingerprint, serverKey, loadPins, savePins, pinsPath } from './pins.js';
export * from './checks.js';

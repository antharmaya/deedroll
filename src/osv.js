/**
 * Known vulnerabilities from OSV.dev (Google's open vulnerability database, which
 * includes GitHub's advisories).
 *
 * What leaves the machine: public package names and versions, nothing else — no scan
 * results, configs, keys or descriptions. Disabled with --no-osv. Covers the scanned
 * package and any followed dependencies, not the full transitive tree: that needs a
 * resolved lockfile, which is npm audit's job.
 */

const BATCH = 'https://api.osv.dev/v1/querybatch';
const VULN = 'https://api.osv.dev/v1/vulns/';
const MAX_DETAILS = 12;

const SEVERITY = { CRITICAL: 'high', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

/** Earliest version that fixes this advisory for this package, if OSV says. */
function fixedIn(vuln, name) {
  for (const a of vuln.affected ?? []) {
    if (a.package?.name !== name) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) return e.fixed;
  }
  return null;
}

/**
 * @param {Array<{name, version}>} packages
 * @returns {Promise<{findings: object[], checked: number, error?: string}>}
 */
export async function checkKnownVulnerabilities(packages, { fetchImpl = globalThis.fetch } = {}) {
  if (packages.length === 0) return { findings: [], checked: 0 };
  try {
    const res = await fetchImpl(BATCH, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        queries: packages.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })),
      }),
    });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    const { results = [] } = await res.json();

    const hits = [];
    results.forEach((r, i) => {
      for (const v of r.vulns ?? []) hits.push({ pkg: packages[i], id: v.id });
    });

    const findings = [];
    for (const hit of hits.slice(0, MAX_DETAILS)) {
      const d = await fetchImpl(`${VULN}${encodeURIComponent(hit.id)}`);
      const vuln = d.ok ? await d.json() : { id: hit.id };
      const sev = SEVERITY[String(vuln.database_specific?.severity ?? '').toUpperCase()] ?? 'medium';
      const fix = fixedIn(vuln, hit.pkg.name);
      const alias = (vuln.aliases ?? []).find((a) => a.startsWith('CVE-'));
      findings.push({
        check: 'known-vulnerability',
        subject: hit.id,
        severity: sev,
        message: `${hit.pkg.name}@${hit.pkg.version}: ${hit.id}${alias ? ` (${alias})` : ''} — ${(vuln.summary ?? 'see advisory').slice(0, 110)}${fix ? `; fixed in ${fix}` : ''}`,
        evidence: [{ file: `https://osv.dev/vulnerability/${hit.id}`, line: 0, text: `${hit.pkg.name}@${hit.pkg.version}` }],
      });
    }
    if (hits.length > MAX_DETAILS) {
      findings.push({
        check: 'known-vulnerability',
        severity: 'info',
        message: `${hits.length - MAX_DETAILS} more advisories not detailed`,
        evidence: [{ file: 'https://osv.dev', line: 0, text: `${hits.length} total` }],
      });
    }
    return { findings, checked: packages.length };
  } catch (err) {
    // A failed lookup is reported, never read as "no known vulnerabilities".
    return {
      findings: [
        {
          check: 'vuln-lookup-failed',
          severity: 'info',
          message: `known-vulnerability lookup failed (${err.message.slice(0, 80)}); this is not a clean result`,
          evidence: [{ file: 'https://osv.dev', line: 0, text: 'unreachable' }],
        },
      ],
      checked: 0,
      error: err.message,
    };
  }
}

/**
 * Audit what is already installed: discover servers across agents, report config-level
 * risks, and statically scan every npm-launched server. Nothing is launched.
 */
import { discoverInstalled, configFindings } from './installed.js';
import { scan, scanRemote } from './index.js';
import { resolveHeaderRefs } from './remote.js';
import { SEVERITY_ORDER } from './checks.js';

/** Run async jobs with at most `limit` in flight. */
async function pool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/** One scan per ecosystem:name@version, however many agents configure it. */
const launchKey = (l) => `${l.kind}:${l.name}@${l.pinned ? l.version : 'latest'}`;

export async function auditInstalled({ home, cwd, concurrency = 4, semantic = false, judge = null, deps = false, osv = true, remote = false, authFromEnv = false, updatePins = false } = {}) {
  const { configs, servers } = discoverInstalled({ home, cwd });

  // The same package often sits in several agents' configs: scan each name@version once.
  const jobs = new Map();
  for (const s of servers) {
    if ((s.launch.kind !== 'npm' && s.launch.kind !== 'pypi') || !s.launch.name) continue;
    const version = s.launch.pinned ? s.launch.version : 'latest';
    const key = launchKey(s.launch);
    if (!jobs.has(key)) jobs.set(key, { name: s.launch.name, version, ecosystem: s.launch.kind });
  }

  const scanned = new Map();
  await pool([...jobs], concurrency, async ([key, job]) => {
    try {
      const r = await scan(`${job.ecosystem}:${job.name}`, { version: job.version, semantic, judge, deps, osv });
      scanned.set(key, { pkg: { name: r.pkg.name, version: r.pkg.version }, findings: r.findings, disclosure: r.disclosure });
    } catch (err) {
      scanned.set(key, {
        pkg: null,
        findings: [
          {
            check: 'scan-error',
            severity: 'info',
            message: `could not scan ${job.name}@${job.version}: ${err.message.slice(0, 160)}`,
            evidence: [{ file: job.ecosystem, line: 0, text: job.name }],
          },
        ],
      });
    }
  });

  // Remote servers: a read-only probe per distinct URL, only when asked (--remote).
  const probes = new Map();
  if (remote) {
    const urls = [...new Set(servers.filter((s) => s.launch.kind === 'remote' && s.probeUrl).map((s) => s.probeUrl))];
    await pool(urls, concurrency, async (url) => {
      const owner = servers.find((s) => s.probeUrl === url);
      const { headers, missing } = authFromEnv ? resolveHeaderRefs(owner.headerRefs) : { headers: {}, missing: [] };
      const r = await scanRemote(url, { headers, updatePins });
      if (missing.length) {
        r.findings.push({
          check: 'credential-unresolved',
          severity: 'info',
          message: `header references ${missing.join(', ')}, which is not set in this environment`,
          evidence: [{ file: new URL(url).host, line: 0, text: missing.join(', ') }],
        });
      }
      probes.set(url, r);
    });
  }

  const results = servers.map((s) => {
    const own = configFindings(s);
    let pkg = null;
    let pkgFindings = [];
    if (s.launch.kind === 'npm' || s.launch.kind === 'pypi') {
      const hit = scanned.get(launchKey(s.launch));
      pkg = hit?.pkg ?? null;
      pkgFindings = hit?.findings ?? [];
    }
    const probe = s.probeUrl ? probes.get(s.probeUrl) : null;
    const remoteFindings = probe?.findings ?? [];
    const findings = [...own, ...pkgFindings, ...remoteFindings]
      .filter((f) => !(probe && f.check === 'not-scanned'))
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    return { ...s, pkg, remote: probe?.remote ?? null, findings };
  });

  return { configs, servers: results, packagesScanned: scanned.size, remoteProbed: probes.size };
}

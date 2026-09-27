/**
 * Audit what is already installed: discover servers across agents, report config-level
 * risks, and statically scan every npm-launched server. Nothing is launched.
 */
import { discoverInstalled, configFindings } from './installed.js';
import { scan } from './index.js';
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

export async function auditInstalled({ home, cwd, concurrency = 4, semantic = false, judge = null } = {}) {
  const { configs, servers } = discoverInstalled({ home, cwd });

  // The same package often sits in several agents' configs: scan each name@version once.
  const jobs = new Map();
  for (const s of servers) {
    if (s.launch.kind !== 'npm') continue;
    const version = s.launch.pinned ? s.launch.version : 'latest';
    const key = `${s.launch.name}@${version}`;
    if (!jobs.has(key)) jobs.set(key, { name: s.launch.name, version });
  }

  const scanned = new Map();
  await pool([...jobs], concurrency, async ([key, job]) => {
    try {
      const r = await scan(`npm:${job.name}`, { version: job.version, semantic, judge });
      scanned.set(key, { pkg: { name: r.pkg.name, version: r.pkg.version }, findings: r.findings, disclosure: r.disclosure });
    } catch (err) {
      scanned.set(key, {
        pkg: null,
        findings: [
          {
            check: 'scan-error',
            severity: 'info',
            message: `could not scan ${job.name}@${job.version}: ${err.message.slice(0, 160)}`,
            evidence: [{ file: 'npm', line: 0, text: job.name }],
          },
        ],
      });
    }
  });

  const results = servers.map((s) => {
    const own = configFindings(s);
    let pkg = null;
    let pkgFindings = [];
    if (s.launch.kind === 'npm') {
      const hit = scanned.get(`${s.launch.name}@${s.launch.pinned ? s.launch.version : 'latest'}`);
      pkg = hit?.pkg ?? null;
      pkgFindings = hit?.findings ?? [];
    }
    const findings = [...own, ...pkgFindings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    return { ...s, pkg, findings };
  });

  return { configs, servers: results, packagesScanned: scanned.size };
}

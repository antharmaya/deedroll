import { SEVERITY_ORDER } from './checks.js';
import { selectDependencies } from './deps.js';

const COLORS = {
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[36m',
  info: '\x1b[90m',
};
const RESET = '\x1b[0m';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (sev, s) => (useColor ? `${COLORS[sev]}${s}${RESET}` : s);

export function render(result) {
  const { target, pkg, entry, declared, findings } = result;
  const out = [];

  out.push('');
  out.push(`  ${pkg ? `${pkg.name}@${pkg.version}` : target}`);
  const bits = [
    entry ? 'in registry' : 'not in registry',
    declared?.size ? `${declared.size} env var(s) declared` : 'no env vars declared',
  ];
  if (pkg) bits.push(`${pkg.files.size} file(s) scanned`);
  if (result.deps) {
    bits.push(`${result.deps.followed} dependency(ies) followed`);
    if (result.deps.skipped.length) bits.push(`${result.deps.skipped.length} skipped`);
  }
  out.push(`  ${bits.join(' · ')}`);
  const extra = [];
  if (result.listing && !entry) {
    extra.push(
      result.listing.source === 'index-miss'
        ? `registry: no listing ships this package as of ${result.listing.indexBuiltAt.slice(0, 10)} (complete index; rebuild with scripts/build-index.js)`
        : `registry: no listing found for this package (${result.listing.indexBuiltAt ? `index of ${result.listing.indexBuiltAt.slice(0, 10)} + ` : ''}name search) — not proof it is unlisted`
    );
  } else if (result.listing?.source && result.listing.source !== 'target') {
    extra.push(`registry: listed as ${result.listing.listings[0]} (found via ${result.listing.source === 'index' ? `index of ${result.listing.indexBuiltAt?.slice(0, 10)}` : 'live name search'})`);
  }
  if (pkg?.provenance) extra.push(`provenance: ${pkg.provenance.current ? 'yes (Sigstore attestation)' : 'none'}`);
  if (result.vulns) extra.push(result.vulns.error ? 'known vulnerabilities: lookup FAILED' : `known vulnerabilities: checked ${result.vulns.checked} package(s) on OSV.dev (sends names + versions; --no-osv to skip)`);
  if (pkg?.fromCache) extra.push('tarball: from local cache (hash verified)');
  for (const e of extra) out.push(`  ${e}`);
  if (pkg && !result.deps) {
    // Say what was not looked at. Measured: top-level-only understated capabilities for
    // 10 of 27 vendor servers (Playwright looked network-only; it launches browsers).
    const { follow } = selectDependencies(pkg.manifest, pkg.name);
    if (follow.length) {
      out.push(`  not followed: ${follow.length} vendor dependency(ies) (${follow.slice(0, 3).map((d) => d.name).join(', ')}${follow.length > 3 ? ', …' : ''}) — capabilities may be understated; rerun with --deps`);
    }
  }
  const d = result.disclosure;
  if (d) {
    out.push(
      d.judged
        ? `  semantic: ${Object.keys(d.judgments).length} capability(ies) judged over ${d.tools} tool description(s) by ${d.model}`
        : `  semantic: not judged — ${d.reason}`
    );
  }
  out.push('');

  if (findings.length === 0) {
    out.push('  no findings');
    out.push('');
    return out.join('\n');
  }

  for (const f of findings) {
    out.push(`  ${paint(f.severity, f.severity.toUpperCase().padEnd(6))} ${f.check}  ${f.message}`);
    for (const e of f.evidence ?? []) {
      const loc = e.line ? `${e.file}:${e.line}` : e.file;
      out.push(`         ${loc}  ${e.text}`);
    }
  }

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  const summary = Object.keys(SEVERITY_ORDER)
    .filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s}`)
    .join(' · ');
  out.push('');
  out.push(`  ${summary}`);
  out.push('');
  return out.join('\n');
}

/** Non-zero when something needs a human. */
export function exitCode(findings, { failOn = 'high' } = {}) {
  const threshold = SEVERITY_ORDER[failOn];
  return findings.some((f) => SEVERITY_ORDER[f.severity] <= threshold) ? 1 : 0;
}

const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const tilde = (p) => (process.env.HOME && p?.startsWith(process.env.HOME) ? `~${p.slice(process.env.HOME.length)}` : p);

function launchLabel(l) {
  switch (l.kind) {
    case 'npm':
      return `npm  ${l.name}${l.version ? `@${l.version}` : ''}${l.pinned ? '' : '  (unpinned)'}`;
    case 'pypi':
      return `pypi ${l.name ?? '?'}${l.pinned ? '' : '  (unpinned)'}`;
    case 'remote':
      return `remote ${l.host}`;
    case 'local':
      return `local ${l.runtime} script`;
    case 'container':
      return 'container';
    default:
      return `binary ${l.command}`;
  }
}

function countLine(findings) {
  const c = findings.reduce((acc, f) => ((acc[f.severity] = (acc[f.severity] ?? 0) + 1), acc), {});
  const parts = ['high', 'medium', 'low'].filter((s) => c[s]).map((s) => paint(s, `${c[s]} ${s}`));
  return parts.length ? parts.join(' · ') : '—';
}

/** Wireshark-shaped: an overview row per server, then detail only where it matters. */
export function renderInstalled(result, { all = false } = {}) {
  const { configs, servers, packagesScanned } = result;
  const out = [''];
  out.push(
    `  mcpscan --installed · ${configs.length} config file(s) · ${servers.length} server(s) · ${packagesScanned} npm package(s) scanned${result.remoteProbed ? ` · ${result.remoteProbed} remote probed (read-only)` : ''} · nothing launched`
  );
  for (const c of configs) {
    out.push(`    ${c.agent.padEnd(15)} ${tilde(c.file)}${c.error ? `  (unreadable: ${c.error})` : `  ${c.servers} server(s)`}`);
  }
  out.push('');
  out.push(`  ${'AGENT'.padEnd(15)} ${'SERVER'.padEnd(24)} ${'LAUNCH'.padEnd(52)} FINDINGS`);
  for (const s of servers) {
    const name = s.scope?.startsWith('project:') ? `${s.name} (project)` : s.name;
    const probed = s.remote ? (s.remote.probed ? ` · ${s.remote.tools} tools` : ` · ${s.remote.reason}`) : '';
    out.push(`  ${s.agent.padEnd(15)} ${clip(name, 24).padEnd(24)} ${clip(launchLabel(s.launch) + probed, 52).padEnd(52)} ${countLine(s.findings)}`);
  }

  const shown = all ? ['high', 'medium', 'low', 'info'] : ['high', 'medium', 'low'];
  for (const s of servers) {
    const list = s.findings.filter((f) => shown.includes(f.severity));
    if (list.length === 0) continue;
    out.push('');
    const scope = s.scope?.startsWith('project:') ? `, project ${tilde(s.scope.slice(8))}` : '';
    out.push(`  ── ${s.name}  (${s.agent}, ${tilde(s.file)}${scope}${s.pkg ? `, scanned ${s.pkg.name}@${s.pkg.version}` : ''})`);
    for (const f of list) {
      out.push(`  ${paint(f.severity, f.severity.toUpperCase().padEnd(6))} ${f.check}  ${f.message}`);
      for (const e of f.evidence ?? []) out.push(`         ${e.line ? `${tilde(e.file)}:${e.line}` : tilde(e.file)}  ${e.text}`);
    }
  }

  const everything = servers.flatMap((s) => s.findings);
  const notScanned = servers.filter((s) => s.findings.some((f) => f.check === 'not-scanned')).length;
  out.push('');
  out.push(`  ${countLine(everything)} across ${servers.length} server(s) · ${notScanned} not statically scannable${all ? '' : ' · --all shows info'}`);
  out.push('');
  return out.join('\n');
}

/** A remote target: what was probed, what it serves, what changed since the pin. */
export function renderRemote(result) {
  const out = [''];
  const r = result.remote;
  const host = new URL(result.target).host;
  out.push(`  ${host}  (remote, read-only probe: initialize + tools/list, never tools/call)`);
  if (r.probed) {
    const who = r.serverInfo ? `${r.serverInfo.name ?? '?'}${r.serverInfo.version ? `@${r.serverInfo.version}` : ''}` : 'unnamed';
    out.push(`  server ${who} · protocol ${r.protocolVersion} · ${r.tools} tool(s) · ${r.firstPin ? 'first probe: pinned' : r.changed ? 'CHANGED since pin' : 'unchanged since pin'}`);
  } else {
    out.push(`  not probed: ${r.message}`);
  }
  out.push('');
  for (const f of result.findings) {
    out.push(`  ${paint(f.severity, f.severity.toUpperCase().padEnd(6))} ${f.check}  ${f.message}`);
    for (const e of f.evidence ?? []) out.push(`         ${e.file}  ${e.text}`);
  }
  out.push('');
  return out.join('\n');
}

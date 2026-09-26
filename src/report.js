import { SEVERITY_ORDER } from './checks.js';

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
  out.push(`  ${bits.join(' · ')}`);
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

/**
 * SARIF 2.1.0, the format GitHub code scanning, Azure DevOps and most security dashboards
 * import. One run per scan; rules come from the catalog, so every result explains itself.
 *
 * Locations: evidence points into a package, not the repository being analysed, so file
 * paths are given relative to a PACKAGE base (described per run) and pseudo-sources such
 * as "npm" or "registry" become logical locations. Line 0 means "no line" and gets no
 * region: SARIF lines start at 1.
 */
import { RULES, fingerprint } from './rules.js';

const LEVEL = { high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY = { high: '8.0', medium: '5.0', low: '3.0', info: '0.0' };
const isPath = (s) => /[/.]/.test(s) && !/^[a-z]+:\/\//i.test(s) && !/\s/.test(s);

function location(ev) {
  if (!ev?.file) return null;
  if (!isPath(ev.file)) return { logicalLocations: [{ name: ev.file, kind: 'resource' }] };
  return {
    physicalLocation: {
      artifactLocation: { uri: ev.file, uriBaseId: 'PACKAGE' },
      ...(ev.line > 0 ? { region: { startLine: ev.line, ...(ev.text ? { snippet: { text: ev.text } } : {}) } } : {}),
    },
  };
}

function ruleFor(id) {
  const r = RULES[id] ?? { title: id, level: 'info', why: '', fix: '' };
  return {
    id,
    name: id.replace(/(^|-)([a-z])/g, (_, __, c) => c.toUpperCase()),
    shortDescription: { text: r.title },
    fullDescription: { text: r.why || r.title },
    help: { text: `${r.why} ${r.fix}`.trim(), markdown: `**Why it matters.** ${r.why}\n\n**What to do.** ${r.fix}` },
    defaultConfiguration: { level: LEVEL[r.level] },
    properties: { tags: ['security', 'mcp'], 'security-severity': SECURITY_SEVERITY[r.level] },
  };
}

/**
 * @param {Array<{target: string, package?: {name, version, ecosystem}, findings: object[]}>} scans
 * @param {{version: string}} tool
 */
export async function toSarif(scans, { version }) {
  const runs = [];
  for (const s of scans) {
    const ids = [...new Set(s.findings.map((f) => f.check))];
    const index = new Map(ids.map((id, i) => [id, i]));
    const results = [];
    for (const f of s.findings) {
      const locs = (f.evidence ?? []).map(location).filter(Boolean).slice(0, 3);
      results.push({
        ruleId: f.check,
        ruleIndex: index.get(f.check),
        level: LEVEL[f.severity] ?? 'note',
        message: { text: f.message.charAt(0).toUpperCase() + f.message.slice(1) },
        ...(locs.length ? { locations: locs } : {}),
        partialFingerprints: { 'deedroll/v1': await fingerprint(f) },
        properties: { severity: f.severity, 'security-severity': SECURITY_SEVERITY[f.severity], ...(f.subject ? { subject: f.subject } : {}) },
      });
    }
    const pkg = s.package;
    runs.push({
      tool: { driver: { name: 'deedroll', version, informationUri: 'https://github.com/varbees/deedroll', rules: ids.map(ruleFor) } },
      automationDetails: { id: `deedroll/${s.target}` },
      originalUriBaseIds: {
        PACKAGE: { description: { text: pkg ? `Files inside ${pkg.ecosystem ?? 'npm'} package ${pkg.name}@${pkg.version}` : `Files of ${s.target}` } },
      },
      results,
      properties: { target: s.target, ...(pkg ? { package: pkg } : {}) },
    });
  }
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs };
}

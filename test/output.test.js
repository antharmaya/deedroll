import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { RULES, SCHEMA, fingerprint } from '../src/rules.js';
import { toSarif } from '../src/sarif.js';
import { toJsonV1 } from '../src/output.js';

const finding = (over = {}) => ({
  check: 'undeclared-env',
  subject: 'ACME_API_KEY',
  severity: 'high',
  message: 'reads ACME_API_KEY (looks like a credential) but the registry entry does not declare it',
  evidence: [{ file: 'dist/index.js', line: 12, text: 'const k = process.env.ACME_API_KEY' }],
  ...over,
});

test('every check id the code can emit is documented in the rules catalog', () => {
  const src = new URL('../src/', import.meta.url);
  const emitted = new Set();
  for (const f of readdirSync(src).filter((n) => n.endsWith('.js'))) {
    for (const m of readFileSync(new URL(f, src), 'utf8').matchAll(/check: '([a-z-]+)'/g)) emitted.add(m[1]);
  }
  const missing = [...emitted].filter((id) => !RULES[id]);
  assert.deepEqual(missing, [], `undocumented checks: ${missing.join(', ')}`);
});

test('fingerprints survive line moves and daily-changing counts, and differ by subject', async () => {
  const a = await fingerprint(finding());
  assert.equal(a, await fingerprint(finding({ evidence: [{ file: 'dist/index.js', line: 99, text: 'moved' }] })));
  assert.notEqual(a, await fingerprint(finding({ subject: 'OTHER_TOKEN' })));
  const day = (n) => fingerprint({ check: 'provenance', severity: 'low', message: `published ${n} day(s) ago`, evidence: [{ file: 'npm', line: 0 }] });
  assert.equal(await day(3), await day(4));
});

test('SARIF: levels, rule metadata, regions only for real lines, logical locations for pseudo-files', async () => {
  const doc = await toSarif(
    [{ target: 'npm:acme', package: { ecosystem: 'npm', name: 'acme', version: '1.0.0' }, findings: [finding(), { check: 'provenance', severity: 'medium', message: 'no repository field', evidence: [{ file: 'package.json', line: 0, text: 'repository: absent' }] }, { check: 'network-egress', severity: 'info', message: 'contacts x.example', evidence: [{ file: 'npm', line: 0 }] }] }],
    { version: '9.9.9' }
  );
  assert.equal(doc.version, '2.1.0');
  const [run] = doc.runs;
  assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ['undeclared-env', 'provenance', 'network-egress']);
  assert.ok(run.tool.driver.rules.every((r) => r.help.text && r.properties['security-severity']));
  const [cred, prov, egress] = run.results;
  assert.equal(cred.level, 'error');
  assert.equal(cred.locations[0].physicalLocation.region.startLine, 12);
  assert.equal(prov.level, 'warning');
  assert.equal(prov.locations[0].physicalLocation.region, undefined, 'line 0 is "no line", not line 0');
  assert.deepEqual(egress.locations[0].logicalLocations, [{ name: 'npm', kind: 'resource' }]);
  assert.match(cred.partialFingerprints['mcpscan/v1'], /^[0-9a-f]{16}$/);
});

test('JSON v1 envelope: schema tag, ecosystem, and an id on every finding', async () => {
  const doc = await toJsonV1({ target: 'pypi:acme', pkg: { ecosystem: 'pypi', name: 'acme', version: '1.0', sha256: 'ab', artifact: { filename: 'acme-1.0-py3-none-any.whl' } }, entry: null, declared: new Map(), findings: [finding()] }, { version: '9.9.9' });
  assert.equal(doc.schema, SCHEMA);
  assert.deepEqual(doc.package, { ecosystem: 'pypi', name: 'acme', version: '1.0', sha256: 'ab', file: 'acme-1.0-py3-none-any.whl' });
  assert.ok(doc.findings.every((f) => /^[0-9a-f]{16}$/.test(f.id)));
});

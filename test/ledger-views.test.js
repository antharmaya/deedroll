import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { gzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { censusOf, registryIndexOf } from '../scripts/ledger-views.js';
import { pctDown, censusText } from '../web/census-text.js';
import { findListing } from '../src/lookup.js';

const ok = (over = {}) => ({ version: '1.0.0', scanned: '2026-10-14', undeclared: [], readmeOnly: [], settings: [], hosts: [], caps: [], install: [], vulns: 0, provenance: false, flags: [], files: 1, ...over });
const rec = (name, packages, signals, gone = null) => ({ name, gone, latest: { name, packages }, signals });
const npm = (id) => ({ type: 'npm', id, version: '1.0.0', env: [] });

test('the census counts each listed server once, by the stated rule', () => {
  const records = [
    rec('io.x/flagged', [npm('a'), npm('b')], { 'npm:a': ok({ undeclared: [{ n: 'API_KEY', at: 'i.js:1' }] }), 'npm:b': ok({ readmeOnly: ['B_TOKEN'] }) }),
    rec('io.x/readme', [npm('c')], { 'npm:c': ok({ readmeOnly: ['C_TOKEN'] }) }),
    rec('io.x/clean', [npm('d')], { 'npm:d': ok() }),
    rec('io.x/missing', [npm('e')], { 'npm:e': { version: '1.0.0', scanned: '2026-10-14', error: 'not found', missing: true } }),
    rec('io.x/waiting', [npm('f')], {}),
    rec('io.x/oci', [{ type: 'oci', id: 'img' }], {}),
    rec('io.x/hosted', [], {}),
    // gone from the registry: not counted, even with a finding on record
    rec('io.x/gone', [npm('g')], { 'npm:g': ok({ undeclared: [{ n: 'G_KEY', at: 'g.js:1' }] }) }, '2026-10-10'),
  ];
  assert.deepEqual(censusOf(records, '2026-10-14'), {
    date: '2026-10-14', listings: 7, packaged: 5, otherOnly: 1, scanned: 3, failed: 1, missing: 1, notScanned: 1, undeclared: 1, readmeOnly: 1,
  });
});

test('shares are truncated to one decimal, never rounded up', () => {
  assert.equal(pctDown(1400, 15110), '9.2'); // 9.265…
  assert.equal(pctDown(2056, 15110), '13.6'); // 13.607…
  assert.equal(pctDown(1394, 15008), '9.2'); // 9.288…, which rounding would make 9.3
  assert.equal(pctDown(1, 3), '33.3');
  assert.equal(pctDown(0, 0), '0.0');
  const t = censusText({ date: '2026-10-14', scanned: 15110, undeclared: 2056, readmeOnly: 1400, failed: 0, notScanned: 0, otherOnly: 0 }, '2026-10-14T05:04:01Z');
  assert.equal(t.pct, '13.6%');
  assert.match(t.line, /^2,056 of the 15,110 servers .* 14 Oct 2026 /);
  assert.equal(t.built, 'Ledger last built 14 Oct 2026, 05:04 UTC.');
});

test('the nightly lookup index is what src/lookup.js reads, and covers only listed servers', async () => {
  const records = [
    rec('io.y/two', [npm('shared'), { type: 'pypi', id: 'Some_Pkg' }], {}),
    rec('io.y/one', [npm('shared')], {}),
    rec('io.y/gone', [npm('old')], {}, '2026-10-01'),
  ];
  const idx = registryIndexOf(records, { builtAt: new Date().toISOString(), snapshot: '2026-10-14' });
  assert.equal(idx.listings, 2);
  assert.deepEqual(idx.index, { shared: ['io.y/one', 'io.y/two'] });
  assert.deepEqual(idx.pypi, { 'some-pkg': ['io.y/two'] });
  // A complete, fresh index is trusted on a miss: no live search for a gone server's package.
  const miss = await findListing('old', { index: idx, fetchImpl: () => assert.fail('no live search expected') });
  assert.equal(miss.source, 'index-miss');
  const hit = await findListing('shared', { index: idx, fetchEntry: async (name) => ({ server: { name, packages: [{ registryType: 'npm', identifier: 'shared' }] } }) });
  assert.equal(hit.source, 'index');
  assert.equal(hit.entry.server.name, 'io.y/one');
});

test('the ledger build publishes the census in meta.json and the lookup index beside it', () => {
  const a = mkdtempSync(join(tmpdir(), 'ledger-'));
  mkdirSync(join(a, 'registry'));
  mkdirSync(join(a, 'scans'));
  const listing = (name, env = []) => ({ name, version: '1.0.0', description: name, repository: null, status: 'active', packages: [{ type: 'npm', id: name.split('/')[1], version: '1.0.0', transport: 'stdio', env }], remotes: [] });
  writeFileSync(join(a, 'registry', '2026-10-14.jsonl.gz'), gzipSync([listing('io.z/a'), listing('io.z/b', [{ name: 'API_KEY', secret: true, required: true }])].map((r) => JSON.stringify(r)).join('\n')));
  const scan = (id) => ({ key: `npm:${id}@1.0.0`, type: 'npm', id, version: '1.0.0', at: '2026-10-14T01:00:00Z', files: 1, provenance: false, reads: [{ n: 'API_KEY', cred: true, doc: false, at: 'i.js:1' }], dynamicEnv: 0, hosts: [], caps: [], install: [], vulns: [], other: [] });
  appendFileSync(join(a, 'scans', 'packages.jsonl'), `${JSON.stringify(scan('a'))}\n${JSON.stringify(scan('b'))}\n`);
  execFileSync('node', [new URL('../scripts/build-ledger.js', import.meta.url).pathname], { env: { ...process.env, DEEDROLL_ARCHIVE: a }, encoding: 'utf8' });
  const meta = JSON.parse(readFileSync(join(a, 'ledger', 'public', 'meta.json'), 'utf8'));
  // b declares API_KEY in its listing, so only a counts.
  assert.equal(meta.census.scanned, 2);
  assert.equal(meta.census.undeclared, 1);
  assert.ok(Date.parse(meta.builtAt));
  const idx = JSON.parse(readFileSync(join(a, 'ledger', 'public', 'registry-index.json'), 'utf8'));
  assert.deepEqual(idx.index, { a: ['io.z/a'], b: ['io.z/b'] });
  assert.equal(idx.snapshot, '2026-10-14');
  assert.equal(idx.builtAt, meta.builtAt);
});

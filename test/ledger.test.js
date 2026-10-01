import test from 'node:test';
import assert from 'node:assert/strict';
import { diffListing, emptyLedger, foldDay, foldProbes, toShards, fromShards, shardOf, searchIndex, searchFiles, searchStore, searchLedger, indexEntry, publicRecord, SHARDS, foldScans, signalOf, packageKey } from '../src/ledger.js';

const listing = (name, over = {}) => ({
  name,
  version: '1.0.0',
  description: `${name} server`,
  repository: null,
  status: 'active',
  packages: [{ type: 'npm', id: name.split('/').pop(), version: '1.0.0', transport: 'stdio', env: [{ name: 'API_KEY', secret: true, required: true }] }],
  remotes: [],
  ...over,
});

test('an unchanged listing has no changes, even when only timestamps moved', () => {
  const a = listing('io.x/a', { updatedAt: '2026-09-28' });
  assert.deepEqual(diffListing(a, { ...a, updatedAt: '2026-09-29' }), []);
});

test('reports a release, a new setting, a dropped secret flag and a moved endpoint as plain facts', () => {
  const a = listing('io.x/a', { remotes: [{ type: 'streamable-http', url: 'https://a.example/mcp', headers: [] }] });
  const b = listing('io.x/a', {
    version: '1.1.0',
    packages: [{ type: 'npm', id: 'a', version: '1.1.0', transport: 'stdio', env: [{ name: 'API_KEY', secret: false, required: true }, { name: 'REGION', secret: false, required: false }] }],
    remotes: [{ type: 'streamable-http', url: 'https://b.example/mcp', headers: [] }],
  });
  const c = diffListing(a, b);
  assert.deepEqual(c.find((x) => x.field === 'version'), { field: 'version', from: '1.0.0', to: '1.1.0' });
  assert.deepEqual(c.find((x) => x.field === 'settings'), { field: 'settings', package: 'npm:a', added: ['REGION'], removed: [], noLongerSecret: ['API_KEY'] });
  assert.deepEqual(c.find((x) => x.field === 'endpoints'), { field: 'endpoints', added: ['https://b.example/mcp'], removed: ['https://a.example/mcp'] });
});

test('a header added to an endpoint is a change of its own', () => {
  const a = listing('io.x/a', { remotes: [{ type: 'streamable-http', url: 'https://a.example/mcp', headers: [] }] });
  const b = listing('io.x/a', { remotes: [{ type: 'streamable-http', url: 'https://a.example/mcp', headers: ['Authorization'] }] });
  assert.deepEqual(diffListing(a, b), [{ field: 'headers', url: 'https://a.example/mcp', added: ['Authorization'], removed: [] }]);
});

test('folds days into a timeline: seen, changed, gone, back', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a'), listing('io.x/b')]);
  foldDay(l, '2026-09-29', [listing('io.x/a', { version: '1.0.1' })]);
  foldDay(l, '2026-09-30', [listing('io.x/a', { version: '1.0.1' }), listing('io.x/b')]);
  const a = l.servers.get('io.x/a');
  const b = l.servers.get('io.x/b');
  assert.deepEqual(a.log.map((e) => e.kind), ['seen', 'changed']);
  assert.deepEqual(b.log.map((e) => [e.date, e.kind]), [['2026-09-28', 'seen'], ['2026-09-29', 'gone'], ['2026-09-30', 'back']]);
  assert.equal(b.gone, null);
  assert.equal(l.start, '2026-09-28');
  assert.equal(l.last, '2026-09-30');
});

test('re-folding a day already in the ledger changes nothing', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a')]);
  foldDay(l, '2026-09-29', [listing('io.x/a', { version: '2' })]);
  const before = JSON.stringify([...l.servers.values()]);
  foldDay(l, '2026-09-29', [listing('io.x/a', { version: '3' })]);
  assert.equal(JSON.stringify([...l.servers.values()]), before);
});

// The reason the storage is cheap to change: a full rebuild from the snapshots must equal the
// nightly incremental build, including a save and reload of the state in between.
test('rebuilding from scratch equals the nightly incremental build after a save and reload', () => {
  const days = [
    ['2026-09-28', [listing('io.x/a'), listing('io.x/b')]],
    ['2026-09-29', [listing('io.x/a', { version: '2' }), listing('io.x/c')]],
    ['2026-09-30', [listing('io.x/a', { version: '2', remotes: [{ type: 'sse', url: 'https://a/mcp', headers: [] }] }), listing('io.x/b'), listing('io.x/c')]],
  ];
  const full = emptyLedger();
  for (const [d, rows] of days) foldDay(full, d, rows);

  const partial = emptyLedger();
  for (const [d, rows] of days.slice(0, 2)) foldDay(partial, d, rows);
  const saved = [...toShards(partial).values()].map((s) => JSON.parse(JSON.stringify({ servers: s })));
  const reloaded = fromShards(JSON.parse(JSON.stringify({ version: partial.version, start: partial.start, last: partial.last })), saved);
  foldDay(reloaded, ...days[2]);

  const norm = (l) => JSON.stringify([...l.servers.values()].sort((x, y) => x.name.localeCompare(y.name)));
  assert.equal(norm(reloaded), norm(full));
  assert.equal(reloaded.last, full.last);
});

test('probes enter the log only when the result changes', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/h', { packages: [], remotes: [{ type: 'streamable-http', url: 'https://h/mcp', headers: [] }] })]);
  const tools = (x) => ({ search: { description: 'd1', schema: 's1' }, ...x });
  foldProbes(l, '2026-09-28', [{ url: 'https://h/mcp', probed: true, reason: null, tools: tools() }]);
  foldProbes(l, '2026-09-29', [{ url: 'https://h/mcp', probed: true, reason: null, tools: tools() }]);
  foldProbes(l, '2026-09-30', [{ url: 'https://h/mcp', probed: true, reason: null, tools: { search: { description: 'd2', schema: 's1' }, fetch: { description: 'f', schema: 'f' } } }]);
  const probes = l.servers.get('io.x/h').log.filter((e) => e.kind === 'probe');
  assert.equal(probes.length, 2, 'the unchanged second day adds nothing');
  assert.equal(probes[0].first, true);
  assert.deepEqual([probes[1].added, probes[1].descriptionChanged, probes[1].removed], [['fetch'], ['search'], []]);
});

test('the published record carries no tool fingerprints', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/h', { remotes: [{ type: 'streamable-http', url: 'https://h/mcp', headers: [] }] })]);
  foldProbes(l, '2026-09-28', [{ url: 'https://h/mcp', probed: true, reason: null, tools: { t: { description: 'x', schema: 'y' } } }]);
  const pub = publicRecord(l.servers.get('io.x/h'));
  assert.equal(pub.probes['https://h/mcp'].tools, 1);
  assert.equal('fingerprint' in pub.probes['https://h/mcp'], false);
});

test('shards are stable and in range', () => {
  const k = shardOf('io.github.owner/server');
  assert.equal(k, shardOf('io.github.owner/server'));
  assert.ok(parseInt(k, 16) < SHARDS && k.length === 2);
});

test('search ranks an exact name, then a prefix, then a description match', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/weather'), listing('io.y/weatherkit'), listing('io.z/maps', { description: 'maps and weather' })]);
  const idx = [...l.servers.values()].map(indexEntry);
  assert.deepEqual(searchIndex(idx, 'io.x/weather').map((e) => e.n)[0], 'io.x/weather');
  assert.deepEqual(searchIndex(idx, 'weather').map((e) => e.n), ['io.x/weather', 'io.y/weatherkit', 'io.z/maps']);
  assert.deepEqual(searchIndex(idx, ''), []);
});

const storeOf = (entries) => searchStore(searchFiles([...entries].sort((a, b) => a.n.localeCompare(b.n))));

test('the text search gives exactly what the in-memory search gives', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/weather'), listing('io.y/weatherkit'), listing('io.z/maps', { description: 'maps and weather' }), listing('io.q/other')]);
  const idx = [...l.servers.values()].map(indexEntry);
  for (const q of ['weather', 'io.x/weather', 'maps', 'io.', 'nothing-like-this']) {
    assert.deepEqual(searchLedger(storeOf(idx), q).map((e) => e.n), searchIndex(idx, q).map((e) => e.n), q);
  }
});

test('a term found only inside the stored entry (not name or description) is not a hit', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a', { version: '9.9.9-unique' })]);
  const idx = [...l.servers.values()].map(indexEntry);
  assert.deepEqual(searchLedger(storeOf(idx), '9.9.9-unique'), []);
});

test('an exact name comes first even when hundreds of names share the term', () => {
  const rows = Array.from({ length: 400 }, (_, i) => listing(`ai.mcp${String(i).padStart(3, '0')}/mcp-tool`));
  rows.push(listing('zz.last/mcp'));
  const l = emptyLedger();
  foldDay(l, '2026-09-28', rows);
  const idx = [...l.servers.values()].map(indexEntry);
  assert.equal(searchLedger(storeOf(idx), 'zz.last/mcp')[0].n, 'zz.last/mcp');
});

test('three search files from different builds are refused, not mixed', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a'), listing('io.x/b')]);
  const idx = [...l.servers.values()].map(indexEntry);
  const tonight = searchFiles(idx, '2026-10-02T00:40Z');
  const lastNight = searchFiles(idx.slice(1), '2026-10-01T00:40Z');
  assert.equal(searchStore({ names: tonight.names, descs: tonight.descs, entries: lastNight.entries }), null);
  assert.ok(searchStore(tonight));
});

test('the build stamp line is never returned as a result', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a')]);
  const store = searchStore(searchFiles([...l.servers.values()].map(indexEntry), 'build-2026'));
  assert.deepEqual(searchLedger(store, 'build-2026'), []);
});

const scanOf = (id, version, reads, extra = {}) => ({ key: packageKey('npm', id, version), type: 'npm', id, version, at: '2026-09-29T01:00:00Z', files: 3, provenance: false, reads, dynamicEnv: 0, hosts: [], caps: [], install: [], vulns: [], other: [], ...extra });

test('reads are judged against what this listing declares, and README-documented ones kept apart', () => {
  const sig = signalOf(scanOf('a', '1.0.0', [
    { n: 'API_KEY', cred: true, doc: false, at: 'i.js:1' },      // declared by the listing
    { n: 'PAY_KEY', cred: true, doc: false, at: 'i.js:2' },      // mentioned nowhere
    { n: 'FREE_KEY', cred: true, doc: true, at: 'i.js:3' },      // README only
    { n: 'REGION', cred: false, doc: false, at: 'i.js:4' },      // a setting
  ]), { type: 'npm', id: 'a', version: '1.0.0', env: [{ name: 'API_KEY', secret: true }] });
  assert.deepEqual(sig.undeclared, [{ n: 'PAY_KEY', at: 'i.js:2' }]);
  assert.deepEqual(sig.readmeOnly, ['FREE_KEY']);
  assert.deepEqual(sig.settings, ['REGION']);
});

test('a release that starts reading a credential is logged; one with the same facts is not', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a')]);
  foldScans(l, '2026-09-28', [scanOf('a', '1.0.0', [{ n: 'API_KEY', cred: true, doc: false, at: 'i.js:1' }])]);
  foldDay(l, '2026-09-29', [listing('io.x/a', { version: '1.1.0', packages: [{ type: 'npm', id: 'a', version: '1.1.0', transport: 'stdio', env: [{ name: 'API_KEY', secret: true, required: true }] }] })]);
  foldScans(l, '2026-09-29', [scanOf('a', '1.1.0', [{ n: 'API_KEY', cred: true, doc: false, at: 'i.js:1' }, { n: 'X402_PRIVATE_KEY', cred: true, doc: false, at: 'pay.js:9' }])]);
  foldDay(l, '2026-09-30', [listing('io.x/a', { version: '1.1.1', packages: [{ type: 'npm', id: 'a', version: '1.1.1', transport: 'stdio', env: [{ name: 'API_KEY', secret: true, required: true }] }] })]);
  foldScans(l, '2026-09-30', [scanOf('a', '1.1.1', [{ n: 'API_KEY', cred: true, doc: false, at: 'i.js:1' }, { n: 'X402_PRIVATE_KEY', cred: true, doc: false, at: 'pay.js:9' }])]);
  const scanned = l.servers.get('io.x/a').log.filter((e) => e.kind === 'scanned');
  assert.equal(scanned.length, 2, 'first scan, then the release that added a key; the identical 1.1.1 adds nothing');
  assert.equal(scanned[0].first, true);
  assert.deepEqual(scanned[1].undeclared, { added: ['X402_PRIVATE_KEY'], removed: [] });
  assert.equal(indexEntry(l.servers.get('io.x/a')).x, 1);
});

test('a failed scan is kept as a fact but never logged as a change', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a')]);
  foldScans(l, '2026-09-28', [{ key: packageKey('npm', 'a', '1.0.0'), type: 'npm', id: 'a', version: '1.0.0', at: '2026-09-28T01:00:00Z', error: 'tarball 404' }]);
  const rec = l.servers.get('io.x/a');
  assert.equal(rec.log.filter((e) => e.kind === 'scanned').length, 0);
  assert.equal(rec.signals['npm:a'].error, 'tarball 404');
});

test('a listing that points at a package its registry does not have is marked missing', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a')]);
  foldScans(l, '2026-09-28', [{ key: packageKey('npm', 'a', '1.0.0'), type: 'npm', id: 'a', version: '1.0.0', at: '2026-09-28T01:00:00Z', error: 'version 1.0.0 not found for a' }]);
  assert.equal(l.servers.get('io.x/a').signals['npm:a'].missing, true);
  assert.equal(indexEntry(l.servers.get('io.x/a')).m, true);
  foldScans(l, '2026-09-28', [{ key: packageKey('npm', 'a', '1.0.0'), type: 'npm', id: 'a', version: '1.0.0', at: '2026-09-28T02:00:00Z', error: 'socket hang up' }]);
  assert.equal(l.servers.get('io.x/a').signals['npm:a'].missing, undefined, 'a network error is not evidence the package is missing');
});

test('scan entries for one day come out in the same order however the scans were batched', () => {
  const two = listing('io.x/two', { packages: [
    { type: 'npm', id: 'zeta', version: '1.0.0', transport: 'stdio', env: [] },
    { type: 'npm', id: 'alpha', version: '1.0.0', transport: 'stdio', env: [] },
  ] });
  const sZeta = scanOf('zeta', '1.0.0', []);
  const sAlpha = scanOf('alpha', '1.0.0', []);
  const once = emptyLedger();
  foldDay(once, '2026-09-28', [two]);
  foldScans(once, '2026-09-28', [sZeta, sAlpha]);
  const split = emptyLedger();
  foldDay(split, '2026-09-28', [two]);
  foldScans(split, '2026-09-28', [sAlpha]);
  foldScans(split, '2026-09-28', [sZeta]);
  assert.deepEqual(split.servers.get('io.x/two').log, once.servers.get('io.x/two').log);
});

test('a release that stops publishing with provenance is logged as a flag change', () => {
  const l = emptyLedger();
  foldDay(l, '2026-09-28', [listing('io.x/a')]);
  foldScans(l, '2026-09-28', [scanOf('a', '1.0.0', [], { provenance: true })]);
  foldDay(l, '2026-09-29', [listing('io.x/a', { version: '1.0.1', packages: [{ type: 'npm', id: 'a', version: '1.0.1', transport: 'stdio', env: [] }] })]);
  foldScans(l, '2026-09-29', [scanOf('a', '1.0.1', [], { provenance: false, other: [{ c: 'provenance-dropped', s: 'medium', x: null }] })]);
  const last = l.servers.get('io.x/a').log.at(-1);
  assert.equal(last.kind, 'scanned');
  assert.deepEqual(last.flags, { added: ['provenance-dropped'], removed: [] });
  assert.deepEqual(last.provenance, { from: true, to: false });
});

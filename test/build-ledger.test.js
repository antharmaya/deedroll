import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, readFileSync, readdirSync, cpSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { gzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';

const SCRIPT = new URL('../scripts/build-ledger.js', import.meta.url).pathname;
const run = (archive, ...args) => execFileSync('node', [SCRIPT, ...args], { env: { ...process.env, MCPSCAN_ARCHIVE: archive }, encoding: 'utf8' });
const listing = (name, version, env = []) => ({ name, version, description: name, repository: null, status: 'active', packages: [{ type: 'npm', id: name.split('/')[1], version, transport: 'stdio', env }], remotes: [] });
const scan = (id, version, at, reads) => ({ key: `npm:${id}@${version}`, type: 'npm', id, version, at, files: 1, provenance: false, reads, dynamicEnv: 0, hosts: [], caps: [], install: [], vulns: [], other: [] });
const day = (archive, date, rows) => writeFileSync(join(archive, 'registry', `${date}.jsonl.gz`), gzipSync(rows.map((r) => JSON.stringify(r)).join('\n')));
const addScan = (archive, s) => appendFileSync(join(archive, 'scans', 'packages.jsonl'), `${JSON.stringify(s)}\n`);

// The promise that keeps the storage cheap to change, held at the level of the real script:
// the nightly fold, with scans arriving between and after builds, equals a full rebuild.
test('the nightly build and a full rebuild produce the same public ledger', () => {
  const a = mkdtempSync(join(tmpdir(), 'ledger-'));
  mkdirSync(join(a, 'registry'));
  mkdirSync(join(a, 'scans'));

  day(a, '2026-09-28', [listing('io.x/a', '1.0.0'), listing('io.x/b', '1.0.0')]);
  addScan(a, scan('a', '1.0.0', '2026-09-28T01:00:00Z', [{ n: 'API_KEY', cred: true, doc: false, at: 'i.js:1' }]));
  run(a);
  // a scan made after that night's build, on the same day
  addScan(a, scan('b', '1.0.0', '2026-09-28T09:00:00Z', []));
  day(a, '2026-09-29', [listing('io.x/a', '1.1.0'), listing('io.x/b', '1.0.0')]);
  addScan(a, scan('a', '1.1.0', '2026-09-29T01:00:00Z', [{ n: 'API_KEY', cred: true, doc: false, at: 'i.js:1' }, { n: 'PAY_KEY', cred: true, doc: false, at: 'p.js:2' }]));
  run(a);
  day(a, '2026-09-30', [listing('io.x/a', '1.1.0')]);
  run(a);

  const b = mkdtempSync(join(tmpdir(), 'ledger-'));
  cpSync(join(a, 'registry'), join(b, 'registry'), { recursive: true });
  cpSync(join(a, 'scans'), join(b, 'scans'), { recursive: true });
  run(b, '--rebuild');

  const shards = (root) => Object.fromEntries(readdirSync(join(root, 'ledger', 'public', 'servers')).map((f) => [f, readFileSync(join(root, 'ledger', 'public', 'servers', f), 'utf8')]));
  assert.deepEqual(shards(a), shards(b));
  const all = Object.values(shards(a)).flatMap((t) => Object.values(JSON.parse(t).servers));
  const recA = all.find((r) => r.name === 'io.x/a');
  assert.deepEqual(recA.log.filter((e) => e.kind === 'scanned').map((e) => e.date), ['2026-09-28', '2026-09-29']);
  assert.equal(all.find((r) => r.name === 'io.x/b').gone, '2026-09-30');
});

// Found while mutation-testing the ordering: a scan made on a day whose snapshot was not built
// yet (a failed snapshot, a manual scan run) used to be folded against the previous day's
// listings, match nothing, and be skipped for good as the cursor moved past it.
test('a scan made before its day is in the ledger waits for that day instead of being lost', () => {
  const a = mkdtempSync(join(tmpdir(), 'ledger-'));
  mkdirSync(join(a, 'registry'));
  mkdirSync(join(a, 'scans'));
  day(a, '2026-09-28', [listing('io.x/a', '1.0.0')]);
  run(a);
  addScan(a, scan('a', '2.0.0', '2026-09-29T01:00:00Z', [{ n: 'NEW_KEY', cred: true, doc: false, at: 'n.js:1' }]));
  run(a); // the 09-29 snapshot does not exist yet
  day(a, '2026-09-29', [listing('io.x/a', '2.0.0')]);
  run(a);
  const all = readdirSync(join(a, 'ledger', 'public', 'servers')).flatMap((f) => Object.values(JSON.parse(readFileSync(join(a, 'ledger', 'public', 'servers', f), 'utf8')).servers));
  const rec = all.find((r) => r.name === 'io.x/a');
  assert.deepEqual(rec.signals['npm:a'].undeclared, [{ n: 'NEW_KEY', at: 'n.js:1' }]);
});

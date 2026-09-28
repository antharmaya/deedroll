import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { diffSnapshots } from '../scripts/snapshot.js';

const L = (name, over = {}) => ({ name, version: '1.0.0', status: 'active', packages: [{ type: 'npm', id: name, env: [{ name: 'A_KEY' }] }], remotes: [], ...over });

test('the daily diff: added, removed, status, declarations and endpoints', () => {
  const before = [L('a'), L('b'), L('c'), L('d', { remotes: [{ url: 'https://d.example/mcp' }] })];
  const after = [
    L('a'),
    L('c', { status: 'deleted' }),
    L('d', { remotes: [{ url: 'https://evil.example/mcp' }] }),
    L('e'),
    L('b', { version: '2.0.0', packages: [{ type: 'npm', id: 'b', env: [{ name: 'A_KEY' }, { name: 'NEW_SECRET' }] }] }),
  ];
  const d = diffSnapshots(before, after);
  assert.deepEqual(d.added, ['e']);
  assert.deepEqual(d.removed, []);
  assert.deepEqual(d.status, [{ name: 'c', from: 'active', to: 'deleted' }]);
  assert.deepEqual(d.declarations, [{ name: 'b', from: '1.0.0', to: '2.0.0' }]);
  assert.deepEqual(d.endpoints, [{ name: 'd', from: ['https://d.example/mcp'], to: ['https://evil.example/mcp'] }]);
  assert.deepEqual(diffSnapshots([L('x')], []).removed, ['x']);
});

test('--verify detects an altered file and a rewritten chain', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcpscan-archive-'));
  const run = () => {
    try {
      return { code: 0, out: execFileSync(process.execPath, ['scripts/snapshot.js', '--verify'], { env: { ...process.env, MCPSCAN_ARCHIVE: dir }, encoding: 'utf8' }) };
    } catch (err) {
      return { code: err.status, out: err.stdout };
    }
  };
  try {
    mkdirSync(join(dir, 'registry'));
    const sha = (b) => createHash('sha256').update(b).digest('hex');
    const files = ['one', 'two'].map((d, i) => {
      const bytes = Buffer.from(`day ${d}\n`);
      writeFileSync(join(dir, 'registry', `2026-01-0${i + 1}.jsonl.gz`), bytes);
      return { file: `registry/2026-01-0${i + 1}.jsonl.gz`, sha256: sha(bytes), bytes: bytes.length };
    });
    const l1 = JSON.stringify({ date: '2026-01-01', files: [files[0]], prev: null });
    const l2 = JSON.stringify({ date: '2026-01-02', files: [files[1]], prev: sha(l1) });
    writeFileSync(join(dir, 'chain.jsonl'), `${l1}\n${l2}\n`);
    assert.equal(run().code, 0);

    writeFileSync(join(dir, 'registry', '2026-01-01.jsonl.gz'), 'rewritten history\n');
    const altered = run();
    assert.equal(altered.code, 1);
    assert.match(altered.out, /ALTERED registry\/2026-01-01/);

    // Fixing the file's hash in the chain breaks the link to the next line instead.
    const forged = JSON.stringify({ date: '2026-01-01', files: [{ ...files[0], sha256: sha(Buffer.from('rewritten history\n')) }], prev: null });
    writeFileSync(join(dir, 'chain.jsonl'), `${forged}\n${l2}\n`);
    assert.match(run().out, /BROKEN CHAIN at 2026-01-02/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

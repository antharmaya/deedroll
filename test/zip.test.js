import test from 'node:test';
import assert from 'node:assert/strict';
import { readZip, stripTopDirectory, ZipError } from '../src/zip.js';
import { makeZip } from './helpers/make-zip.js';

const text = (u8) => Buffer.from(u8).toString('utf8');

test('reads stored and deflated entries, skipping directories', async () => {
  const zip = makeZip([
    { path: 'pkg/', content: '', method: 0 },
    { path: 'pkg/server.py', content: 'import os\nKEY = os.environ["ACME_API_KEY"]\n' },
    { path: 'pkg/data.json', content: '{"a":1}', method: 0 },
  ]);
  const { files } = await readZip(zip);
  assert.deepEqual([...files.keys()], ['pkg/server.py', 'pkg/data.json']);
  assert.match(text(files.get('pkg/server.py')), /ACME_API_KEY/);
  assert.equal(text(files.get('pkg/data.json')), '{"a":1}');
});

test('a zip bomb that lies about its size is cut off by what it inflates to', async () => {
  const bomb = makeZip([{ path: 'x.py', content: 'a'.repeat(3 * 1024 * 1024), declaredSize: 10 }]);
  const { files, skipped } = await readZip(bomb, { maxFileBytes: 1024 * 1024 });
  assert.equal(files.size, 0);
  assert.deepEqual(skipped, [{ path: 'x.py', reason: 'inflates past the size limit' }]);
});

test('encrypted entries are skipped, not half-read; keep() filters before inflating', async () => {
  const zip = makeZip([
    { path: 'secret.py', content: 'x', flags: 1 },
    { path: 'README.md', content: 'docs' },
    { path: 'ok.py', content: 'y' },
  ]);
  const { files, skipped } = await readZip(zip, { keep: (p) => p.endsWith('.py') });
  assert.deepEqual([...files.keys()], ['ok.py']);
  assert.deepEqual(skipped, [{ path: 'secret.py', reason: 'encrypted' }]);
});

test('garbage is refused with a ZipError', async () => {
  await assert.rejects(readZip(new Uint8Array(100)), ZipError);
});

test('stripTopDirectory drops a single wrapping directory, and only then', () => {
  const wrapped = new Map([['pkg-1.0/setup.py', 1], ['pkg-1.0/pkg/a.py', 2]]);
  assert.deepEqual([...stripTopDirectory(wrapped).keys()], ['setup.py', 'pkg/a.py']);
  const flat = new Map([['setup.py', 1], ['pkg/a.py', 2]]);
  assert.equal(stripTopDirectory(flat), flat);
});

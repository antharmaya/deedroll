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
import { splitDocs, DOC_FILE, keepNpmFile } from '../src/docs.js';

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

// Found live 2026-09-29: a "hardcoded fallback key" was the server's documented public
// free-tier key, stated in its README. A credential the README documents is a metadata
// placement gap, not a hidden read: low, and the message says where it is documented.
test('a credential its README documents is reported as worth knowing, not as a hidden read', () => {
  const pkg = pkgWith({ 'index.js': 'const k = process.env.ACME_API_KEY;\nconst s = process.env.OTHER_SECRET;\n' });
  pkg.docs = new Map([['README.md', Buffer.from('## Setup\nSet `ACME_API_KEY` to your key, or leave it unset to use the free tier.\n')]]);
  const findings = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  const acme = findings.find((f) => f.subject === 'ACME_API_KEY');
  const other = findings.find((f) => f.subject === 'OTHER_SECRET');
  assert.equal(acme.severity, 'low');
  assert.equal(acme.documented, 'README');
  assert.match(acme.message, /README documents it/);
  assert.equal(other.severity, 'high', 'a credential the README never mentions stays high');
  assert.equal(other.documented, undefined);
});

test('a README mention must be the whole name, not part of a longer one', () => {
  const pkg = pkgWith({ 'index.js': 'const k = process.env.API_KEY;\n' });
  pkg.docs = new Map([['README.md', Buffer.from('Set ACME_API_KEY_V2 for the new endpoint.\n')]]);
  const [f] = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(f.severity, 'high');
});

// The first version of the README check passed its tests and found nothing live: the
// package readers kept only code files, so no README ever reached it. This goes through the
// real tar reader, and checks the README stays out of every code check.
test('a README read from a real tarball reaches the credential check, and only that check', () => {
  const entries = [
    ['package/index.js', 'const k = process.env.ACME_API_KEY;\n'],
    ['package/README.md', 'Set `ACME_API_KEY`. Docs at https://docs.example.com\n```js\nconst t = process.env.README_ONLY_TOKEN;\n```\n'],
  ];
  const tar = Buffer.concat([...entries.map(([p, c]) => { const t = tarWith(p, c); return t.subarray(0, t.length - 1024); }), Buffer.alloc(1024)]);
  const { files, docs } = splitDocs(readTarGz(gzipSync(tar), { keep: keepNpmFile }));
  assert.equal(docs.size, 1, 'the README lands in docs');
  assert.ok(![...files.keys()].some((p) => DOC_FILE.test(p)), 'and never in the code files');
  const pkg = { ...pkgWith({}), files, docs };
  const env = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.deepEqual(env.map((f) => [f.subject, f.severity, f.documented]), [['ACME_API_KEY', 'low', 'README']]);
  assert.deepEqual(checkNetworkEgress(pkg, null), [], "a README link is not the server contacting a host");
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

test('a variable only ever mentioned in a comment is not evidence; a real read elsewhere still is', () => {
  // Found live (@vidofy/mcp, 2026-09-29): a JSDoc paragraph explaining old debugging
  // history literally contained "process.env.REDIS_PASSWORD", and the checker cited that
  // prose line as proof of a read the package's real code made three lines further down.
  const pkg = pkgWith({
    'store.js': [
      '/**',
      ' * Historically this broke because `process.env.REDIS_PASSWORD` was empty',
      ' * unless a human exported it by hand.',
      ' */',
      '// process.env.REDIS_PASSWORD would also be a comment here',
      '# process.env.REDIS_PASSWORD (python-style full-line comment too)',
      'const real = process.env.REDIS_PASSWORD;',
    ].join('\n'),
  });
  const findings = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(findings.length, 1, 'one variable, not one finding per mention');
  assert.equal(findings[0].evidence.length, 1);
  assert.equal(findings[0].evidence[0].line, 7, 'evidence is the real code line, not a comment line');
  assert.match(findings[0].evidence[0].text, /const real/);
});

test('a mid-line comment (code followed by //) is still scanned: only whole-line comments are skipped', () => {
  const pkg = pkgWith({ 'index.js': 'const k = process.env.ACME_API_KEY; // read once at startup\n' });
  const findings = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence[0].line, 1);
});

test('a package\'s own test suite stubbing env vars is not evidence the server reads them', () => {
  // Found live (@digital-science-dsl/dimensions-analytics-mcp, 2026-09-29): three of four
  // flagged variables were only ever set or deleted inside the package's own *.test.ts
  // fixtures, testing its config-loader — not a real read by the shipped server.
  const pkg = pkgWith({
    'dist/config.js': 'const real = process.env.REAL_SERVER_SECRET;\n',
    'test/client/config/loader.test.ts': 'process.env.FAKE_TEST_SECRET = "test-value";\ndelete process.env.FAKE_TEST_SECRET;\n',
    'tests/other.spec.js': 'process.env.ANOTHER_FAKE_KEY = "x";\n',
    'src/test_helpers.py': 'os.environ["PY_FAKE_TOKEN"] = "x"\n',
  });
  const findings = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.deepEqual(findings.map((f) => f.subject), ['REAL_SERVER_SECRET']);
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

// Found in the first full registry scan (2026-10-01): names that describe a credential (where
// it is stored, its scope, the header it goes in) are settings, not credentials.
test('names that describe a credential rather than hold one are not credentials', () => {
  for (const n of ['REVIEWABLE_MCP_CREDENTIAL_BACKEND', 'RATE_LIMIT_REDIS_KEY_PREFIX', 'FL_API_KEY_HEADER', 'MCP_OAUTH_SCOPES',
    'SERVICENOW_AUTH_METHOD', 'X402_TOKEN_ADDRESS', 'SSH_AUTH_SOCK', 'TYPESHIP_CREDENTIAL_STORE', 'PDFGATE_WEBHOOK_PORT',
    'SAP_MCP_AUTH_TYPE', 'COINBASE_CDP_KEY_NAME', '__NEXT_PRIVATE_CPU_PROFILE', 'NEXT_PRIVATE_WORKER']) {
    assert.equal(isCredentialName(n), false, n);
  }
});

test('key material in another encoding is still a credential', () => {
  for (const n of ['MCP_CLIENT_PRIVATE_KEY_PEM', 'FIDACY_SIGNING_KEY_B64', 'GCS_SERVICE_ACCOUNT_KEY_JSON', 'MINITOK_MCP_AUTH_TOKEN_NEXT', 'AWS_ACCESS_KEY_ID', 'X402_PRIVATE_KEY']) {
    assert.equal(isCredentialName(n), true, n);
  }
});

// Found live 2026-10-02 (@uplink-code/mcp@0.1.4): the server ships example code for the agent
// as a string, so process.env.UPLINK_API_KEY appeared in its instructions text and was
// reported as a high-severity read. The server never reads it. A mention that only ever sits
// inside a string is info, with the text as evidence; a real read anywhere keeps its severity.
test('an env var that only appears inside a string is info, not a read', () => {
  const pkg = pkgWith({ 'index.js': 'const help = "const s = uplink.session(process.env.ACME_API_KEY)\\n// call it";\n' });
  const [f] = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(f.severity, 'info');
  assert.equal(f.inText, true);
  assert.match(f.message, /only inside a string/);
  assert.equal(f.evidence[0].line, 1);
});

test('a real read keeps its severity even when the same name also appears in text', () => {
  const pkg = pkgWith({ 'index.js': 'const help = `set process.env.ACME_API_KEY first`;\nconst k = process.env.ACME_API_KEY;\n' });
  const [f] = checkUndeclaredSecrets(pkg, { server: { name: 'x' } }, new Map());
  assert.equal(f.severity, 'high');
  assert.equal(f.inText, undefined);
  assert.equal(f.evidence[0].line, 2, 'evidence is the real read, not the text');
});

test('string detection survives quotes, regex literals and template expressions on one minified line', () => {
  const cases = [
    ['const a = "it\'s"; const k = process.env.ACME_API_KEY;', 'high'],
    ['s.replace(/"/g, ""); const k = process.env.ACME_API_KEY;', 'high'],
    ['const u = `${process.env.ACME_API_KEY}`;', 'high'],
    ['const u = `a ${x ? "b" : `c`} d`; const k = process.env.ACME_API_KEY;', 'high'],
    ["const t = 'use process.env.ACME_API_KEY in your code';", 'info'],
  ];
  for (const [line, want] of cases) {
    const [f] = checkUndeclaredSecrets(pkgWith({ 'index.js': `${line}\n` }), { server: { name: 'x' } }, new Map());
    assert.equal(f.severity, want, line);
  }
});

test('a template literal that opens lines earlier still counts as text (the live uplink shape)', () => {
  const src = 'const guide = `Write a script like this:\nconst session = await uplink.session(process.env.ACME_API_KEY)\nthen pair the device.`;\nexport default guide;\n';
  const [f] = checkUndeclaredSecrets(pkgWith({ 'lib/index.js': src }), { server: { name: 'x' } }, new Map());
  assert.equal(f.severity, 'info');
  assert.equal(f.evidence[0].line, 2);
});

test('a line comment with an apostrophe does not swallow the next line\'s real read', () => {
  const src = "// don't forget the key\nconst k = process.env.ACME_API_KEY;\n";
  const [f] = checkUndeclaredSecrets(pkgWith({ 'index.js': src }), { server: { name: 'x' } }, new Map());
  assert.equal(f.severity, 'high');
});

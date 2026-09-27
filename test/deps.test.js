import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveVersion } from '../src/sources.js';
import { selectDependencies, vendorToken, mergeDependencies } from '../src/deps.js';
import { runAllChecks, checkDependencyInstallScripts } from '../src/checks.js';
import { extractTools } from '../src/tools.js';

const packument = {
  'dist-tags': { latest: '1.9.0', next: '2.0.0-rc.1' },
  versions: Object.fromEntries(
    ['0.8.0', '0.8.3', '0.9.0', '1.2.0', '1.4.2', '1.4.9', '1.9.0', '2.0.0-rc.1', '1.64.0-alpha-17'].map((v) => [v, {}])
  ),
};

// ---------- version resolution: every spec shape seen in real vendor manifests ----------

test('exact versions, including pre-release pins (Playwright shape)', () => {
  assert.deepEqual(resolveVersion(packument, '1.4.2'), { version: '1.4.2', approximate: false });
  assert.deepEqual(resolveVersion(packument, '1.64.0-alpha-17'), { version: '1.64.0-alpha-17', approximate: false });
});

test('dist-tags (PayPal depends on @paypal/agent-toolkit@latest)', () => {
  assert.equal(resolveVersion(packument, 'latest').version, '1.9.0');
  assert.equal(resolveVersion(packument, 'next').version, '2.0.0-rc.1');
  assert.equal(resolveVersion(packument, '*').version, '1.9.0');
});

test('caret ranges stay within the major, and within the minor below 1.0 (Supabase ^0.8.0)', () => {
  assert.equal(resolveVersion(packument, '^1.2.0').version, '1.9.0');
  assert.equal(resolveVersion(packument, '^0.8.0').version, '0.8.3');
});

test('tilde ranges stay within the minor, and never pick a pre-release', () => {
  assert.equal(resolveVersion(packument, '~1.4.0').version, '1.4.9');
  assert.equal(resolveVersion(packument, '^1.0.0').version, '1.9.0', 'not 1.64.0-alpha');
});

test('an unsupported range falls back to latest and says so', () => {
  assert.deepEqual(resolveVersion(packument, '>=1.0.0 <2.0.0'), { version: '1.9.0', approximate: true });
});

// ---------- which dependencies to follow (the real vendor manifests) ----------

const names = (r) => r.follow.map((d) => d.name);

test('vendor token: scope for scoped packages, first word otherwise', () => {
  assert.equal(vendorToken('@playwright/mcp'), 'playwright');
  assert.equal(vendorToken('mongodb-mcp-server'), 'mongodb');
});

test('Playwright: follows playwright and playwright-core', () => {
  const m = { dependencies: { playwright: '1.64.0', 'playwright-core': '1.64.0' } };
  assert.deepEqual(names(selectDependencies(m, '@playwright/mcp')), ['playwright', 'playwright-core']);
});

test('MongoDB: follows @mongodb-js/mcp-*, never the MCP SDK, not generic deps', () => {
  const m = {
    dependencies: {
      '@mongodb-js/mcp-tools-mongodb': '3.0.4',
      '@mongodb-js/mcp-core': '3.0.4',
      '@modelcontextprotocol/node': '^2.0.0',
      '@mongosh/service-provider-node-driver': '^5.0.2',
    },
  };
  assert.deepEqual(names(selectDependencies(m, 'mongodb-mcp-server')), ['@mongodb-js/mcp-tools-mongodb', '@mongodb-js/mcp-core']);
});

test('PayPal: same scope is followed, colors and the SDK are not', () => {
  const m = { dependencies: { colors: '^1.4.0', '@paypal/agent-toolkit': 'latest', '@modelcontextprotocol/sdk': '^1.6.1' } };
  assert.deepEqual(names(selectDependencies(m, '@paypal/mcp')), ['@paypal/agent-toolkit']);
});

test('Stripe: nothing to follow (a shim for a hosted server)', () => {
  const m = { dependencies: { colors: '^1.4.0', '@modelcontextprotocol/sdk': '^1.17.1' } };
  assert.deepEqual(names(selectDependencies(m, '@stripe/mcp')), []);
});

test('the count cap reports how many were left out', () => {
  const deps = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`@v/mcp-${i}`, '1.0.0']));
  const r = selectDependencies({ dependencies: deps }, '@v/root', { max: 16 });
  assert.equal(r.follow.length, 16);
  assert.equal(r.capped, 4);
});

// ---------- merged virtual package ----------

const buf = (s) => Buffer.from(s, 'utf8');
const root = {
  name: '@acme/mcp',
  version: '1.0.0',
  manifest: { name: '@acme/mcp' },
  files: new Map([['cli.js', buf('import "@acme/core";')]]),
};
const dep = {
  name: '@acme/core',
  version: '2.0.0',
  manifest: { scripts: { postinstall: 'node fetch-binary.js' } },
  files: new Map([
    ['package.json', buf('{"description": "not code", "https://evil.example.net": 1}')],
    ['tools.js', buf('server.registerTool("run_cmd", { description: "Runs a command" }, h);\nexec(cmd);')],
  ]),
};

test('dependency files land under node_modules/<name>/, but tool-shaped code there is never a tool', () => {
  const merged = mergeDependencies(root, [dep]);
  assert.ok(merged.files.has('node_modules/@acme/core/tools.js'));
  // Measured: 49 tools found inside vendor dependencies, ~0 of them the server's own.
  assert.deepEqual(extractTools(merged.files).tools, []);
});

test('capabilities in a dependency are reported with the dependency path; its package.json is not read as code', () => {
  const merged = mergeDependencies(root, [dep]);
  const findings = runAllChecks({ pkg: merged, entry: null, declared: new Map(), officialNames: [] });
  const exec = findings.find((f) => f.check === 'capability' && /process execution/.test(f.message));
  assert.equal(exec.evidence[0].file, 'node_modules/@acme/core/tools.js');
  assert.ok(!findings.some((f) => f.check === 'network-egress' && /evil\.example\.net/.test(f.message)));
});

test('a followed dependency\'s postinstall is flagged, because npm runs it on the user\'s machine', () => {
  const [f] = checkDependencyInstallScripts(mergeDependencies(root, [dep]));
  assert.equal(f.severity, 'high');
  assert.match(f.message, /dependency @acme\/core@2\.0\.0 runs a postinstall/);
});

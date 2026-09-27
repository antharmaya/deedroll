import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveLaunch, parseCodexToml, discoverInstalled, configFindings } from '../src/installed.js';
import { renderInstalled } from '../src/report.js';

const SECRET = 'sk-live-THIS-MUST-NEVER-APPEAR-9f8e7d';

// ---------- launch resolution ----------

test('npx with a pinned scoped version', () => {
  assert.deepEqual(resolveLaunch({ command: 'npx', args: ['-y', '@acme/mcp@1.4.2'] }), {
    kind: 'npm',
    name: '@acme/mcp',
    version: '1.4.2',
    pinned: true,
  });
});

test('npx with no version, or @latest, is unpinned', () => {
  assert.equal(resolveLaunch({ command: 'npx', args: ['-y', 'some-mcp'] }).pinned, false);
  assert.equal(resolveLaunch({ command: 'npx', args: ['some-mcp@latest'] }).pinned, false);
});

test('npm exec --package, pnpm dlx and a full path to npx all resolve', () => {
  assert.equal(resolveLaunch({ command: 'npm', args: ['exec', '--package=foo@2.0.0', '--', 'foo'] }).name, 'foo');
  assert.equal(resolveLaunch({ command: 'pnpm', args: ['dlx', 'bar'] }).name, 'bar');
  assert.equal(resolveLaunch({ command: '/usr/local/bin/npx', args: ['baz'] }).name, 'baz');
});

test('uvx, docker, remote, local scripts and binaries are classified, not guessed', () => {
  assert.equal(resolveLaunch({ command: 'uvx', args: ['mcp-server-fetch'] }).kind, 'pypi');
  assert.equal(resolveLaunch({ command: 'uvx', args: ['pkg==1.2.0'] }).pinned, true);
  assert.equal(resolveLaunch({ command: 'docker', args: ['run', '-i', 'img'] }).kind, 'container');
  assert.deepEqual(resolveLaunch({ type: 'http', url: 'https://mcp.example.com/sse?token=abc' }), {
    kind: 'remote',
    host: 'mcp.example.com',
  });
  assert.equal(resolveLaunch({ command: 'node', args: ['/x/server.js'] }).kind, 'local');
  assert.equal(resolveLaunch({ command: 'gk', args: ['mcp'] }).kind, 'binary');
});

// ---------- codex toml ----------

test('codex toml: sub-tables belong to their server, never become servers', () => {
  const toml = [
    '[mcp_servers.node_repl]',
    'command = "npx"',
    'args = ["-y", "node-repl-mcp"]',
    '[mcp_servers.node_repl.env]',
    `API_KEY = "${SECRET}"`,
    '[mcp_servers.stitch]',
    'url = "https://stitch.example.com/mcp"',
    '[mcp_servers.stitch.http_headers]',
    `Authorization = "Bearer ${SECRET}"`,
    '[mcp_servers."quoted name"]',
    'command = "uvx"',
    'args = [',
    '  "some-pkg",',
    ']',
    '[profiles.default]',
    'model = "x"',
  ].join('\n');
  const servers = parseCodexToml(toml);
  assert.deepEqual(servers.map((s) => s.name), ['node_repl', 'stitch', 'quoted name']);
  assert.equal(servers[0].launch.name, 'node-repl-mcp');
  assert.equal(servers[1].launch.kind, 'remote');
  assert.equal(servers[2].launch.name, 'some-pkg', 'multi-line array folded');
  assert.equal(servers[0].env.API_KEY.literal, true);
});

// ---------- secrets never leave the parser ----------

function fakeHome() {
  const home = mkdtempSync(join(tmpdir(), 'mcpscan-home-'));
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({
      mcpServers: {
        leaky: { command: 'npx', args: ['-y', 'leaky-mcp', `--api-key=${SECRET}`], env: { OPENAI_API_KEY: SECRET } },
        referenced: { command: 'npx', args: ['ok-mcp@1.0.0'], env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' } },
      },
      projects: { '/work/app': { mcpServers: { remote: { type: 'http', url: `https://r.example.com/?key=${SECRET}`, headers: { Authorization: `Bearer ${SECRET}` } } } } },
    })
  );
  mkdirSync(join(home, '.codex'));
  writeFileSync(join(home, '.codex', 'config.toml'), `[mcp_servers.c]\ncommand = "uvx"\nargs = ["c-mcp"]\n[mcp_servers.c.env]\nSECRET_TOKEN = "${SECRET}"\n`);
  return home;
}

test('a planted secret appears nowhere: not in discovery, findings, JSON or rendering', () => {
  const home = fakeHome();
  try {
    const found = discoverInstalled({ home, cwd: home });
    assert.equal(found.servers.length, 4);
    const withFindings = {
      configs: found.configs,
      servers: found.servers.map((s) => ({ ...s, pkg: null, findings: configFindings(s) })),
      packagesScanned: 0,
    };
    const surfaces = [JSON.stringify(found), JSON.stringify(withFindings), renderInstalled(withFindings, { all: true })];
    for (const text of surfaces) assert.ok(!text.includes(SECRET), 'secret leaked into output');
    assert.ok(!surfaces[2].includes('?key='), 'URL query strings must not be shown');
    assert.ok(surfaces[2].includes('r.example.com'), 'the host is still shown');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('plaintext secrets are reported by name; ${REFERENCES} are not', () => {
  const home = fakeHome();
  try {
    const { servers } = discoverInstalled({ home, cwd: home });
    const byName = Object.fromEntries(servers.map((s) => [s.name, configFindings(s)]));
    const subjects = (n) => byName[n].filter((f) => f.check === 'plaintext-secret').map((f) => f.subject).sort();
    assert.deepEqual(subjects('leaky'), ['OPENAI_API_KEY', 'api-key']);
    assert.deepEqual(subjects('referenced'), []);
    assert.deepEqual(subjects('remote'), ['Authorization']);
    assert.deepEqual(subjects('c'), ['SECRET_TOKEN']);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('unpinned launches are flagged, pinned ones are not', () => {
  const home = fakeHome();
  try {
    const { servers } = discoverInstalled({ home, cwd: home });
    const unpinned = servers.filter((s) => configFindings(s).some((f) => f.check === 'unpinned-launch')).map((s) => s.name);
    assert.deepEqual(unpinned.sort(), ['c', 'leaky']);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('project-scoped servers keep their project', () => {
  const home = fakeHome();
  try {
    const remote = discoverInstalled({ home, cwd: home }).servers.find((s) => s.name === 'remote');
    assert.equal(remote.scope, 'project:/work/app');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('an unreadable config is reported, not fatal', () => {
  const home = mkdtempSync(join(tmpdir(), 'mcpscan-home-'));
  try {
    writeFileSync(join(home, '.claude.json'), '{ not json');
    const { configs, servers } = discoverInstalled({ home, cwd: home });
    assert.equal(servers.length, 0);
    assert.ok(configs[0].error);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

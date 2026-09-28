import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { findMcpEndpoint, validatesOrigin, judgeLocal, FOREIGN_ORIGIN } from '../src/local-core.js';
import { listeningPorts, expandSubnet } from '../src/local.js';

/** A real local MCP server (2026-07-28, stateless). `checkOrigin` decides whether it follows the spec's Origin rule. */
function mcpServer({ checkOrigin }) {
  const server = createServer((req, res) => {
    if (checkOrigin && req.headers.origin && req.headers.origin !== 'http://localhost') {
      res.writeHead(403);
      return res.end();
    }
    if (req.method !== 'POST' || req.url !== '/mcp') {
      res.writeHead(404);
      return res.end();
    }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const msg = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { resultType: 'complete', tools: [{ name: 'run_shell', description: 'Runs a command' }] } }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` })));
}

test('a local server that answers any website is found and judged high; one that checks Origin is not', async () => {
  const bad = await mcpServer({ checkOrigin: false });
  const good = await mcpServer({ checkOrigin: true });
  try {
    const b = await findMcpEndpoint(bad.base);
    assert.equal(b.url, `${bad.base}/mcp`);
    assert.deepEqual(b.tools.map((t) => t.name), ['run_shell']);
    assert.equal(await validatesOrigin(b.url), false);
    const g = await findMcpEndpoint(good.base);
    assert.equal(await validatesOrigin(g.url), true);

    const badFindings = judgeLocal({ ...b, bind: '127.0.0.1', originValidated: false }).map((f) => [f.check, f.severity]);
    assert.deepEqual(badFindings, [['no-origin-validation', 'high'], ['unauthenticated', 'info']]);
    assert.ok(!judgeLocal({ ...g, bind: '127.0.0.1', originValidated: true }).some((f) => f.check === 'no-origin-validation'));
  } finally {
    bad.server.close();
    good.server.close();
  }
});

test('binding every interface: high with no sign-in, medium with it', () => {
  const open = judgeLocal({ url: 'http://127.0.0.1:3000/mcp', bind: '0.0.0.0', answered: true, tools: [], originValidated: true });
  assert.deepEqual(open.find((f) => f.check === 'local-network-exposed').severity, 'high');
  const signedIn = judgeLocal({ url: 'http://127.0.0.1:3000/mcp', bind: '::', answered: false, auth: true });
  assert.deepEqual(signedIn.map((f) => [f.check, f.severity]), [['local-network-exposed', 'medium']]);
});

test('nothing that is not MCP is reported', async () => {
  const plain = createServer((req, res) => res.end('<html>hello</html>'));
  await new Promise((r) => plain.listen(0, '127.0.0.1', r));
  try {
    assert.equal(await findMcpEndpoint(`http://127.0.0.1:${plain.address().port}`, { timeoutMs: 1500 }), null);
  } finally {
    plain.close();
  }
});

test('listening ports come from the operating system, with the owning process', { skip: process.platform !== 'linux' }, async () => {
  const s = await mcpServer({ checkOrigin: true });
  try {
    const port = Number(new URL(s.base).port);
    const l = listeningPorts().find((x) => x.port === port);
    assert.equal(l.bind, '127.0.0.1');
    assert.match(l.process, /node/);
  } finally {
    s.server.close();
  }
});

test('--subnet only scans a private range of at most 256 addresses', () => {
  assert.equal(expandSubnet('192.168.1.0/24').length, 254);
  assert.deepEqual(expandSubnet('10.0.0.8/30'), ['10.0.0.9', '10.0.0.10']);
  assert.throws(() => expandSubnet('8.8.8.0/24'), /private ranges/);
  assert.throws(() => expandSubnet('10.0.0.0/16'), /at most a \/24/);
  assert.throws(() => expandSubnet('nonsense'), /a\.b\.c\.d\/nn/);
  assert.ok(FOREIGN_ORIGIN.endsWith('.invalid'), 'the probe Origin can never be a real site');
});

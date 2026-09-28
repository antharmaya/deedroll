import test from 'node:test';
import assert from 'node:assert/strict';
import { privateAddress, validateTarget, createLimiter, handleProbe, ipv6Bytes } from '../src/relay-core.js';
import { guardedFetch } from '../src/relay-node.js';

test('private and special addresses are refused, in every IPv6 disguise', () => {
  const priv = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::',
    '::ffff:7f00:1', // how the URL parser rewrites [::ffff:127.0.0.1]: the bypass found on 2026-09-28
    '::ffff:127.0.0.1', '::7f00:1', '64:ff9b::a00:1', '2002:7f00:1::', '2001:0:4136::1', 'fe80::1', 'fd00::1', 'ff02::1', 'not-an-ip'];
  const pub = ['8.8.8.8', '1.1.1.1', '::ffff:808:808', '2002:808:808::', '2606:4700::1111'];
  for (const ip of priv) assert.equal(privateAddress(ip), true, ip);
  for (const ip of pub) assert.equal(privateAddress(ip), false, ip);
  assert.deepEqual(ipv6Bytes('::1').slice(-2), [0, 1]);
  assert.equal(ipv6Bytes('1::2::3'), null);
});

test('the relay accepts one clean https URL and nothing else', () => {
  assert.ok(validateTarget('https://mcp.example.com/mcp').url);
  for (const bad of ['http://mcp.example.com/mcp', 'https://u:p@mcp.example.com/mcp', 'https://localhost/mcp', 'https://printer.local/mcp',
    'https://[::ffff:127.0.0.1]/mcp', 'https://169.254.169.254/', 'not a url', '', 42, `https://x.com/${'a'.repeat(3000)}`]) {
    assert.ok(validateTarget(bad).error, String(bad).slice(0, 40));
  }
});

test('the pinned fetch refuses private destinations at connect time, whatever the first check said', async () => {
  for (const url of ['https://127.0.0.1/mcp', 'https://[::ffff:7f00:1]/mcp', 'https://[::1]/mcp']) {
    await assert.rejects(guardedFetch(url), /private address/, url);
  }
  await assert.rejects(guardedFetch('http://example.com/'), /only fetches https/);
});

test('rate limit: a fixed window per caller', () => {
  const allow = createLimiter({ max: 2, windowMs: 1000 });
  assert.deepEqual([allow('a', 0), allow('a', 1), allow('a', 2), allow('b', 2), allow('a', 1001)], [true, true, false, true, true]);
});

test('the relay runs the read-only probe and keeps its answer shape', async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    const msg = JSON.parse(init.body);
    seen.push(msg.method);
    return Response.json({ jsonrpc: '2.0', id: msg.id, result: { resultType: 'complete', tools: [{ name: 'search', description: 'Search the docs' }] } });
  };
  const r = await handleProbe({ url: 'https://mcp.example.com/mcp' }, { fetchImpl });
  assert.equal(r.status, 200);
  assert.equal(r.body.via, 'relay');
  assert.equal(r.body.remote.era, 'modern');
  assert.deepEqual(r.body.tools.map((t) => t.name), ['search']);
  assert.deepEqual(seen, ['tools/list'], 'discovery only');
  assert.equal((await handleProbe({ url: 'http://x.com' }, { fetchImpl })).status, 400);
  assert.equal((await handleProbe({ url: 'https://x.com/mcp' }, { fetchImpl, limiter: () => false })).status, 429);
});

test('a hostile server cannot aim the relay inward through its own OAuth metadata', async () => {
  // The MCP server itself is public; its metadata names a private "authorization server".
  const { inspectAuth } = await import('../src/auth.js');
  const asked = [];
  const fetchImpl = async (url, init) => {
    asked.push(url);
    if (url.startsWith('https://mcp.example.com/')) return Response.json({ resource: 'https://mcp.example.com/mcp', authorization_servers: ['https://10.0.0.5'] });
    return guardedFetch(url, init); // the relay's own fetch for everything else
  };
  const r = await inspectAuth('https://mcp.example.com/mcp', { fetchImpl, timeoutMs: 3000 });
  assert.ok(asked.some((u) => u.startsWith('https://10.0.0.5/')), 'it tried');
  assert.equal(r.auth.unreadable, true, 'and got nothing back');
  assert.deepEqual(r.findings, [], 'refused is unknown, not a finding against the server');
});

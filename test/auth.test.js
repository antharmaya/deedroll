import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectAuth, resourceMetadataUrls, authServerMetadataUrls } from '../src/auth.js';
import { annotationSummary } from '../src/remote-scan.js';

/** A fake web of metadata documents: url -> JSON (or a status number). Records what was asked. */
function web(docs) {
  const asked = [];
  const fetchImpl = async (url) => {
    asked.push(url);
    const d = docs[url];
    if (d === undefined) return new Response('', { status: 404 });
    if (typeof d === 'number') return new Response('', { status: d });
    return Response.json(d);
  };
  return { fetchImpl, asked };
}

const MCP = 'https://mcp.example.com/mcp';
const PRM = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';
const AS = 'https://auth.example.com';
const ASM = 'https://auth.example.com/.well-known/oauth-authorization-server';
const good = { issuer: AS, authorization_endpoint: `${AS}/authorize`, code_challenge_methods_supported: ['S256'], client_id_metadata_document_supported: true, authorization_response_iss_parameter_supported: true };

test('discovery order follows the MCP spec: path-inserted, then root; OAuth then OIDC', () => {
  assert.deepEqual(resourceMetadataUrls(MCP), [PRM, 'https://mcp.example.com/.well-known/oauth-protected-resource']);
  assert.deepEqual(authServerMetadataUrls('https://auth.example.com/tenant1'), [
    'https://auth.example.com/.well-known/oauth-authorization-server/tenant1',
    'https://auth.example.com/.well-known/openid-configuration/tenant1',
    'https://auth.example.com/tenant1/.well-known/openid-configuration',
  ]);
});

test('a well-built sign-in produces no findings, and says what it supports', async () => {
  const { fetchImpl } = web({ [PRM]: { resource: MCP, authorization_servers: [AS] }, [ASM]: good });
  const r = await inspectAuth(MCP, { fetchImpl });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.auth.server, { issuer: AS, metadataUrl: ASM, pkceS256: true, clientIdMetadataDocuments: true, dynamicRegistration: false, issParameter: true });
});

test('the WWW-Authenticate pointer is used first when present', async () => {
  const custom = 'https://mcp.example.com/meta';
  const { fetchImpl, asked } = web({ [custom]: { resource: MCP, authorization_servers: [AS] }, [ASM]: good });
  await inspectAuth(MCP, { resourceMetadata: custom, fetchImpl });
  assert.equal(asked[0], custom);
});

test('OAuth challenge but no metadata: medium, because standard clients cannot sign in', async () => {
  const r = await inspectAuth(MCP, { bearer: true, fetchImpl: web({}).fetchImpl });
  assert.deepEqual(r.findings.map((f) => [f.check, f.severity]), [['oauth-metadata-missing', 'medium']]);
});

test('no OAuth challenge and no metadata is custom sign-in, allowed by the spec: info only', async () => {
  const r = await inspectAuth(MCP, { bearer: false, fetchImpl: web({}).fetchImpl });
  assert.deepEqual(r.findings.map((f) => [f.check, f.severity]), [['custom-auth', 'info']]);
});

test('issuer mismatch, missing PKCE and DCR-only are each reported', async () => {
  const { fetchImpl } = web({
    [PRM]: { resource: MCP, authorization_servers: [AS] },
    [ASM]: { issuer: 'https://attacker.example', authorization_endpoint: 'x', registration_endpoint: `${AS}/register`, code_challenge_methods_supported: ['plain'] },
  });
  const checks = (await inspectAuth(MCP, { fetchImpl })).findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ['oauth-dcr-only', 'oauth-issuer-mismatch', 'oauth-no-pkce']);
});

test('a resource naming another server is flagged; the server itself or its origin is not', async () => {
  const other = await inspectAuth(MCP, { fetchImpl: web({ [PRM]: { resource: 'https://other.example.com/mcp', authorization_servers: [AS] }, [ASM]: good }).fetchImpl });
  assert.ok(other.findings.some((f) => f.check === 'oauth-resource-mismatch'));
  for (const resource of [MCP, `${MCP}/`, 'https://mcp.example.com', 'https://MCP.example.com/mcp']) {
    const r = await inspectAuth(MCP, { fetchImpl: web({ [PRM]: { resource, authorization_servers: [AS] }, [ASM]: good }).fetchImpl });
    assert.ok(!r.findings.some((f) => f.check === 'oauth-resource-mismatch'), resource);
  }
});

test('tool annotations are summarised as declarations; read-only wins over destructive', () => {
  const s = annotationSummary([
    { name: 'a', annotations: { readOnlyHint: true } },
    { name: 'b', annotations: { destructiveHint: true } },
    { name: 'c', annotations: { readOnlyHint: true, destructiveHint: true } },
    { name: 'd' },
  ]);
  assert.deepEqual(s, { readOnly: 2, destructive: 1, openWorld: 0, unannotated: 1, destructiveNames: ['b'] });
});

test('metadata that cannot be read at all (a browser blocked by CORS) is unknown, never "missing"', async () => {
  const blocked = async () => { throw new TypeError('Failed to fetch'); };
  const r = await inspectAuth(MCP, { bearer: true, fetchImpl: blocked });
  assert.deepEqual(r.findings, []);
  assert.equal(r.auth.unreadable, true);
});

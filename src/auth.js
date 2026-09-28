/**
 * How a hosted MCP server that requires sign-in lets people sign in, read from public
 * metadata only: no credentials, no login. A fifth of registry endpoints answer 401 (30-
 * endpoint sample, 2026-09-28); "requires authentication" alone tells a user nothing about
 * whether that sign-in is built safely.
 *
 * Follows the discovery order in MCP 2026-07-28, basic/authorization/authorization-server-
 * discovery: the WWW-Authenticate resource_metadata URL, else the path-inserted then root
 * well-known URI (RFC 9728); then for the authorization server, RFC 8414 and OpenID
 * Connect discovery in the specified order. Web platform APIs only.
 */

const CAP = 256 * 1024;

async function getJson(url, fetchImpl, timeoutMs) {
  try {
    const res = await fetchImpl(url, { headers: { accept: 'application/json' }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return { status: res.status };
    const text = await res.text();
    if (text.length > CAP) return { status: res.status, error: 'too large' };
    return { status: res.status, json: JSON.parse(text) };
  } catch (err) {
    return { status: 0, error: err?.name === 'TimeoutError' ? 'timeout' : 'unreachable' };
  }
}

/** RFC 9728 well-known URIs for a resource: path-inserted first, then root. */
export function resourceMetadataUrls(mcpUrl) {
  const u = new URL(mcpUrl);
  const path = u.pathname.replace(/\/$/, '');
  const out = [];
  if (path && path !== '/') out.push(`${u.origin}/.well-known/oauth-protected-resource${path}`);
  out.push(`${u.origin}/.well-known/oauth-protected-resource`);
  return out;
}

/** RFC 8414 / OIDC discovery URLs for an issuer, in the order MCP requires. */
export function authServerMetadataUrls(issuer) {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/$/, '');
  if (path && path !== '/') {
    return [
      `${u.origin}/.well-known/oauth-authorization-server${path}`,
      `${u.origin}/.well-known/openid-configuration${path}`,
      `${u.origin}${path}/.well-known/openid-configuration`,
    ];
  }
  return [`${u.origin}/.well-known/oauth-authorization-server`, `${u.origin}/.well-known/openid-configuration`];
}

const norm = (s) => String(s ?? '').replace(/\/$/, '').toLowerCase();

/**
 * @returns {Promise<{auth: object, findings: object[]}>}
 */
export async function inspectAuth(mcpUrl, { resourceMetadata = null, bearer = true, fetchImpl = globalThis.fetch, timeoutMs = 8000 } = {}) {
  const host = new URL(mcpUrl).host;
  const findings = [];
  const auth = { required: true, resourceMetadataUrl: null, resource: null, authorizationServers: [], scopes: [], server: null };

  // 1. Protected resource metadata.
  let prm = null;
  let answered = false; // did anything reply at all? A browser blocked by CORS gets nothing
  for (const url of resourceMetadata ? [resourceMetadata] : resourceMetadataUrls(mcpUrl)) {
    const r = await getJson(url, fetchImpl, timeoutMs);
    if (r.status) answered = true;
    if (r.json?.authorization_servers || r.json?.resource) {
      prm = r.json;
      auth.resourceMetadataUrl = url;
      break;
    }
  }
  // Could not read anything (network or browser policy): unknown, never "missing".
  if (!prm && !answered) {
    auth.unreadable = true;
    return { auth, findings };
  }
  if (!prm && !bearer) {
    // No OAuth challenge and no metadata: the server uses its own scheme (an API key or
    // token configured by hand), which the specification allows. Not a violation.
    auth.custom = true;
    findings.push({
      check: 'custom-auth',
      severity: 'info',
      message: 'uses its own sign-in rather than MCP\'s OAuth flow: clients need a key or token configured by hand',
      evidence: [{ file: host, line: 0, text: 'HTTP 401 without a Bearer challenge or OAuth metadata' }],
    });
    return { auth, findings };
  }
  if (!prm) {
    findings.push({
      check: 'oauth-metadata-missing',
      severity: 'medium',
      message: 'requires sign-in but publishes no OAuth protected resource metadata (RFC 9728), which the MCP specification requires; standard clients cannot discover how to sign in',
      evidence: [{ file: host, line: 0, text: resourceMetadata ?? resourceMetadataUrls(mcpUrl).join(' , ') }],
    });
    return { auth, findings };
  }
  auth.resource = prm.resource ?? null;
  auth.authorizationServers = Array.isArray(prm.authorization_servers) ? prm.authorization_servers.slice(0, 5) : [];
  auth.scopes = Array.isArray(prm.scopes_supported) ? prm.scopes_supported.slice(0, 30) : [];

  // The token audience: a resource that names something else lets a token meant for one
  // server be accepted by another (RFC 8707 / 9728 audience binding).
  if (prm.resource && norm(prm.resource) !== norm(mcpUrl) && norm(prm.resource) !== norm(new URL(mcpUrl).origin)) {
    findings.push({
      check: 'oauth-resource-mismatch',
      severity: 'medium',
      message: `its resource metadata names ${prm.resource}, not this server (${mcpUrl}); tokens would be bound to a different audience`,
      evidence: [{ file: auth.resourceMetadataUrl, line: 0, text: `resource: ${prm.resource}` }],
    });
  }
  if (!auth.authorizationServers.length) {
    findings.push({
      check: 'oauth-metadata-missing',
      severity: 'medium',
      message: 'its resource metadata lists no authorization server, which the MCP specification requires',
      evidence: [{ file: auth.resourceMetadataUrl, line: 0, text: 'authorization_servers: absent' }],
    });
    return { auth, findings };
  }

  // 2. Authorization server metadata, validated as the spec requires (issuer must match).
  const issuer = auth.authorizationServers[0];
  let asm = null;
  let from = null;
  let asAnswered = false;
  for (const url of authServerMetadataUrls(issuer)) {
    const r = await getJson(url, fetchImpl, timeoutMs);
    if (r.status) asAnswered = true;
    if (r.json?.issuer || r.json?.authorization_endpoint) {
      asm = r.json;
      from = url;
      break;
    }
  }
  if (!asm && !asAnswered) {
    auth.unreadable = true;
    return { auth, findings };
  }
  if (!asm) {
    findings.push({
      check: 'oauth-metadata-missing',
      severity: 'medium',
      message: `its authorization server ${issuer} publishes no discoverable metadata (RFC 8414 or OpenID Connect discovery)`,
      evidence: [{ file: issuer, line: 0, text: authServerMetadataUrls(issuer).join(' , ') }],
    });
    return { auth, findings };
  }
  const pkce = Array.isArray(asm.code_challenge_methods_supported) ? asm.code_challenge_methods_supported : null;
  auth.server = {
    issuer: asm.issuer ?? null,
    metadataUrl: from,
    pkceS256: Boolean(pkce?.includes('S256')),
    clientIdMetadataDocuments: asm.client_id_metadata_document_supported === true,
    dynamicRegistration: Boolean(asm.registration_endpoint),
    issParameter: asm.authorization_response_iss_parameter_supported === true,
  };

  if (asm.issuer && asm.issuer !== issuer) {
    findings.push({
      check: 'oauth-issuer-mismatch',
      severity: 'medium',
      message: `authorization server metadata says issuer ${asm.issuer}, but it was discovered as ${issuer}; the MCP specification requires clients to reject it`,
      evidence: [{ file: from, line: 0, text: `issuer: ${asm.issuer}` }],
    });
  }
  if (!auth.server.pkceS256) {
    findings.push({
      check: 'oauth-no-pkce',
      severity: 'medium',
      message: `authorization server does not advertise PKCE with S256 (code_challenge_methods_supported: ${pkce ? pkce.join(', ') || 'empty' : 'absent'}); OAuth 2.1, which MCP authorization builds on, requires PKCE`,
      evidence: [{ file: from, line: 0, text: `code_challenge_methods_supported: ${pkce ? JSON.stringify(pkce) : 'absent'}` }],
    });
  }
  if (auth.server.dynamicRegistration && !auth.server.clientIdMetadataDocuments) {
    findings.push({
      check: 'oauth-dcr-only',
      severity: 'low',
      message: 'clients can register only through Dynamic Client Registration, deprecated in MCP 2026-07-28 in favour of Client ID Metadata Documents',
      evidence: [{ file: from, line: 0, text: 'registration_endpoint present; client_id_metadata_document_supported absent' }],
    });
  }
  return { auth, findings };
}

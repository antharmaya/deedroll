/**
 * The two sources of truth we diff against each other:
 *   1. the MCP registry entry — what the publisher DECLARED
 *   2. the npm tarball       — what the code ACTUALLY does
 */
import { createHash } from 'node:crypto';
import { readTarGz } from './tar.js';
import { readCached, writeCached } from './cache.js';
import { resolveVersion, provenanceHistory } from './model.js';
import { keepNpmFile, splitDocs } from './docs.js';

// Pure logic lives in model.js so the browser adapter can share it; re-exported here
// so existing imports keep working.
export { declaredEnvVars, npmIdentifiers, resolveVersion, provenanceHistory } from './model.js';

const REGISTRY = 'https://registry.modelcontextprotocol.io';
const NPM = 'https://registry.npmjs.org';


async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    const err = new Error(`${res.status} ${res.statusText} for ${url}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

/**
 * Look up a server in the official MCP registry by its registry name
 * (e.g. "io.github.owner/server"). Returns the latest version entry, or null.
 *
 * Uses the exact endpoint: measured ~0.9 s, against 3-14 s for the substring
 * `search` this used to go through. Falls back to search only if the exact endpoint
 * errors for a reason other than "not found".
 */
export async function fetchRegistryEntry(serverName) {
  const exact = `${REGISTRY}/v0.1/servers/${encodeURIComponent(serverName)}/versions/latest`;
  const res = await fetch(exact, { headers: { accept: 'application/json' } });
  if (res.status === 404) return null;
  if (res.ok) {
    const body = await res.json();
    return body?.server?.name === serverName ? body : null;
  }
  const url = `${REGISTRY}/v0/servers?search=${encodeURIComponent(serverName)}&limit=100`;
  const list = await getJson(url);
  const matches = (list.servers ?? []).filter((s) => s.server?.name === serverName);
  if (matches.length === 0) return null;
  const latest = matches.find((m) => m._meta?.['io.modelcontextprotocol.registry/official']?.isLatest);
  return latest ?? matches[matches.length - 1];
}

/**
 * Download an npm package and read it in memory. It is never extracted and no
 * lifecycle script runs — `npm install` would have run three of them by now. The
 * compressed tarball may be cached by content hash (see cache.js).
 *
 * @param {string} spec  a version, dist-tag or range (see resolveVersion)
 * @param {{maxUnpackedBytes?: number}} [opts]  skip, rather than download, anything larger
 */
export async function fetchNpmPackage(name, spec = 'latest', { maxUnpackedBytes = Infinity } = {}) {
  const packument = await getJson(`${NPM}/${encodeURIComponent(name).replace('%40', '@')}`);
  const { version: resolved, approximate } = resolveVersion(packument, spec);
  const manifest = packument.versions?.[resolved];
  if (!manifest) throw new Error(`version ${spec} not found for ${name}`);

  const unpackedSize = manifest.dist?.unpackedSize ?? null;
  if (unpackedSize && unpackedSize > maxUnpackedBytes) {
    return { name, version: resolved, manifest, skipped: 'too large', unpackedSize };
  }

  let tgz = readCached(manifest.dist.integrity);
  const fromCache = Boolean(tgz);
  if (!tgz) {
    const res = await fetch(manifest.dist.tarball);
    if (!res.ok) throw new Error(`tarball fetch failed: ${res.status}`);
    tgz = Buffer.from(await res.arrayBuffer());
    writeCached(manifest.dist.integrity, tgz);
  }

  const sha1 = createHash('sha1').update(tgz).digest('hex');
  const sha512 = createHash('sha512').update(tgz).digest('base64');
  const integrityOk = manifest.dist.integrity
    ? manifest.dist.integrity === `sha512-${sha512}`
    : manifest.dist.shasum === sha1;

  const { files, docs } = splitDocs(readTarGz(tgz, { keep: keepNpmFile }));

  return {
    name,
    version: resolved,
    approximate,
    manifest,
    files,
    docs,
    integrityOk,
    tarballBytes: tgz.length,
    fromCache,
    provenance: provenanceHistory(packument, resolved),
    unpackedSize,
    sha256: createHash('sha256').update(tgz).digest('hex'),
    publishedAt: packument.time?.[resolved] ?? null,
    maintainers: (packument.maintainers ?? []).map((m) => m.name ?? String(m)),
    versionCount: Object.keys(packument.versions ?? {}).length,
  };
}

/**
 * The two sources of truth we diff against each other:
 *   1. the MCP registry entry — what the publisher DECLARED
 *   2. the npm tarball       — what the code ACTUALLY does
 */
import { createHash } from 'node:crypto';
import { readTarGz } from './tar.js';

const REGISTRY = 'https://registry.modelcontextprotocol.io';
const NPM = 'https://registry.npmjs.org';

const SCANNABLE = /\.(m?js|cjs|ts|mts|cts|py|json)$/i;

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
 */
export async function fetchRegistryEntry(serverName) {
  const url = `${REGISTRY}/v0/servers?search=${encodeURIComponent(serverName)}&limit=100`;
  const body = await getJson(url);
  const matches = (body.servers ?? []).filter((s) => s.server?.name === serverName);
  if (matches.length === 0) return null;
  const latest = matches.find(
    (m) => m._meta?.['io.modelcontextprotocol.registry/official']?.isLatest
  );
  return latest ?? matches[matches.length - 1];
}

/** Every environment variable the registry entry declares, across all packages. */
export function declaredEnvVars(entry) {
  const declared = new Map(); // NAME -> { isSecret, isRequired }
  for (const pkg of entry?.server?.packages ?? []) {
    for (const ev of pkg.environmentVariables ?? []) {
      if (!ev?.name) continue;
      declared.set(ev.name, {
        isSecret: Boolean(ev.isSecret),
        isRequired: Boolean(ev.isRequired),
      });
    }
  }
  return declared;
}

/** npm packages named by the registry entry. */
export function npmIdentifiers(entry) {
  return (entry?.server?.packages ?? [])
    .filter((p) => (p.registryType ?? '').toLowerCase() === 'npm' && p.identifier)
    .map((p) => ({ identifier: p.identifier, version: p.version, fileSha256: p.fileSha256 }));
}

/**
 * Download an npm package and read it in memory. Nothing is written to disk and
 * no lifecycle script runs — `npm install` would have run three of them by now.
 */
export async function fetchNpmPackage(name, version = 'latest') {
  const packument = await getJson(`${NPM}/${encodeURIComponent(name).replace('%40', '@')}`);
  const resolved =
    version === 'latest' || !version
      ? packument['dist-tags']?.latest
      : packument['dist-tags']?.[version] ?? version;
  const manifest = packument.versions?.[resolved];
  if (!manifest) throw new Error(`version ${resolved} not found for ${name}`);

  const res = await fetch(manifest.dist.tarball);
  if (!res.ok) throw new Error(`tarball fetch failed: ${res.status}`);
  const tgz = Buffer.from(await res.arrayBuffer());

  const sha1 = createHash('sha1').update(tgz).digest('hex');
  const sha512 = createHash('sha512').update(tgz).digest('base64');
  const integrityOk = manifest.dist.integrity
    ? manifest.dist.integrity === `sha512-${sha512}`
    : manifest.dist.shasum === sha1;

  const files = readTarGz(tgz, { keep: (p) => SCANNABLE.test(p) || p === 'package.json' });

  return {
    name,
    version: resolved,
    manifest,
    files,
    integrityOk,
    sha256: createHash('sha256').update(tgz).digest('hex'),
    publishedAt: packument.time?.[resolved] ?? null,
    maintainers: (packument.maintainers ?? []).map((m) => m.name ?? String(m)),
    versionCount: Object.keys(packument.versions ?? {}).length,
  };
}

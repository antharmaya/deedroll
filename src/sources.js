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

/** [major, minor, patch, prerelease] or null. */
function parse(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(String(v));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3]), m[4] ?? null] : null;
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/**
 * Resolve an npm version spec against a packument, without a semver dependency.
 *
 * Covers what vendor packages actually use for their own dependencies: exact versions
 * (including pre-release pins), dist-tags ("latest"), ^ and ~ ranges, * and empty.
 * Anything else resolves to the latest tag and is reported as approximate rather
 * than silently treated as exact. Trade-off: a full semver library would be more
 * correct, and would be the first dependency of a security tool.
 *
 * @returns {{version: string|null, approximate: boolean}}
 */
export function resolveVersion(packument, spec) {
  const versions = Object.keys(packument.versions ?? {});
  const tags = packument['dist-tags'] ?? {};
  const s = String(spec ?? '').trim();

  if (!s || s === '*' || s === 'x') return { version: tags.latest ?? null, approximate: false };
  if (tags[s]) return { version: tags[s], approximate: false };
  if (packument.versions?.[s]) return { version: s, approximate: false };

  const range = /^([\^~])\s*(\d+\.\d+\.\d+)$/.exec(s);
  if (range) {
    const base = parse(range[2]);
    const ok = versions
      .map((v) => [v, parse(v)])
      .filter(([, p]) => p && !p[3] && cmp(p, base) >= 0)
      .filter(([, p]) => {
        if (range[1] === '~') return p[0] === base[0] && p[1] === base[1];
        if (base[0] > 0) return p[0] === base[0];
        if (base[1] > 0) return p[0] === 0 && p[1] === base[1];
        return p[0] === 0 && p[1] === 0 && p[2] === base[2];
      })
      .sort((a, b) => cmp(b[1], a[1]));
    if (ok.length) return { version: ok[0][0], approximate: false };
  }
  return { version: tags.latest ?? null, approximate: true };
}

/**
 * Download an npm package and read it in memory. Nothing is written to disk and
 * no lifecycle script runs — `npm install` would have run three of them by now.
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
    approximate,
    manifest,
    files,
    integrityOk,
    tarballBytes: tgz.length,
    unpackedSize,
    sha256: createHash('sha256').update(tgz).digest('hex'),
    publishedAt: packument.time?.[resolved] ?? null,
    maintainers: (packument.maintainers ?? []).map((m) => m.name ?? String(m)),
    versionCount: Object.keys(packument.versions ?? {}).length,
  };
}

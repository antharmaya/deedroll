/**
 * The browser adapter: the same checks as the CLI, on web platform primitives only —
 * fetch, DecompressionStream, crypto.subtle, TextDecoder. No Node imports, so it runs
 * in a browser tab (and in Node 22, which has all of these, which is how it is tested).
 *
 * Nothing is executed and nothing is extracted to disk: the tarball is unpacked into
 * memory. What leaves the tab: public package names and versions, sent to npm, the MCP
 * registry and OSV.dev. Emits real progress events; the UI animates those and never
 * fakes progress.
 */
import { runAllChecks, SEVERITY_ORDER } from './checks.js';
import { resolveVersion, provenanceHistory, declaredEnvVars, shipsPackage } from './model.js';
import { checkKnownVulnerabilities } from './osv.js';

const NPM = 'https://registry.npmjs.org';
const REGISTRY = 'https://registry.modelcontextprotocol.io';
const SCANNABLE = /\.(m?js|cjs|ts|mts|cts|py|json)$/i;
const MAX_FILE = 1024 * 1024;

/** Enough of Buffer's surface for the checks: they only ever call toString('utf8'). */
export class Bytes {
  constructor(u8) {
    this.u8 = u8;
    this.length = u8.length;
  }
  toString() {
    return new TextDecoder('utf-8').decode(this.u8);
  }
}

async function gunzip(u8) {
  const stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const ascii = (u8, from, len) => new TextDecoder('latin1').decode(u8.subarray(from, from + len)).replace(/\0.*$/s, '');

/** In-memory tar reader: same rules as src/tar.js, on Uint8Array. */
export function readTar(tar, keep = () => true) {
  const files = new Map();
  let offset = 0;
  let longName = null;
  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512);
    if (h.every((b) => b === 0)) break;
    const name = longName ?? ascii(h, 0, 100);
    const size = parseInt(ascii(h, 124, 12).trim() || '0', 8) || 0;
    const type = ascii(h, 156, 1) || '0';
    const prefix = ascii(h, 345, 155);
    longName = null;
    const start = offset + 512;
    const end = start + size;
    if (end > tar.length) break;
    if (type === 'L') longName = ascii(tar, start, size);
    else if (type === '0') {
      const rel = (prefix ? `${prefix}/${name}` : name).replace(/^package\//, '');
      if (size <= MAX_FILE && keep(rel)) files.set(rel, new Bytes(tar.slice(start, end)));
    }
    offset = start + Math.ceil(size / 512) * 512;
  }
  return files;
}

async function digest(alg, u8) {
  return new Uint8Array(await crypto.subtle.digest(alg, u8));
}
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
function base64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Download with real byte progress. */
async function download(url, onProgress, fetchImpl) {
  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`download failed (HTTP ${res.status})`);
  const total = Number(res.headers.get('content-length')) || null;
  if (!res.body?.getReader) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks = [];
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    got += value.length;
    onProgress({ stage: 'download', bytes: got, total });
  }
  const out = new Uint8Array(got);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

/**
 * npm answers a missing *scoped* package with a 404 that has no CORS header, so in a tab
 * it surfaces as a bare network error, indistinguishable from being offline. Unscoped
 * 404s do carry the header, so a request for a name nobody publishes tells the two apart:
 * if npm answers that, the network is fine and the scoped package isn't public.
 */
const PROBE = `${NPM}/mcpscan-reachability-probe-0`;
async function fetchPackument(name, fetchImpl) {
  const url = `${NPM}/${encodeURIComponent(name).replace('%40', '@')}`;
  try {
    return await fetchImpl(url);
  } catch (err) {
    if (!name.startsWith('@')) throw err;
    let reachable = false;
    try {
      await fetchImpl(PROBE);
      reachable = true;
    } catch {
      /* genuinely offline: report the original error */
    }
    if (!reachable) throw err;
    return { status: 404, ok: false };
  }
}

export async function fetchPackageInBrowser(name, spec = 'latest', { onProgress = () => {}, fetchImpl = globalThis.fetch } = {}) {
  onProgress({ stage: 'metadata', name });
  const res = await fetchPackument(name, fetchImpl);
  if (res.status === 404) throw Object.assign(new Error(`No public package called “${name}” on npm.`), { code: 'not-found' });
  if (!res.ok) throw new Error(`npm answered HTTP ${res.status}`);
  const packument = await res.json();
  const { version, approximate } = resolveVersion(packument, spec);
  const manifest = packument.versions?.[version];
  if (!manifest) throw Object.assign(new Error(`${name} has no version ${spec}.`), { code: 'not-found' });

  const tgz = await download(manifest.dist.tarball, onProgress, fetchImpl);
  const integrityOk = manifest.dist.integrity
    ? manifest.dist.integrity === `sha512-${base64(await digest('SHA-512', tgz))}`
    : manifest.dist.shasum === hex(await digest('SHA-1', tgz));

  onProgress({ stage: 'unpack' });
  const files = readTar(await gunzip(tgz), (p) => SCANNABLE.test(p) || p === 'package.json');

  return {
    name,
    version,
    approximate,
    manifest,
    files,
    integrityOk,
    tarballBytes: tgz.length,
    sha256: hex(await digest('SHA-256', tgz)),
    publishedAt: packument.time?.[version] ?? null,
    versionCount: Object.keys(packument.versions ?? {}).length,
    provenance: provenanceHistory(packument, version),
  };
}

/** Registry listing: bundled index first (fetched lazily), then the exact endpoint. */
export async function findListingInBrowser(npmName, { indexUrl, fetchImpl = globalThis.fetch } = {}) {
  let index = null;
  try {
    const r = await fetchImpl(indexUrl);
    if (r.ok) index = await r.json();
  } catch {
    /* no index: say so below */
  }
  for (const listing of index?.index?.[npmName] ?? []) {
    const r = await fetchImpl(`${REGISTRY}/v0.1/servers/${encodeURIComponent(listing)}/versions/latest`);
    if (!r.ok) continue;
    const entry = await r.json();
    if (shipsPackage(entry.server, npmName)) return { entry, found: true, listings: index.index[npmName], indexBuiltAt: index.builtAt };
  }
  return { entry: null, found: false, listings: [], indexBuiltAt: index?.builtAt ?? null };
}

/**
 * The whole scan, in a tab. Same result shape as the CLI's scan().
 */
export async function scanInBrowser(npmName, { spec = 'latest', indexUrl, osv = true, onProgress = () => {}, fetchImpl = globalThis.fetch } = {}) {
  const pkg = await fetchPackageInBrowser(npmName, spec, { onProgress, fetchImpl });
  onProgress({ stage: 'registry' });
  const listing = await findListingInBrowser(npmName, { indexUrl, fetchImpl });
  const entry = listing.entry;
  const declared = declaredEnvVars(entry);

  onProgress({ stage: 'checks', files: pkg.files.size });
  const findings = runAllChecks({ pkg, entry, declared, officialNames: [] });

  let vulns = null;
  if (osv) {
    onProgress({ stage: 'vulnerabilities' });
    const r = await checkKnownVulnerabilities([{ name: pkg.name, version: pkg.version }], { fetchImpl });
    findings.push(...r.findings);
    vulns = { checked: r.checked, error: r.error ?? null };
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  onProgress({ stage: 'done' });
  return { target: `npm:${npmName}`, pkg, entry, declared, listing, findings, vulns };
}

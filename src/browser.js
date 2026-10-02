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
import { resolveVersion, provenanceHistory, declaredEnvVars, shipsPackage, normalizePypiName, listingStatus } from './model.js';
import { fetchPypiPackage } from './pypi.js';
import { checkKnownVulnerabilities } from './osv.js';
import { Bytes, readTar, gunzip, digest, hex, base64, download } from './archive.js';
import { keepNpmFile, splitDocs } from './docs.js';

export { Bytes, readTar } from './archive.js';

const NPM = 'https://registry.npmjs.org';
const REGISTRY = 'https://registry.modelcontextprotocol.io';

/**
 * npm answers a missing *scoped* package with a 404 that has no CORS header, so in a tab
 * it surfaces as a bare network error, indistinguishable from being offline. Unscoped
 * 404s do carry the header, so a request for a name nobody publishes tells the two apart:
 * if npm answers that, the network is fine and the scoped package isn't public.
 */
const PROBE = `${NPM}/deedroll-reachability-probe-0`;
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
  const { files, docs } = splitDocs(readTar(await gunzip(tgz), keepNpmFile));

  return {
    name,
    version,
    approximate,
    manifest,
    files,
    docs,
    integrityOk,
    tarballBytes: tgz.length,
    sha256: hex(await digest('SHA-256', tgz)),
    publishedAt: packument.time?.[version] ?? null,
    versionCount: Object.keys(packument.versions ?? {}).length,
    provenance: provenanceHistory(packument, version),
  };
}

/** Registry listing: bundled index first (fetched lazily), then the exact endpoint. */
export async function findListingInBrowser(npmName, { indexUrl, ecosystem = 'npm', fetchImpl = globalThis.fetch } = {}) {
  let index = null;
  try {
    const r = await fetchImpl(indexUrl);
    if (r.ok) index = await r.json();
  } catch {
    /* no index: say so below */
  }
  const names = (ecosystem === 'pypi' ? index?.pypi?.[normalizePypiName(npmName)] : index?.index?.[npmName]) ?? [];
  for (const listing of names) {
    const r = await fetchImpl(`${REGISTRY}/v0.1/servers/${encodeURIComponent(listing)}/versions/latest`);
    if (!r.ok) continue;
    const entry = await r.json();
    if (shipsPackage(entry.server, npmName, ecosystem)) return { entry, found: true, listings: names, indexBuiltAt: index.builtAt };
  }
  return { entry: null, found: false, listings: [], indexBuiltAt: index?.builtAt ?? null };
}

/**
 * The whole scan, in a tab. Same result shape as the CLI's scan(). `name` may carry an
 * ecosystem prefix: "pypi:mcp-server-fetch"; bare names and "npm:" are npm.
 */
export async function scanInBrowser(target, { spec = 'latest', indexUrl, osv = true, onProgress = () => {}, fetchImpl = globalThis.fetch } = {}) {
  const ecosystem = /^pypi:/i.test(target) ? 'pypi' : 'npm';
  const npmName = target.replace(/^(npm|pypi):/i, '');
  const pkg = ecosystem === 'pypi'
    ? await fetchPypiPackage(npmName, spec, { onProgress, fetchImpl })
    : await fetchPackageInBrowser(npmName, spec, { onProgress, fetchImpl });
  onProgress({ stage: 'registry' });
  const listing = await findListingInBrowser(npmName, { indexUrl, ecosystem, fetchImpl });
  const entry = listing.entry;
  const declared = declaredEnvVars(entry);

  onProgress({ stage: 'checks', files: pkg.files.size });
  const findings = [...listingStatus(entry), ...runAllChecks({ pkg, entry, declared, officialNames: [] })];

  let vulns = null;
  if (osv) {
    onProgress({ stage: 'vulnerabilities' });
    const r = await checkKnownVulnerabilities([{ name: pkg.name, version: pkg.version, ecosystem }], { fetchImpl });
    findings.push(...r.findings);
    vulns = { checked: r.checked, error: r.error ?? null };
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  onProgress({ stage: 'done' });
  return { target: `${ecosystem}:${npmName}`, pkg, entry, declared, listing, findings, vulns };
}

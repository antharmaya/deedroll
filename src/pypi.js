/**
 * PyPI source adapter. Produces the same `pkg` shape the checks read for npm, with
 * `ecosystem: 'pypi'`, so every check that reads code runs unchanged; the few that read
 * package metadata branch on the ecosystem.
 *
 * Web platform APIs only, so this one file serves the CLI (Node 22) and the browser page:
 * every PyPI endpoint it uses sends CORS headers (checked 2026-09-28).
 *
 * What leaves the machine: the project name and version, sent to pypi.org and
 * files.pythonhosted.org. Nothing is installed: the archive is read in memory.
 */
import { readZip, stripTopDirectory } from './zip.js';
import { Bytes, readTar, gunzip, digest, hex, download } from './archive.js';
import { pickPypiFile, pypiSourceUrl, repoSlug } from './model.js';
import { DOC_FILE, splitDocs } from './docs.js';

const PYPI = 'https://pypi.org';
const SCANNABLE = /\.(py|pyi|json|toml|cfg|m?js|cjs|ts)$/i;
const MAX_ARCHIVE = 50 * 1024 * 1024;

export class PypiNotFound extends Error {
  code = 'not-found';
}

async function getJson(url, fetchImpl) {
  const res = await fetchImpl(url);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`PyPI answered HTTP ${res.status} for ${url}`);
  return res.json();
}

/**
 * PEP 740 provenance for one file: who built it, from which repository and workflow.
 * Only 200 means present and only 404 means absent; anything else is unknown, because
 * PyPI's integrity API answers some files with a lasting 503 (seen 2026-09-28 on
 * mcp-server-fetch's sdist) and "unknown" must never be reported as "absent".
 */
export async function pypiProvenance(project, version, filename, fetchImpl = globalThis.fetch) {
  const url = `${PYPI}/integrity/${encodeURIComponent(project)}/${encodeURIComponent(version)}/${encodeURIComponent(filename)}/provenance`;
  try {
    let res = await fetchImpl(url, { headers: { accept: 'application/vnd.pypi.integrity.v1+json' } });
    // Intermittent 503s are normal here (measured 2026-09-28): one retry recovers most.
    if (res.status >= 500) {
      await new Promise((r) => setTimeout(r, 400));
      res = await fetchImpl(url, { headers: { accept: 'application/vnd.pypi.integrity.v1+json' } });
    }
    if (res.status === 404) return { state: 'absent' };
    if (!res.ok) return { state: 'unknown', status: res.status, publisher: null };
    const body = await res.json();
    const pub = body.attestation_bundles?.[0]?.publisher ?? {};
    return { state: 'present', publisher: { kind: pub.kind ?? null, repository: pub.repository ?? null, workflow: pub.workflow ?? null } };
  } catch {
    return { state: 'unknown' };
  }
}

/** Releases that have at least one file, oldest first (PyPI orders keys as strings). */
function releaseOrder(releases) {
  return Object.entries(releases ?? {})
    .filter(([, files]) => files.length)
    .map(([v, files]) => ({ v, at: Math.min(...files.map((f) => Date.parse(f.upload_time_iso_8601 ?? f.upload_time))) }))
    .sort((a, b) => a.at - b.at)
    .map((r) => r.v);
}

/**
 * Which files of which releases carry a PEP 740 attestation, from the Simple API.
 * `state` is 'unknown' only when the Simple API itself did not answer.
 */
export async function provenanceHistoryPypi(project, releases, version, filename, fetchImpl = globalThis.fetch) {
  let files;
  try {
    const res = await fetchImpl(`${PYPI}/simple/${encodeURIComponent(project)}/`, { headers: { accept: 'application/vnd.pypi.simple.v1+json' } });
    if (!res.ok) throw new Error(String(res.status));
    files = (await res.json()).files ?? [];
  } catch {
    return { state: 'unknown', current: false, earlierWithProvenance: 0, lastWithProvenance: null };
  }
  const attested = new Set(files.filter((f) => f.provenance).map((f) => f.filename));
  const current = attested.has(filename);
  const order = releaseOrder(releases);
  const earlier = order.slice(0, Math.max(0, order.indexOf(version))).filter((v) => (releases[v] ?? []).some((f) => attested.has(f.filename)));
  return { state: current ? 'present' : 'absent', current, earlierWithProvenance: earlier.length, lastWithProvenance: earlier.at(-1) ?? null };
}

export async function fetchPypiPackage(name, spec = 'latest', { fetchImpl = globalThis.fetch, onProgress = () => {} } = {}) {
  onProgress({ stage: 'metadata', name });
  const project = await getJson(`${PYPI}/pypi/${encodeURIComponent(name)}/json`, fetchImpl);
  if (!project) throw new PypiNotFound(`No public package called “${name}” on PyPI.`);
  const version = spec === 'latest' || !spec ? project.info.version : spec;
  const files = project.releases?.[version];
  if (!files?.length) throw new PypiNotFound(`${name} has no release ${version} on PyPI.`);
  // Per-version metadata (yanked, project URLs at that release) lives on the version URL.
  const info = version === project.info.version ? project.info : ((await getJson(`${PYPI}/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`, fetchImpl))?.info ?? project.info);

  const pick = pickPypiFile(files);
  if (!pick) throw new Error(`${name} ${version} has neither a wheel nor an sdist to read`);
  if (pick.file.size > MAX_ARCHIVE) return { ecosystem: 'pypi', name: info.name, version, skipped: 'too large', unpackedSize: pick.file.size };

  const archive = await download(pick.file.url, onProgress, fetchImpl);
  const sha256 = hex(await digest('SHA-256', archive));
  onProgress({ stage: 'unpack' });
  // METADATA and PKG-INFO embed the README: documentation, not code. They are read into
  // `docs`, never `files` (their links read as network egress otherwise; found on mcp-server-fetch).
  const keep = (p) => SCANNABLE.test(p) || /(^|\/)(setup\.py|pyproject\.toml)$/.test(p) || DOC_FILE.test(p);

  let raw;
  if (/\.(whl|zip)$/i.test(pick.file.filename)) {
    raw = (await readZip(archive, { keep })).files;
    if (pick.kind === 'sdist') raw = stripTopDirectory(raw);
  } else if (/\.tar\.gz$/i.test(pick.file.filename)) {
    raw = stripTopDirectory(readTar(await gunzip(archive), keep));
  } else {
    throw new Error(`cannot read ${pick.file.filename}`);
  }
  const { files: filesMap, docs } = splitDocs(new Map([...raw].map(([k, v]) => [k, v instanceof Bytes ? v : new Bytes(v)])));

  // Presence and history come from the Simple API (PEP 691 JSON), which lists every file
  // with a provenance URL or null: one request, served from the index, reliable. The
  // integrity endpoint is only asked for the publisher of this file, best effort: it
  // answered persistent 503s for files that do have provenance (talamus 1.1.3).
  const history = await provenanceHistoryPypi(info.name, project.releases, version, pick.file.filename, fetchImpl);
  const current = history.current ? await pypiProvenance(info.name, version, pick.file.filename, fetchImpl) : null;

  const repository = pypiSourceUrl(info);
  return {
    ecosystem: 'pypi',
    name: info.name,
    version,
    approximate: false,
    manifest: {
      name: info.name,
      version,
      repository: repository ?? undefined,
      scripts: {},
      deprecated: info.yanked ? info.yanked_reason || 'yanked' : undefined,
      requiresDist: info.requires_dist ?? [],
    },
    artifact: { filename: pick.file.filename, kind: pick.kind, buildsFromSource: pick.buildsFromSource },
    files: filesMap,
    docs,
    integrityOk: pick.file.digests?.sha256 ? pick.file.digests.sha256 === sha256 : null,
    tarballBytes: archive.length,
    sha256,
    publishedAt: pick.file.upload_time_iso_8601 ?? null,
    versionCount: releaseOrder(project.releases).length,
    provenance: {
      current: history.current,
      state: history.state,
      publisher: current?.publisher ?? null,
      sourceSlug: repoSlug(repository),
      earlierWithProvenance: history.earlierWithProvenance,
      lastWithProvenance: history.lastWithProvenance,
    },
  };
}

/**
 * Pure logic shared by the Node and browser adapters: no I/O, no platform imports.
 * Moved out of sources.js and lookup.js on 2026-09-28 so the scanner can run in a
 * browser without a second copy of any rule.
 */

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
 * Was this version published with npm provenance (a Sigstore attestation that it was
 * built by CI from a named repo), and were earlier ones? A package that used to carry
 * provenance and suddenly does not is a known sign of a publish from a stolen token.
 */
export function provenanceHistory(packument, version) {
  const has = (v) => Boolean(packument.versions?.[v]?.dist?.attestations);
  const t = packument.time ?? {};
  const cutoff = Date.parse(t[version] ?? '') || Infinity;
  const earlier = Object.keys(packument.versions ?? {}).filter((v) => v !== version && (Date.parse(t[v] ?? '') || 0) < cutoff);
  const withProv = earlier.filter(has).sort((a, b) => Date.parse(t[b] ?? 0) - Date.parse(t[a] ?? 0));
  return { current: has(version), earlierWithProvenance: withProv.length, lastWithProvenance: withProv[0] ?? null };
}

/** Words worth searching for: "@acme/weather-mcp-server" -> ["weather", "acme"]. */
export function searchTerms(npmName) {
  const scope = /^@([^/]+)\//.exec(npmName)?.[1];
  const bare = npmName.replace(/^@[^/]+\//, '');
  const core = bare
    .replace(/(^|[-_])(mcp|server|model-context-protocol)(?=$|[-_])/gi, '$1')
    .replace(/[-_]+/g, '-')
    .replace(/^-|-$/g, '');
  return [...new Set([core, scope].filter((t) => t && t.length >= 3))].slice(0, 2);
}

/** PEP 503: PyPI names compare case-insensitively with runs of -_. folded to one dash. */
export const normalizePypiName = (name) => String(name).toLowerCase().replace(/[-_.]+/g, '-');

export const shipsPackage = (server, name, ecosystem = 'npm') =>
  (server?.packages ?? []).some((p) => {
    const type = (p.registryType ?? '').toLowerCase();
    if (type !== ecosystem || !p.identifier) return false;
    return ecosystem === 'pypi' ? normalizePypiName(p.identifier) === normalizePypiName(name) : p.identifier === name;
  });

/** Packages of one ecosystem named by the registry entry. */
export function packageIdentifiers(entry, ecosystem) {
  return (entry?.server?.packages ?? [])
    .filter((p) => (p.registryType ?? '').toLowerCase() === ecosystem && p.identifier)
    .map((p) => ({ identifier: p.identifier, version: p.version, fileSha256: p.fileSha256 }));
}


/* ---------- PyPI ---------- */

/**
 * Which file of a release to read. A wheel is what `pip install` and `uvx` pick when one
 * fits, and installing a wheel runs no code; a pure-Python wheel (`none-any`) fits every
 * machine, so it is the most honest stand-in for "what you get". With no wheel at all,
 * pip builds the sdist, and building runs the package's own setup code on your machine.
 */
export function pickPypiFile(files) {
  const usable = files ?? [];
  const wheels = usable.filter((f) => f.packagetype === 'bdist_wheel');
  const pure = wheels.find((f) => /-none-any\.whl$/.test(f.filename));
  if (pure) return { file: pure, kind: 'wheel', buildsFromSource: false };
  if (wheels.length) return { file: wheels[0], kind: 'wheel', buildsFromSource: false };
  const sdist = usable.find((f) => f.packagetype === 'sdist');
  return sdist ? { file: sdist, kind: 'sdist', buildsFromSource: true } : null;
}

/** "owner/repo" from a GitHub or GitLab URL, lowercased; null otherwise. */
export function repoSlug(url) {
  const m = /^(?:git\+)?(?:https?|git|ssh):\/\/(?:[^@/]+@)?(github\.com|gitlab\.com)[/:]([^/\s]+)\/([^/\s#?]+)/i.exec(String(url ?? '').trim());
  return m ? `${m[2]}/${m[3].replace(/\.git$/, '')}`.toLowerCase() : null;
}

/** The source repository a PyPI project points at, from its project URLs. */
export function pypiSourceUrl(info) {
  const urls = Object.entries(info?.project_urls ?? {});
  const named = urls.find(([k]) => /^(source|source code|repository|code|github|homepage|home)$/i.test(k.trim()));
  const any = urls.find(([, v]) => repoSlug(v));
  return (named && repoSlug(named[1]) ? named[1] : any?.[1]) ?? (repoSlug(info?.home_page) ? info.home_page : null);
}

/**
 * The registry's own verdict on a listing. `deleted` is what maintainers set for spam,
 * malware or impersonation under the moderation policy; `deprecated` is the publisher
 * withdrawing it. Read from the official `_meta`, which every entry fetch already has.
 */
export function listingStatus(entry) {
  const official = entry?._meta?.['io.modelcontextprotocol.registry/official'];
  const status = official?.status;
  if (!status || status === 'active') return [];
  return [
    {
      check: 'listing-status',
      subject: status,
      severity: status === 'deleted' ? 'high' : 'medium',
      message: status === 'deleted'
        ? `the MCP registry has removed this listing (status deleted${official.statusChangedAt ? ` on ${official.statusChangedAt.slice(0, 10)}` : ''}), which its moderation policy uses for spam, malware and impersonation`
        : `the registry listing is marked ${status}${official.statusChangedAt ? ` since ${official.statusChangedAt.slice(0, 10)}` : ''}`,
      evidence: [{ file: 'registry', line: 0, text: `${entry.server.name}: status ${status}` }],
    },
  ];
}

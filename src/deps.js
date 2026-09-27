/**
 * Follow a thin wrapper into the packages where its tools actually live.
 *
 * Measured on the vendor benchmark: @playwright/mcp is five files; its tools are in
 * `playwright-core`. mongodb-mcp-server's are in fourteen @mongodb-js/mcp-* packages.
 * Scanning only the top-level tarball reports those servers as having no tools.
 *
 * Bounded on purpose — one level deep, vendor-affine dependencies only, a count cap
 * and a size cap — because every step outward costs a download and adds noise, and an
 * unbounded walk ends up scanning half of npm.
 */
import { fetchNpmPackage } from './sources.js';

/** Protocol plumbing, not a vendor's tools: scanning it would surface SDK examples as phantom tools. */
const NEVER_FOLLOW = /^@modelcontextprotocol\//;

/** The vendor's own name: the scope ("@paypal/mcp" -> paypal), else the first word ("mongodb-mcp-server" -> mongodb). */
export function vendorToken(rootName) {
  const scoped = /^@([^/]+)\//.exec(rootName);
  const token = scoped ? scoped[1] : rootName.split(/[-_.]/)[0];
  return token.toLowerCase();
}

/**
 * Which dependencies to follow: same scope, the vendor's name, or "mcp" in the name.
 * @returns {{follow: Array<{name, spec}>, capped: number}}
 */
export function selectDependencies(manifest, rootName, { max = 16 } = {}) {
  const token = vendorToken(rootName);
  const scope = /^(@[^/]+)\//.exec(rootName)?.[1] ?? null;
  const picked = [];
  for (const [name, spec] of Object.entries(manifest?.dependencies ?? {})) {
    if (NEVER_FOLLOW.test(name)) continue;
    const lower = name.toLowerCase();
    const affine =
      (scope && name.startsWith(`${scope}/`)) ||
      (token.length >= 3 && lower.includes(token)) ||
      /(^|[/@_-])mcp([_-]|$)/.test(lower);
    if (affine) picked.push({ name, spec });
  }
  return { follow: picked.slice(0, max), capped: Math.max(0, picked.length - max) };
}

async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    })
  );
  return out;
}

/**
 * Download the selected dependencies (in memory, never executed).
 * @returns {Promise<{deps: object[], skipped: Array<{name, spec, reason}>, capped: number}>}
 */
export async function expandDependencies(pkg, { max = 16, maxUnpackedBytes = 25 * 1024 * 1024, concurrency = 4 } = {}) {
  const { follow, capped } = selectDependencies(pkg.manifest, pkg.name, { max });
  const deps = [];
  const skipped = [];
  await pool(follow, concurrency, async ({ name, spec }) => {
    try {
      const d = await fetchNpmPackage(name, spec, { maxUnpackedBytes });
      if (d.skipped) skipped.push({ name, spec, reason: `${d.skipped} (${Math.round(d.unpackedSize / 1048576)} MB unpacked)` });
      else deps.push(d);
    } catch (err) {
      skipped.push({ name, spec, reason: err.message.slice(0, 120) });
    }
  });
  deps.sort((a, b) => a.name.localeCompare(b.name));
  return { deps, skipped, capped };
}

/**
 * One virtual package: the root's files plus each dependency's under
 * node_modules/<name>/, the path a user would open after a real install. Every check
 * then runs unchanged — they never cared where a file came from.
 */
export function mergeDependencies(pkg, deps) {
  const files = new Map(pkg.files);
  for (const d of deps) {
    for (const [path, buf] of d.files) files.set(`node_modules/${d.name}/${path}`, buf);
  }
  return {
    ...pkg,
    files,
    dependencies: deps.map((d) => ({
      name: d.name,
      version: d.version,
      approximate: d.approximate,
      manifest: d.manifest,
      tarballBytes: d.tarballBytes,
      fromCache: d.fromCache,
      files: d.files.size,
    })),
  };
}

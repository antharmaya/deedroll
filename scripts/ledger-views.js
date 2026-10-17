/**
 * Views of the ledger that the nightly build publishes beside it. Pure functions over ledger
 * records, so a test can hold them to their counting rules without a real archive.
 *
 *   registryIndexOf  the package -> listing index the page's lookup uses (src/data/ shape)
 *   censusOf         the registry-wide credential figure shown on the page
 */
import { normalizePypiName } from '../src/model.js';

/** Package types deedroll reads today. Listings that ship only other types are counted apart. */
export const READABLE = ['npm', 'pypi'];

/**
 * The lookup index (package name -> registry listing names) from the listings present in the
 * registry on the ledger's last day. Same shape as scripts/build-index.js writes, so
 * src/lookup.js and src/browser.js read either.
 */
export function registryIndexOf(records, { builtAt, snapshot }) {
  const index = {};
  const pypi = {};
  let listings = 0;
  const live = [...records].filter((r) => !r.gone).sort((a, b) => a.name.localeCompare(b.name));
  for (const rec of live) {
    listings++;
    for (const p of rec.latest.packages ?? []) {
      if (!p.id) continue;
      const map = p.type === 'npm' ? index : p.type === 'pypi' ? pypi : null;
      if (!map) continue;
      const key = p.type === 'pypi' ? normalizePypiName(p.id) : p.id;
      (map[key] ??= []).includes(rec.name) || map[key].push(rec.name);
    }
  }
  // A snapshot is a complete walk of the registry (snapshot.js writes nothing on a partial one).
  return { builtAt, snapshot, source: 'ledger', complete: true, listings, index, pypi };
}

/**
 * The census. Counting rule, applied to every listing present in the registry on `date`:
 *   packaged     names at least one npm or PyPI package
 *   otherOnly    names packages, but only types deedroll cannot read yet (OCI, MCPB, NuGet, Cargo)
 *   scanned      packaged, with a successful scan recorded for at least one of those packages
 *   failed       packaged, every recorded scan failed (missing    = the package or version
 *                the listing names does not exist on npm or PyPI)
 *   notScanned   packaged, no scan recorded yet
 *   undeclared   scanned, and some package's code reads a credential-like name (outside a
 *                string) that this listing does not declare and the package's README/docs
 *                never mention
 *   readmeOnly   scanned, not undeclared, and some such read is explained only in the README
 * Percentages are of `scanned`. Each server counts once, whatever number of packages it ships.
 */
export function censusOf(records, date) {
  const c = { date, listings: 0, packaged: 0, otherOnly: 0, scanned: 0, failed: 0, missing: 0, notScanned: 0, undeclared: 0, readmeOnly: 0 };
  for (const rec of records) {
    if (rec.gone) continue;
    c.listings++;
    const pkgs = rec.latest.packages ?? [];
    const readable = pkgs.filter((p) => READABLE.includes(p.type));
    if (!readable.length) {
      if (pkgs.length) c.otherOnly++;
      continue;
    }
    c.packaged++;
    const sigs = readable.map((p) => rec.signals?.[`${p.type}:${p.id}`]).filter(Boolean);
    const ok = sigs.filter((s) => !s.error);
    if (!sigs.length) {
      c.notScanned++;
      continue;
    }
    if (!ok.length) {
      c.failed++;
      if (sigs.some((s) => s.missing)) c.missing++;
      continue;
    }
    c.scanned++;
    if (ok.some((s) => s.undeclared?.length)) c.undeclared++;
    else if (ok.some((s) => s.readmeOnly?.length)) c.readmeOnly++;
  }
  return c;
}

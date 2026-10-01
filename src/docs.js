/**
 * A package's own documentation, kept apart from its code.
 *
 * Read for one purpose: to see what the package already explains about itself, so a finding
 * never calls something undeclared that its README spells out (found live 2026-09-29: a
 * "hardcoded fallback key" was a documented public free-tier key). It lives in its own map,
 * never in `files`, because every code check scans `files`: a README's links would read as
 * network egress, and its `process.env.X` examples as credential reads.
 */
export const DOC_FILE = /^(?:[^/]+\/)?(?:readme(?:\.(?:md|markdown|rst|txt))?|metadata|pkg-info)$/i;

/** Split what a reader kept into code (`files`) and documentation (`docs`). */
export function splitDocs(entries) {
  const files = new Map();
  const docs = new Map();
  for (const [path, buf] of entries) (DOC_FILE.test(path) ? docs : files).set(path, buf);
  return { files, docs };
}

/** What the npm readers (Node and browser) keep from a tarball: code, the manifest, and docs. */
const NPM_CODE = /\.(m?js|cjs|ts|mts|cts|py|json)$/i;
export const keepNpmFile = (path) => NPM_CODE.test(path) || path === 'package.json' || DOC_FILE.test(path);

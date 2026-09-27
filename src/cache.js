/**
 * Content-addressed tarball cache.
 *
 * Keyed by npm's own integrity hash (sha512), and re-verified on every read: a file
 * that no longer matches its key is deleted and re-downloaded, so a corrupted or
 * tampered cache can never feed a scan. Only the COMPRESSED tarball is stored — never
 * extracted, never executed. Package metadata is never cached: deprecations and
 * dist-tags change, a published version's bytes do not.
 *
 * Disabled with --no-cache or MCPSCAN_NO_CACHE=1.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export function cacheDir() {
  const base = process.env.XDG_CACHE_HOME || join(homedir(), '.cache');
  return join(base, 'mcpscan', 'tarballs');
}

const disabled = () => process.env.MCPSCAN_NO_CACHE === '1';

/** "sha512-<base64>" -> a filename-safe key; null for anything that is not sha512. */
function keyFor(integrity) {
  const m = /^sha512-([A-Za-z0-9+/=]+)$/.exec(integrity ?? '');
  return m ? Buffer.from(m[1], 'base64').toString('hex') : null;
}

const matches = (bytes, integrity) => `sha512-${createHash('sha512').update(bytes).digest('base64')}` === integrity;

export function readCached(integrity, dir = cacheDir()) {
  if (disabled()) return null;
  const key = keyFor(integrity);
  if (!key) return null;
  const file = join(dir, `${key}.tgz`);
  if (!existsSync(file)) return null;
  const bytes = readFileSync(file);
  if (!matches(bytes, integrity)) {
    rmSync(file, { force: true }); // corrupted or tampered: never trust it
    return null;
  }
  return bytes;
}

export function writeCached(integrity, bytes, dir = cacheDir()) {
  if (disabled()) return;
  const key = keyFor(integrity);
  if (!key || !matches(bytes, integrity)) return; // only ever cache verified bytes
  try {
    mkdirSync(dir, { recursive: true });
    const tmp = join(dir, `${key}.${process.pid}.tmp`);
    writeFileSync(tmp, bytes);
    renameSync(tmp, join(dir, `${key}.tgz`)); // atomic: a crash never leaves a half file under the key
  } catch {
    // a read-only home or full disk must not break a scan
  }
}

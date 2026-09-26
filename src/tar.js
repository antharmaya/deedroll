/**
 * Minimal in-memory tar reader for npm tarballs.
 *
 * The whole point: we never extract an untrusted archive to disk and we never run it.
 * Path traversal, symlink attacks and install scripts all need a filesystem write to
 * matter. We read bytes in memory, so none of them apply.
 */
import { gunzipSync } from 'node:zlib';

const BLOCK = 512;

/** Octal header field -> number. Trailing NUL/space padding is normal. */
function octal(buf, offset, length) {
  const raw = buf.toString('ascii', offset, offset + length).replace(/\0.*$/, '').trim();
  if (raw === '') return 0;
  const n = parseInt(raw, 8);
  return Number.isNaN(n) ? 0 : n;
}

function str(buf, offset, length) {
  return buf.toString('utf8', offset, offset + length).replace(/\0.*$/, '');
}

/**
 * @param {Buffer} tgz gzipped tarball
 * @param {{maxFileBytes?: number, keep?: (path: string) => boolean}} [opts]
 * @returns {Map<string, Buffer>} path (with the leading "package/" stripped) -> contents
 */
export function readTarGz(tgz, opts = {}) {
  const maxFileBytes = opts.maxFileBytes ?? 1024 * 1024;
  const keep = opts.keep ?? (() => true);
  const tar = gunzipSync(tgz);
  const files = new Map();

  let offset = 0;
  let longName = null;

  while (offset + BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK);
    if (header.every((b) => b === 0)) break; // end-of-archive

    const name = longName ?? str(header, 0, 100);
    const size = octal(header, 124, 12);
    const type = str(header, 156, 1) || '0';
    const prefix = str(header, 345, 155);
    longName = null;

    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) break; // truncated archive; stop rather than throw

    if (type === 'L') {
      // GNU long filename: the next header's name lives in this entry's body.
      longName = tar.toString('utf8', dataStart, dataEnd).replace(/\0.*$/, '');
    } else if (type === '0' || type === '') {
      const full = prefix ? `${prefix}/${name}` : name;
      // npm tarballs root everything at "package/"
      const rel = full.replace(/^package\//, '');
      if (size <= maxFileBytes && keep(rel)) {
        files.set(rel, tar.subarray(dataStart, dataEnd));
      }
    }
    // Every other type (dirs, symlinks, pax headers) is skipped on purpose.

    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;
  }

  return files;
}

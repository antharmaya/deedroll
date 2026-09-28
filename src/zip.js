/**
 * In-memory zip reader for Python wheels, zip sdists and .mcpb bundles.
 *
 * Web primitives only (DecompressionStream, DataView), so the Node and browser adapters
 * share it; it returns raw bytes and each adapter wraps them (Buffer in Node, Bytes in a
 * tab). Like the tar reader, nothing is extracted to disk and nothing is run, so path
 * traversal and symlink entries have nothing to act on.
 *
 * Hostile archives: the central directory's sizes are the author's claim, so every
 * inflate is capped by what actually comes out, not by what the header says (a zip bomb
 * declares a small size and inflates to gigabytes). Zip64 and encrypted entries are
 * refused or skipped rather than half-read.
 */

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

export class ZipError extends Error {}

function findEndOfCentralDirectory(view) {
  // The record is 22 bytes plus a comment of up to 65535.
  const stop = Math.max(0, view.byteLength - 22 - 0xffff);
  for (let i = view.byteLength - 22; i >= stop; i--) if (view.getUint32(i, true) === EOCD) return i;
  throw new ZipError('not a zip archive (no end-of-central-directory record)');
}

/** Inflate raw DEFLATE, stopping as soon as the output passes `cap` bytes. */
async function inflateCapped(u8, cap) {
  const stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  const reader = stream.getReader();
  const chunks = [];
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    got += value.length;
    if (got > cap) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
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
 * @param {Uint8Array} u8  the whole archive
 * @param {{keep?: (path: string) => boolean, maxFileBytes?: number, maxFiles?: number}} [opts]
 * @returns {Promise<{files: Map<string, Uint8Array>, skipped: {path: string, reason: string}[]}>}
 */
export async function readZip(u8, { keep = () => true, maxFileBytes = 1024 * 1024, maxFiles = 5000 } = {}) {
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const eocd = findEndOfCentralDirectory(view);
  const count = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  if (count === 0xffff || cdOffset === 0xffffffff) throw new ZipError('zip64 archives are not supported');
  if (count > maxFiles) throw new ZipError(`archive lists ${count} entries (limit ${maxFiles})`);

  const names = new TextDecoder('utf-8');
  const files = new Map();
  const skipped = [];
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > u8.length || view.getUint32(p, true) !== CENTRAL) throw new ZipError('corrupt central directory');
    const flags = view.getUint16(p + 8, true);
    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const size = view.getUint32(p + 24, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const localOffset = view.getUint32(p + 42, true);
    const path = names.decode(u8.subarray(p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;

    if (path.endsWith('/') || !keep(path)) continue;
    if (flags & 1) {
      skipped.push({ path, reason: 'encrypted' });
      continue;
    }
    if (size > maxFileBytes) {
      skipped.push({ path, reason: 'too large' });
      continue;
    }
    if (localOffset + 30 > u8.length || view.getUint32(localOffset, true) !== LOCAL) throw new ZipError(`corrupt local header for ${path}`);
    const start = localOffset + 30 + view.getUint16(localOffset + 26, true) + view.getUint16(localOffset + 28, true);
    const data = u8.subarray(start, start + compSize);
    if (data.length !== compSize) throw new ZipError(`truncated entry ${path}`);

    let bytes = null;
    if (method === 0) bytes = compSize <= maxFileBytes ? data.slice() : null;
    else if (method === 8) bytes = await inflateCapped(data, maxFileBytes);
    else {
      skipped.push({ path, reason: `compression method ${method}` });
      continue;
    }
    if (!bytes) {
      skipped.push({ path, reason: 'inflates past the size limit' });
      continue;
    }
    files.set(path, bytes);
  }
  return { files, skipped };
}

/** sdists and bundles wrap everything in one top directory ("pkg-1.0/"); drop it. */
export function stripTopDirectory(files) {
  const tops = new Set([...files.keys()].map((k) => k.split('/')[0]));
  if (tops.size !== 1 || [...files.keys()].some((k) => !k.includes('/'))) return files;
  return new Map([...files].map(([k, v]) => [k.slice(k.indexOf('/') + 1), v]));
}

/**
 * Archive and byte primitives on web platform APIs only (DecompressionStream, crypto.subtle,
 * TextDecoder), shared by every adapter that must run both in Node 22 and in a browser tab.
 * Nothing here touches a filesystem: archives are read in memory, never extracted.
 */

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

export async function gunzip(u8) {
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

export async function digest(alg, u8) {
  return new Uint8Array(await crypto.subtle.digest(alg, u8));
}
export const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
export function base64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Download with real byte progress. */
export async function download(url, onProgress, fetchImpl) {
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

/**
 * Pins on disk, for the CLI. The fingerprints and the diff live in pins-core.js, shared
 * with the browser; this file only knows where the pins are kept.
 */
import { readFileSync, writeFileSync, mkdirSync, renameSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { fingerprintTool, fingerprintTools, diffFingerprints, serverKey } from './pins-core.js';

export { serverKey, fingerprintTools, diffFingerprints } from './pins-core.js';

export function pinsPath() {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'mcpscan', 'pins.json');
}

export const fingerprint = fingerprintTool;

export async function diffPins(previous, tools, opts = {}) {
  return diffFingerprints(previous, await fingerprintTools(tools), opts);
}

export function loadPins(path = pinsPath()) {
  try {
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {};
  } catch {
    return {};
  }
}

export function savePins(pins, path = pinsPath()) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(pins, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, path);
}

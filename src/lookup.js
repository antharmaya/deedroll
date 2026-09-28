/**
 * Which official-registry listing ships this npm package?
 *
 * The registry's own search matches listing names only (pretrip-mcp is listed as
 * agency.kesey/pretrip), so: a bundled index first, then a verified live name search.
 * A miss is reported as "no listing found", never "not listed" — the index is a dated
 * snapshot and name search cannot see listings named differently from their package.
 */
import { readFileSync } from 'node:fs';
import { fetchRegistryEntry } from './sources.js';
import { searchTerms, shipsPackage } from './model.js';

export { searchTerms } from './model.js';

const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';
export const FRESH_DAYS = 7;

let cachedIndex;
export function loadIndex() {
  if (cachedIndex !== undefined) return cachedIndex;
  try {
    cachedIndex = JSON.parse(readFileSync(new URL('./data/registry-index.json', import.meta.url), 'utf8'));
  } catch {
    cachedIndex = null; // no index shipped: fall back to live search only
  }
  return cachedIndex;
}

/**
 * @returns {Promise<{entry: object|null, source: 'index'|'search'|'index-miss'|null, listings: string[], indexBuiltAt: string|null}>}
 */
export async function findListing(npmName, { index = loadIndex(), fetchImpl = globalThis.fetch, fetchEntry = fetchRegistryEntry } = {}) {
  const indexBuiltAt = index?.builtAt ?? null;
  const fromIndex = index?.index?.[npmName] ?? [];
  for (const name of fromIndex) {
    const entry = await fetchEntry(name);
    if (entry && shipsPackage(entry.server, npmName)) return { entry, source: 'index', listings: fromIndex, indexBuiltAt };
  }

  // A complete, recent index is trusted on a miss: live name search costs 3-14 s per
  // term and rarely finds what a full walk of the registry did not. The price: a
  // listing created after builtAt is unseen until the index is rebuilt.
  const ageDays = indexBuiltAt ? (Date.now() - Date.parse(indexBuiltAt)) / 86400000 : Infinity;
  if (index?.complete && ageDays <= FRESH_DAYS) {
    return { entry: null, source: 'index-miss', listings: [], indexBuiltAt };
  }

  for (const term of searchTerms(npmName)) {
    const url = `${REGISTRY}?search=${encodeURIComponent(term)}&version=latest&limit=100`;
    const res = await fetchImpl(url);
    if (!res.ok) continue;
    const body = await res.json();
    const hits = (body.servers ?? []).filter((s) => shipsPackage(s.server, npmName));
    if (hits.length) {
      return { entry: hits[0], source: 'search', listings: hits.map((h) => h.server.name), indexBuiltAt };
    }
  }
  return { entry: null, source: null, listings: [], indexBuiltAt };
}

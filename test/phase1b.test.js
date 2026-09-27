import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { findListing, searchTerms } from '../src/lookup.js';
import { checkKnownVulnerabilities } from '../src/osv.js';
import { readCached, writeCached } from '../src/cache.js';
import { provenanceHistory } from '../src/sources.js';
import { checkProvenanceDrop } from '../src/checks.js';

const json = (body, status = 200) => ({ ok: status === 200, status, json: async () => body });

// ---------- registry listing lookup ----------

test('search terms strip scope noise and mcp/server words', () => {
  assert.deepEqual(searchTerms('pretrip-mcp'), ['pretrip']);
  assert.deepEqual(searchTerms('@acme/weather-mcp-server'), ['weather', 'acme']);
});

const listing = (name, identifier) => ({ server: { name, packages: [{ registryType: 'npm', identifier }] } });

test('index hit is verified against the listing before it is trusted', async () => {
  const index = { builtAt: '2026-09-27T00:00:00Z', index: { 'pkg-a': ['io.x/wrong', 'io.x/right'] } };
  const entries = { 'io.x/wrong': listing('io.x/wrong', 'something-else'), 'io.x/right': listing('io.x/right', 'pkg-a') };
  const r = await findListing('pkg-a', { index, fetchEntry: async (n) => entries[n], fetchImpl: async () => json({}) });
  assert.equal(r.entry.server.name, 'io.x/right');
  assert.equal(r.source, 'index');
});

test('live search only accepts a listing that actually ships the package', async () => {
  const fetchImpl = async () => json({ servers: [listing('io.impostor/pretrip', 'pretrip-mcp-fork'), listing('agency.kesey/pretrip', 'pretrip-mcp')] });
  const r = await findListing('pretrip-mcp', { index: null, fetchImpl });
  assert.equal(r.entry.server.name, 'agency.kesey/pretrip');
  assert.equal(r.source, 'search');
});

test('a miss is a miss, not a guess', async () => {
  const r = await findListing('nobody-mcp', { index: null, fetchImpl: async () => json({ servers: [listing('io.a/b', 'other')] }) });
  assert.equal(r.entry, null);
});

// ---------- OSV ----------

test('OSV: advisories become findings with severity, CVE alias and fix version', async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith('querybatch')) return json({ results: [{ vulns: [{ id: 'GHSA-aaaa' }] }] });
    return json({
      id: 'GHSA-aaaa',
      aliases: ['CVE-2025-1234'],
      summary: 'Path traversal',
      database_specific: { severity: 'HIGH' },
      affected: [{ package: { name: 'srv' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }],
    });
  };
  const { findings } = await checkKnownVulnerabilities([{ name: 'srv', version: '1.0.0' }], { fetchImpl });
  assert.equal(findings[0].severity, 'high');
  assert.match(findings[0].message, /CVE-2025-1234.*Path traversal.*fixed in 2\.0\.0/);
});

test('OSV: an outage is reported as a failed lookup, never as clean', async () => {
  const { findings, error } = await checkKnownVulnerabilities([{ name: 'srv', version: '1.0.0' }], {
    fetchImpl: async () => json({}, 503),
  });
  assert.ok(error);
  assert.equal(findings[0].check, 'vuln-lookup-failed');
  assert.match(findings[0].message, /not a clean result/);
});

// ---------- content-addressed cache ----------

const integrityOf = (b) => `sha512-${createHash('sha512').update(b).digest('base64')}`;

test('cache round-trips verified bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcpscan-cache-'));
  try {
    const bytes = Buffer.from('tarball bytes');
    writeCached(integrityOf(bytes), bytes, dir);
    assert.deepEqual(readCached(integrityOf(bytes), dir), bytes);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a tampered cache file is deleted and never returned', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcpscan-cache-'));
  try {
    const bytes = Buffer.from('original');
    const integrity = integrityOf(bytes);
    writeCached(integrity, bytes, dir);
    const [file] = readdirSync(dir);
    writeFileSync(join(dir, file), 'malicious replacement');
    assert.equal(readCached(integrity, dir), null);
    assert.equal(existsSync(join(dir, file)), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bytes that do not match their claimed integrity are never cached', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcpscan-cache-'));
  try {
    writeCached(integrityOf(Buffer.from('a')), Buffer.from('b'), dir);
    assert.equal(readdirSync(dir).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- provenance drop ----------

const packument = {
  time: { '1.0.0': '2026-01-01', '1.1.0': '2026-02-01', '1.2.0': '2026-03-01' },
  versions: {
    '1.0.0': { dist: {} },
    '1.1.0': { dist: { attestations: { url: 'x' } } },
    '1.2.0': { dist: {} },
  },
};

test('provenance history sees the drop from 1.1.0 to 1.2.0', () => {
  assert.deepEqual(provenanceHistory(packument, '1.2.0'), { current: false, earlierWithProvenance: 1, lastWithProvenance: '1.1.0' });
  assert.equal(provenanceHistory(packument, '1.1.0').current, true);
});

test('a drop is flagged; never having provenance is not', () => {
  const dropped = checkProvenanceDrop({ name: 'p', version: '1.2.0', provenance: provenanceHistory(packument, '1.2.0') });
  assert.equal(dropped[0].check, 'provenance-dropped');
  const never = checkProvenanceDrop({ name: 'p', version: '1.0.0', provenance: provenanceHistory(packument, '1.0.0') });
  assert.deepEqual(never, []);
});

test('a complete, fresh index is trusted on a miss: no live search', async () => {
  let searched = false;
  const index = { builtAt: new Date().toISOString(), complete: true, index: {} };
  const r = await findListing('nobody-mcp', { index, fetchImpl: async () => { searched = true; return json({ servers: [] }); } });
  assert.equal(r.source, 'index-miss');
  assert.equal(searched, false);
});

test('a stale or incomplete index still falls back to live search', async () => {
  let searches = 0;
  const fetchImpl = async () => { searches++; return json({ servers: [] }); };
  await findListing('nobody-mcp', { index: { builtAt: '2026-01-01T00:00:00Z', complete: true, index: {} }, fetchImpl });
  await findListing('nobody-mcp', { index: { builtAt: new Date().toISOString(), complete: false, index: {} }, fetchImpl });
  assert.ok(searches >= 2);
});

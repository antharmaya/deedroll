import test from 'node:test';
import assert from 'node:assert/strict';
import { badgeOf, atomFeed, describeEntry } from '../src/feeds.js';

const rec = (signals = {}, extra = {}) => ({
  name: 'io.github.x/y', firstSeen: '2026-09-28', lastSeen: '2026-10-02', gone: null,
  latest: { name: 'io.github.x/y', version: '1.0.0', packages: [{ type: 'npm', id: 'y' }], remotes: [] },
  signals, probes: {}, log: [{ date: '2026-09-28', kind: 'seen', version: '1.0.0' }], ...extra,
});
const sig = (undeclared = [], readmeOnly = []) => ({ version: '1.0.0', undeclared: undeclared.map((n) => ({ n, at: 'i.js:1' })), readmeOnly, settings: [], hosts: [], caps: [], install: [], vulns: 0 });

test('the badge states how the code compares with the listing, never a verdict', () => {
  assert.equal(badgeOf(rec({ 'npm:y': sig() })).message, 'declares what it reads');
  assert.equal(badgeOf(rec({ 'npm:y': sig(['A_KEY', 'B_KEY']) })).message, '2 credentials not declared');
  assert.equal(badgeOf(rec({ 'npm:y': sig([], ['A_KEY']) })).message, '1 credential in README only');
  assert.equal(badgeOf(null).message, 'not in the registry');
  assert.equal(badgeOf(rec({}, { gone: '2026-10-01' })).message, 'no longer listed');
  assert.equal(badgeOf(rec({ 'npm:y': { error: 'not found', missing: true } })).message, 'package not found');
  for (const b of [badgeOf(rec({ 'npm:y': sig(['A_KEY']) })), badgeOf(rec({ 'npm:y': sig() }))]) {
    assert.equal(b.schemaVersion, 1);
    assert.doesNotMatch(b.message, /safe|secure|verified|risk|danger/i);
  }
});

test('the same credential read by two packages of one server is counted once', () => {
  assert.equal(badgeOf(rec({ 'npm:y': sig(['A_KEY']), 'pypi:y': sig(['A_KEY']) })).message, '1 credential not declared');
});

test('every log entry kind reads as a sentence', () => {
  const entries = [
    { kind: 'seen', version: '1.0.0' },
    { kind: 'back', version: '1.1.0' },
    { kind: 'gone' },
    { kind: 'changed', changes: [{ field: 'version', from: '1.0.0', to: '1.1.0' }, { field: 'description', from: 'a', to: 'b' }] },
    { kind: 'scanned', package: 'npm:y', version: '1.0.0', first: true, undeclared: ['PAY_KEY'], readmeOnly: [], hosts: 0, caps: [], install: 0, vulns: 0, flags: [] },
    { kind: 'scanned', package: 'npm:y', version: '1.1.0', undeclared: { added: ['NEW_KEY'], removed: [] }, provenance: { from: true, to: false } },
    { kind: 'probe', url: 'https://h.example/mcp', first: true, probed: true, tools: 3 },
    { kind: 'probe', url: 'https://h.example/mcp', probed: true, tools: 4, added: ['t4'], removed: [], descriptionChanged: [], inputsChanged: [] },
  ];
  for (const e of entries) assert.match(describeEntry(e), /^[A-Z].*\.$/, JSON.stringify(e));
  assert.match(describeEntry(entries[5]), /now reads, undeclared: NEW_KEY; stopped publishing with provenance/);
  assert.match(describeEntry(entries[4]), /PAY_KEY/);
});

test('the feed is newest first and escapes what publishers wrote', () => {
  const r = rec({}, { name: 'io.github.x/<y&z>', log: [
    { date: '2026-09-28', kind: 'seen', version: '1.0.0' },
    { date: '2026-09-30', kind: 'changed', changes: [{ field: 'version', from: '1.0.0', to: '<2>' }] },
  ] });
  const feed = atomFeed(r, 'https://deedroll.antharmaya.com');
  assert.ok(feed.indexOf('2026-09-30T00:00:00Z</updated>\n    <link') < feed.indexOf('2026-09-28T00:00:00Z</updated>\n    <link'));
  assert.doesNotMatch(feed, /<y&z>|<2>/);
  assert.match(feed, /&lt;y&amp;z&gt;/);
  assert.equal((feed.match(/<entry>/g) ?? []).length, 2);
});

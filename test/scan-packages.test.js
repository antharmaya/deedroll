import test from 'node:test';
import assert from 'node:assert/strict';
import { summarize, SCAN_RULES } from '../scripts/scan-packages.js';

const result = (findings) => ({ pkg: { version: '1.0.0', files: new Map([['index.js', Buffer.from('')]]), integrityOk: true }, findings });

test('a mention inside a string keeps that fact in the stored summary', () => {
  const s = summarize('npm', 'a', '1.0.0', result([
    { check: 'undeclared-env', subject: 'UPLINK_API_KEY', severity: 'info', inText: true, evidence: [{ file: 'i.js', line: 9 }] },
    { check: 'undeclared-env', subject: 'REAL_KEY', severity: 'high', evidence: [{ file: 'i.js', line: 2 }] },
  ]));
  assert.deepEqual(s.reads.map((r) => [r.n, r.txt ?? false]), [['UPLINK_API_KEY', true], ['REAL_KEY', false]]);
});

test('every summary records the rules it was made under', () => {
  const s = summarize('npm', 'a', '1.0.0', result([]));
  assert.equal(s.rules, SCAN_RULES);
  assert.match(SCAN_RULES, /^[0-9a-f]{12}$/);
});

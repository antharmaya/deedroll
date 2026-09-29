import test from 'node:test';
import assert from 'node:assert/strict';
import { detectToolCollisions, collisionFindings } from '../src/collisions.js';

test('two distinct installs sharing a tool name collide; a name used once does not', () => {
  const installs = [
    { key: 'a', tools: ['search', 'read_file'] },
    { key: 'b', tools: ['search', 'run_shell'] },
    { key: 'c', tools: ['read_file'] },
  ];
  const c = detectToolCollisions(installs);
  assert.deepEqual(c.map((x) => x.name), ['read_file', 'search']);
  assert.deepEqual(new Set(c.find((x) => x.name === 'search').keys), new Set(['a', 'b']));
  assert.deepEqual(new Set(c.find((x) => x.name === 'read_file').keys), new Set(['a', 'c']));
  assert.ok(!c.some((x) => x.name === 'run_shell'));
});

test('a repeated name inside one install counts once, not as a self-collision', () => {
  const c = detectToolCollisions([{ key: 'a', tools: ['search', 'search'] }, { key: 'b', tools: ['other'] }]);
  assert.deepEqual(c, []);
});

test('no installs, or none overlapping, gives no findings', () => {
  assert.deepEqual(detectToolCollisions([]), []);
  assert.deepEqual(detectToolCollisions([{ key: 'a', tools: ['x'] }, { key: 'b', tools: ['y'] }]), []);
});

test('findings name the OTHER installs, not the one they are attached to', () => {
  const installs = [{ key: 'a', label: 'heroku (npm)' }, { key: 'b', label: 'stripe (npm)' }, { key: 'c', label: 'acme (pypi)' }];
  const collisions = detectToolCollisions([
    { key: 'a', tools: ['charge'] },
    { key: 'b', tools: ['charge'] },
    { key: 'c', tools: ['charge'] },
  ]);
  const labelOf = (k) => installs.find((i) => i.key === k).label;
  const fA = collisionFindings(collisions, installs[0], labelOf);
  assert.equal(fA.length, 1);
  assert.equal(fA[0].check, 'tool-name-collision');
  assert.equal(fA[0].subject, 'charge');
  assert.equal(fA[0].severity, 'medium');
  assert.ok(!fA[0].message.includes('heroku'), 'never names itself');
  assert.ok(fA[0].message.includes('stripe (npm)') && fA[0].message.includes('acme (pypi)'));
});

test('an install with no colliding tools gets no findings', () => {
  const installs = [{ key: 'a' }, { key: 'b' }];
  const collisions = detectToolCollisions([{ key: 'a', tools: ['x'] }, { key: 'b', tools: ['y'] }]);
  assert.deepEqual(collisionFindings(collisions, installs[0], (k) => k), []);
});

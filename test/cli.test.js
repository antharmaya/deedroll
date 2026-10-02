import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../bin/deedroll.js', import.meta.url));

// The whole CLI once crashed on load (an unescaped ${VAR} in the help template) while
// every unit test passed. This runs the binary itself.
test('the CLI starts and prints its usage', () => {
  const out = execFileSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' });
  assert.match(out, /deedroll --installed/);
  assert.match(out, /\$\{VAR\}/, 'placeholders print literally');
});

test('no target prints usage and exits 2', () => {
  let code = 0;
  try {
    execFileSync(process.execPath, [BIN], { encoding: 'utf8', stdio: 'pipe' });
  } catch (err) {
    code = err.status;
  }
  assert.equal(code, 2);
});

// lib/util.js env(): WEB_AUDIT_KIT_* primary names with deprecated TESTGPT7_* fallback.
const { test, afterEach } = require('node:test');
const assert = require('node:assert');
const { env } = require('../lib/util');

const KEYS = ['PROBE_NEW', 'PROBE_LEGACY', 'PROBE_BOTH'].flatMap(n => [`WEB_AUDIT_KIT_${n}`, `TESTGPT7_${n}`]);
afterEach(() => { for (const k of KEYS) delete process.env[k]; });

function captureStderr(fn) {
  const lines = [];
  const original = process.stderr.write;
  process.stderr.write = chunk => { lines.push(String(chunk)); return true; };
  try { return { value: fn(), lines }; } finally { process.stderr.write = original; }
}

test('env: reads the WEB_AUDIT_KIT_ name without a warning', () => {
  process.env.WEB_AUDIT_KIT_PROBE_NEW = 'new';
  const { value, lines } = captureStderr(() => env('PROBE_NEW'));
  assert.strictEqual(value, 'new');
  assert.deepStrictEqual(lines, []);
});

test('env: falls back to the legacy TESTGPT7_ name and warns once', () => {
  process.env.TESTGPT7_PROBE_LEGACY = 'old';
  const { value, lines } = captureStderr(() => [env('PROBE_LEGACY'), env('PROBE_LEGACY')]);
  assert.deepStrictEqual(value, ['old', 'old']);
  assert.strictEqual(lines.length, 1);
  assert.match(lines[0], /TESTGPT7_PROBE_LEGACY is deprecated; use WEB_AUDIT_KIT_PROBE_LEGACY/);
});

test('env: the new name wins when both are set; unset returns undefined', () => {
  process.env.WEB_AUDIT_KIT_PROBE_BOTH = 'new';
  process.env.TESTGPT7_PROBE_BOTH = 'old';
  const { value, lines } = captureStderr(() => env('PROBE_BOTH'));
  assert.strictEqual(value, 'new');
  assert.deepStrictEqual(lines, []);
  assert.strictEqual(env('PROBE_UNSET_ANYWHERE'), undefined);
});

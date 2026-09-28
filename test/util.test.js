// lib/util.js behavioral tests.
const { test } = require('node:test');
const assert = require('node:assert');
const { bool, escapeHtml, severityWeight, addFinding, parseRecipients } = require('../lib/util');

test('bool: only explicit truthy forms are true', () => {
  for (const v of [true, 'true', 'on', 1, '1']) assert.strictEqual(bool(v), true, String(v));
  for (const v of [false, 'false', 'TRUE', 'yes', 0, '0', '', null, undefined, {}, 2]) {
    assert.strictEqual(bool(v), false, String(v));
  }
});

test('escapeHtml: escapes all five HTML-significant characters', () => {
  assert.strictEqual(escapeHtml(`<a href="x" title='y'>&</a>`),
    '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
});

test('escapeHtml: null/undefined -> empty, numbers stringified, no double-escape surprises', () => {
  assert.strictEqual(escapeHtml(null), '');
  assert.strictEqual(escapeHtml(undefined), '');
  assert.strictEqual(escapeHtml(0), '0');
  assert.strictEqual(escapeHtml('&amp;'), '&amp;amp;');
});

test('severityWeight: known weights and fallback', () => {
  assert.deepStrictEqual(['Critical', 'High', 'Medium', 'Low', 'Info', undefined].map(severityWeight), [30, 18, 8, 3, 1, 1]);
});

test('addFinding: appends with sequential area-scoped id and all fields', () => {
  const findings = [];
  addFinding(findings, 'High', 'Security', 'T1', 'E1', 'F1', 'I1');
  addFinding(findings, 'Low', 'Design UX', 'T2', 'E2', 'F2', 'I2');
  assert.deepStrictEqual(findings[0], { id: 'Security-1', severity: 'High', area: 'Security', title: 'T1', evidence: 'E1', impact: 'I1', fix: 'F1' });
  assert.strictEqual(findings[1].id, 'Design UX-2');
});

test('parseRecipients: rejects CR/LF header-injection and angle-bracket payloads', () => {
  const out = parseRecipients('ok@example.com\r\nBcc: evil@example.com, "x" <y@example.com>, a\rb@example.com');
  assert.ok(out.includes('ok@example.com'));
  for (const r of out) assert.doesNotMatch(r, /[\r\n<>\s]/, r);
});

test('parseRecipients: caps at 20 and accepts ; and newline separators', () => {
  const many = Array.from({ length: 30 }, (_, i) => `u${i}@example.com`).join(';');
  assert.strictEqual(parseRecipients(many).length, 20);
  assert.deepStrictEqual(parseRecipients('a@example.com\nb@example.com'), ['a@example.com', 'b@example.com']);
  assert.deepStrictEqual(parseRecipients(undefined), []);
});

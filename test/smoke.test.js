// 순수 헬퍼 스모크 — 리팩 회귀 안전망. 서버 미기동(require.main 가드)으로 import만.
// 실행: npm test  (node --test)
const { test } = require('node:test');
const assert = require('node:assert');
const {
  isPrivateIp, isLoopbackHost, hostnameMatchesAllowlist,
  escapeHtml, parseRecipients, severityWeight,
} = require('../server');

test('isPrivateIp: 사설/메타데이터/루프백 → true', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1',
                    '169.254.169.254', '100.64.0.1', '0.0.0.0']) {
    assert.strictEqual(isPrivateIp(ip), true, ip);
  }
});

test('isPrivateIp: 공인 IP → false', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) {
    assert.strictEqual(isPrivateIp(ip), false, ip);
  }
});

test('isPrivateIp: IPv4-mapped IPv6도 내부 판정(SSRF 우회 차단)', () => {
  assert.strictEqual(isPrivateIp('::ffff:169.254.169.254'), true);
  assert.strictEqual(isPrivateIp('::ffff:8.8.8.8'), false);
});

test('isLoopbackHost', () => {
  for (const h of ['127.0.0.1', 'localhost', '::1', 'LOCALHOST']) assert.ok(isLoopbackHost(h), h);
  assert.strictEqual(isLoopbackHost('example.com'), false);
});

test('hostnameMatchesAllowlist: 정확/와일드카드', () => {
  assert.ok(hostnameMatchesAllowlist('example.com', 'example.com'));
  assert.ok(hostnameMatchesAllowlist('api.example.org', '*.example.org'));
  assert.strictEqual(hostnameMatchesAllowlist('evil.com', '*.example.org'), false);
  assert.strictEqual(hostnameMatchesAllowlist('notexample.com', 'example.com'), false);
});

test('escapeHtml: XSS 메타문자 이스케이프', () => {
  assert.strictEqual(escapeHtml('<a href="x">&\'</a>'),
    '&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;');
  assert.strictEqual(escapeHtml(null), '');
});

test('parseRecipients: 유효 이메일만, 최대 20', () => {
  assert.deepStrictEqual(parseRecipients('a@b.com, c@d.com'), ['a@b.com', 'c@d.com']);
  assert.deepStrictEqual(parseRecipients('bad, x@y.com; no@'), ['x@y.com']);
  assert.strictEqual(parseRecipients(Array.from({ length: 30 }, (_, i) => `u${i}@x.com`).join(',')).length, 20);
  assert.deepStrictEqual(parseRecipients(''), []);
});

test('severityWeight: 등급 가중치', () => {
  assert.strictEqual(severityWeight('Critical'), 30);
  assert.strictEqual(severityWeight('Low'), 3);
  assert.strictEqual(severityWeight('unknown'), 1);
});

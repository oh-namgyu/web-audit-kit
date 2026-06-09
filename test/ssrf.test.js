// SSRF 가드 회귀테스트 — '리다이렉트/타깃 사설IP 차단'을 잠금.
// (과거 redirect:'follow'로 퇴화하던 갭을 잡는 그물. fetch/Playwright 둘 다 매 홉 assertTargetAllowed 재검증.)
// IP 리터럴만 사용 → DNS·네트워크 불필요, 결정적. 실행: npm test
const { test } = require('node:test');
const assert = require('node:assert');
const { assertTargetAllowed } = require('../server');

// 기본은 loopback 바인딩이므로 사설IP 차단을 켜야 가드가 동작(운영 노출 모드는 기본 차단).
process.env.TESTGPT7_BLOCK_PRIVATE_IPS = 'true';

test('SSRF: 클라우드 메타데이터/사설/루프백 IP 차단', async () => {
  for (const u of ['http://169.254.169.254/latest/meta-data/', 'http://10.0.0.1/',
                   'http://127.0.0.1:9200/', 'http://192.168.0.1/', 'http://172.16.5.5/']) {
    await assert.rejects(() => assertTargetAllowed(new URL(u)), /blocked private|reserved/i, u);
  }
});

test('SSRF: 공인 IP는 허용', async () => {
  await assert.doesNotReject(() => assertTargetAllowed(new URL('http://93.184.216.34/')));
});

test('SSRF: http/https 외 프로토콜 거부', async () => {
  for (const u of ['ftp://example.com/', 'file:///etc/passwd', 'gopher://x/']) {
    await assert.rejects(() => assertTargetAllowed(new URL(u)), /http\/https/i, u);
  }
});

test('SSRF: IPv4-mapped IPv6 메타데이터도 차단(우회 방지)', async () => {
  await assert.rejects(() => assertTargetAllowed(new URL('http://[::ffff:169.254.169.254]/')));
});

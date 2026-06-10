// SSRF guard regression tests — lock in 'redirect / target private-IP blocking'.
// (Safety net for the gap where redirect:'follow' used to regress. Both fetch and
//  Playwright re-validate via assertTargetAllowed on every hop.)
// IP literals only → no DNS/network needed, deterministic. Run: npm test
const { test } = require('node:test');
const assert = require('node:assert');
const dns = require('node:dns');
const { assertTargetAllowed, pinnedLookup } = require('../server');

// Default binding is loopback, so private-IP blocking must be enabled for the
// guard to engage (the network-exposed mode blocks by default).
process.env.TESTGPT7_BLOCK_PRIVATE_IPS = 'true';

test('SSRF: blocks cloud metadata / private / loopback IPs', async () => {
  for (const u of ['http://169.254.169.254/latest/meta-data/', 'http://10.0.0.1/',
                   'http://127.0.0.1:9200/', 'http://192.168.0.1/', 'http://172.16.5.5/']) {
    await assert.rejects(() => assertTargetAllowed(new URL(u)), /blocked private|reserved/i, u);
  }
});

test('SSRF: allows public IPs', async () => {
  await assert.doesNotReject(() => assertTargetAllowed(new URL('http://93.184.216.34/')));
});

test('SSRF: rejects non-http/https protocols', async () => {
  for (const u of ['ftp://example.com/', 'file:///etc/passwd', 'gopher://x/']) {
    await assert.rejects(() => assertTargetAllowed(new URL(u)), /http\/https/i, u);
  }
});

test('SSRF: blocks IPv4-mapped IPv6 metadata too (bypass prevention)', async () => {
  await assert.rejects(() => assertTargetAllowed(new URL('http://[::ffff:169.254.169.254]/')));
});

// DNS rebinding regression: even if the check-time lookup and the connect-time
// lookup return different IPs, assertTargetAllowed returns the IP resolved at
// check time as a pin, and the connection is forced onto that pin (pinnedLookup),
// so TOCTOU/rebinding cannot reach a private network.
test('SSRF: DNS rebinding — pins the checked IP and blocks re-resolution', async () => {
  const realLookup = dns.promises.lookup;
  // First (check) call: public IP. Later (connect re-resolution) calls: private metadata IP.
  let calls = 0;
  dns.promises.lookup = async () => {
    calls += 1;
    const ip = calls === 1 ? '93.184.216.34' : '169.254.169.254';
    return [{ address: ip, family: 4 }];
  };
  try {
    const allow = await assertTargetAllowed(new URL('http://rebind.example/'));
    // The public IP resolved at check time must be returned as the pin (connection is fixed to it).
    assert.strictEqual(allow.pinnedIp, '93.184.216.34');
    // The connect lookup must force-return the pinned IP without re-querying DNS → never reaches the rebound private IP.
    const lookup = pinnedLookup(allow.pinnedIp);
    const resolved = await new Promise((res, rej) =>
      lookup('rebind.example', { all: true }, (e, addrs) => (e ? rej(e) : res(addrs))));
    assert.deepStrictEqual(resolved, [{ address: '93.184.216.34', family: 4 }]);
  } finally {
    dns.promises.lookup = realLookup;
  }
});

// If the rebind resolves to a private IP at 'check time', block immediately (never reach the pin).
test('SSRF: rejects when it rebinds to a private IP at check time', async () => {
  const realLookup = dns.promises.lookup;
  dns.promises.lookup = async () => [{ address: '10.1.2.3', family: 4 }];
  try {
    await assert.rejects(() => assertTargetAllowed(new URL('http://rebind2.example/')),
      /blocked private|reserved/i);
  } finally {
    dns.promises.lookup = realLookup;
  }
});

// lib/mail.js offline tests — header-injection hardening and the "no config, no send" gate.
// A non-existent sendmail path is pinned before import so no test can ever deliver mail.
const { test, afterEach } = require('node:test');
const assert = require('node:assert');
process.env.TESTGPT7_SENDMAIL_PATH = '/nonexistent/web-audit-kit-test-sendmail';
const { encodeHeader, foldBase64, buildEmailMessage, getMailConfig, sendReportEmail, sendWithSmtp } = require('../lib/mail');
const { makeReport } = require('./_fixtures');

const ENV_KEYS = ['TESTGPT7_MAIL_TRANSPORT', 'TESTGPT7_SMTP_HOST', 'SMTP_HOST', 'TESTGPT7_SMTP_PORT', 'SMTP_PORT'];
const saved = Object.fromEntries(ENV_KEYS.map(k => [k, process.env[k]]));
afterEach(() => {
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

const headerBlock = msg => msg.split('\r\n\r\n')[0].split('\r\n');

test('encodeHeader: CR/LF collapsed so no extra header can be injected', () => {
  const out = encodeHeader('Hello\r\nBcc: evil@example.com\nX: y');
  assert.doesNotMatch(out, /[\r\n]/);
  assert.strictEqual(out, 'Hello  Bcc: evil@example.com X: y');
});

test('encodeHeader: non-ASCII becomes RFC 2047 base64 encoded-word', () => {
  const out = encodeHeader('Prüfbericht ✓\r\nBcc: x');
  assert.match(out, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
  const decoded = Buffer.from(out.slice(10, -2), 'base64').toString('utf8');
  assert.strictEqual(decoded, 'Prüfbericht ✓  Bcc: x');
});

test('buildEmailMessage: CR/LF in subject/from/to cannot add headers', () => {
  const msg = buildEmailMessage({
    from: 'a@example.com\r\nBcc: evil@example.com',
    to: ['b@example.com\r\nCc: evil@example.com'],
    subject: 'S\r\nBcc: evil@example.com',
    body: 'body',
  });
  const headers = headerBlock(msg);
  assert.deepStrictEqual(headers.map(h => h.split(':')[0]),
    ['From', 'To', 'Subject', 'Date', 'MIME-Version', 'Content-Type', 'Content-Transfer-Encoding']);
  assert.ok(!headers.some(h => /^(Bcc|Cc):/i.test(h)));
});

test('buildEmailMessage: multipart with base64 attachments folded at 76 chars', () => {
  const content = 'x'.repeat(500);
  const msg = buildEmailMessage({ from: 'a@example.com', to: ['b@example.com'], subject: 's', body: 'hi',
    attachments: [{ filename: 'r.html', contentType: 'text/html; charset=UTF-8', content }] });
  const boundary = msg.match(/boundary="([^"]+)"/)[1];
  assert.ok(msg.trimEnd().endsWith(`--${boundary}--`));
  assert.match(msg, /Content-Disposition: attachment; filename="r.html"/);
  const folded = foldBase64(content);
  assert.ok(folded.split('\r\n').every(line => line.length <= 76));
  assert.strictEqual(Buffer.from(folded.replace(/\r\n/g, ''), 'base64').toString('utf8'), content);
});

test('getMailConfig: defaults to disabled transport', () => {
  delete process.env.TESTGPT7_MAIL_TRANSPORT;
  assert.strictEqual(getMailConfig().transport, 'disabled');
});

test('sendReportEmail: skipped when there are no valid recipients', async () => {
  process.env.TESTGPT7_MAIL_TRANSPORT = 'sendmail';
  const r = await sendReportEmail(makeReport({ profile: { reportRecipients: 'not-an-email\r\nBcc: x' } }));
  assert.strictEqual(r.status, 'skipped');
  assert.deepStrictEqual(r.recipients, []);
});

test('sendReportEmail: skipped when transport is unset/disabled/off', async () => {
  for (const t of [undefined, 'disabled', 'off', ' OFF ']) {
    if (t === undefined) delete process.env.TESTGPT7_MAIL_TRANSPORT; else process.env.TESTGPT7_MAIL_TRANSPORT = t;
    const r = await sendReportEmail(makeReport());
    assert.strictEqual(r.status, 'skipped', String(t));
    assert.strictEqual(r.reason, 'mail transport disabled');
  }
});

test('sendReportEmail: unknown transport (e.g. typo) never falls through to sendmail', async () => {
  for (const t of ['smpt', 'yes', 'true']) {
    process.env.TESTGPT7_MAIL_TRANSPORT = t;
    const r = await sendReportEmail(makeReport());
    assert.strictEqual(r.status, 'skipped', t);
    assert.match(r.reason, /unknown mail transport/);
  }
});

test('sendReportEmail: smtp without host fails closed without opening a socket', async () => {
  process.env.TESTGPT7_MAIL_TRANSPORT = 'smtp';
  delete process.env.TESTGPT7_SMTP_HOST;
  delete process.env.SMTP_HOST;
  const r = await sendReportEmail(makeReport());
  assert.strictEqual(r.status, 'failed');
  assert.match(r.error, /SMTP host is not configured/);
  await assert.rejects(() => sendWithSmtp({ smtp: { host: '' } }, ['a@example.com'], 'm'), /not configured/);
});

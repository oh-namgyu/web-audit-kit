// lib/report.js tests — every target/user-controlled string must be escaped in HTML.
const { test } = require('node:test');
const assert = require('node:assert');
const { buildHtmlReport, buildMarkdown, buildEmailSummary, severityClass } = require('../lib/report');
const { makeReport } = require('./_fixtures');

test('buildHtmlReport: no raw <script>/onerror payload survives anywhere', () => {
  const html = buildHtmlReport(makeReport());
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /<img/i);
  assert.match(html, /&lt;script&gt;alert\(&quot;x&quot;\)&lt;\/script&gt;/);
  assert.match(html, /onerror=&#39;y&#39;/);
});

test('buildHtmlReport: severity cannot break out of the class attribute', () => {
  const html = buildHtmlReport(makeReport());
  for (const m of html.matchAll(/class="([^"]*)"/g)) assert.match(m[1], /^[a-z0-9 -]*$/, m[1]);
});

test('buildHtmlReport: escapes report id inside <title>', () => {
  const html = buildHtmlReport(makeReport({ id: '</title><script>1</script>' }));
  assert.match(html, /<title>Site Audit Report &lt;\/title&gt;&lt;script&gt;1&lt;\/script&gt;<\/title>/);
});

test('buildHtmlReport: tolerates a minimal report (empty findings/viewports)', () => {
  const html = buildHtmlReport({ id: '1', targetUrl: 'http://a.test/', summary: {} });
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /No issues detected\./);
  assert.match(html, /No Critical\/High items\./);
  assert.match(html, /<li>None<\/li>/);
});

test('severityClass: letters only, lowercase, fallback low', () => {
  assert.strictEqual(severityClass('Critical'), 'critical');
  assert.strictEqual(severityClass(`High" onmouseover="x`), 'highonmouseoverx');
  assert.strictEqual(severityClass(''), 'low');
  assert.strictEqual(severityClass(undefined), 'low');
});

test('buildMarkdown: includes core sections, counts, and findings in order', () => {
  const md = buildMarkdown(makeReport({ findings: [
    { severity: 'High', area: 'Security', title: 'A', evidence: 'e', impact: 'i', fix: 'f' },
    { severity: 'Low', area: 'Design UX', title: 'B', evidence: 'e', impact: 'i', fix: 'f' },
  ] }));
  for (const h of ['# Site Audit Report', '## Audit Profile', '## Mail Delivery', '## Scope Plan', '## Findings', '## Viewports']) {
    assert.ok(md.includes(h), h);
  }
  assert.ok(md.indexOf('### 1. [High] Security - A') < md.indexOf('### 2. [Low] Design UX - B'));
  assert.match(md, /- Critical: 1/);
});

test('buildMarkdown: falls back to parsed profile recipients when mail not attempted', () => {
  const md = buildMarkdown(makeReport({ mailDelivery: undefined, profile: { reportRecipients: 'a@example.com;bad' } }));
  assert.match(md, /- Recipients: a@example\.com\n/);
  assert.match(md, /- Status: pending/);
});

test('buildEmailSummary: top 5 Critical/High only, and a no-priority fallback', () => {
  const findings = Array.from({ length: 8 }, (_, i) => ({ severity: i % 2 ? 'High' : 'Low', title: `T${i}` }));
  const body = buildEmailSummary(makeReport({ findings }));
  assert.deepStrictEqual(body.match(/^- \[High\] T\d$/gm), ['- [High] T1', '- [High] T3', '- [High] T5', '- [High] T7']);
  assert.match(buildEmailSummary({ targetUrl: 'x', findings: [] }), /- No Critical\/High items/);
});

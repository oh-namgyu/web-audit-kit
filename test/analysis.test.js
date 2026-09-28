// lib/analysis.js tests — profile normalization, scope gate, header/viewport findings, scoring.
const { test } = require('node:test');
const assert = require('node:assert');
const {
  normalizeAuditProfile, buildScopePlan, analyzeAuditProfile, analyzeHeaders,
  analyzeViewportResult, summarizeAreas, summarizeVerdict,
} = require('../lib/analysis');

const titles = findings => findings.map(f => f.title);
const plan = input => { const p = normalizeAuditProfile(input); return { p, s: buildScopePlan(p) }; };

test('normalizeAuditProfile: unknown enums fall back, strings trimmed and capped', () => {
  const p = normalizeAuditProfile({ ownership: '__proto__', environment: 'mars', permissionLevel: 'root', notes: ` ${'n'.repeat(2000)} `, contact: 'x'.repeat(500), allowDelete: 'on' });
  assert.strictEqual(p.ownership, 'owner');
  assert.strictEqual(p.environment, 'internal-test');
  assert.strictEqual(p.permissionLevel, 'surface-only');
  assert.strictEqual(p.notes.length, 1200);
  assert.strictEqual(p.contact.length, 200);
  assert.strictEqual(p.allowDelete, true);
  assert.strictEqual(p.labels.ownership, 'I am the owner');
});

test('normalizeAuditProfile: accepts nested {profile} and top-level notes fallback', () => {
  const p = normalizeAuditProfile({ profile: { ownership: 'external-or-unknown' }, notes: 'top' });
  assert.strictEqual(p.ownership, 'external-or-unknown');
  assert.strictEqual(p.notes, 'top');
});

test('buildScopePlan: owner surface-only has only default allowed items, nothing blocked', () => {
  const { s } = plan({});
  assert.strictEqual(s.allowed.length, 3);
  assert.deepStrictEqual(s.blocked, []);
  assert.match(s.label, / · /);
});

test('buildScopePlan: unknown ownership blocks login/write even with a test account', () => {
  const { s } = plan({ ownership: 'external-or-unknown', permissionLevel: 'test-data-write', hasTestAccount: true });
  assert.strictEqual(s.allowed.length, 3);
  assert.ok(s.blocked.some(b => /ownership\/approval is unclear/.test(b)));
  assert.ok(s.blocked.some(b => /post-login/.test(b)));
  assert.ok(s.blocked.some(b => /Create\/update\/upload/.test(b)));
});

test('buildScopePlan: other-team needs explicit approval', () => {
  const base = { ownership: 'other-team-authorized', permissionLevel: 'login-readonly', hasTestAccount: true };
  assert.ok(plan(base).s.blocked.some(b => /post-login/.test(b)));
  assert.ok(plan({ ...base, hasExplicitApproval: true }).s.allowed.some(a => /post-login read-only/.test(a)));
});

test('buildScopePlan: writes never allowed in production; delete needs sandbox+rollback', () => {
  const prod = plan({ environment: 'production', permissionLevel: 'test-data-write', hasTestAccount: true }).s;
  assert.ok(!prod.allowed.some(a => /create\/update/.test(a)));
  assert.ok(prod.manualRequired.length >= 3, 'production requires window/contact/recipients');
  const del = { environment: 'staging', permissionLevel: 'destructive-sandbox', hasTestAccount: true, allowDelete: true };
  assert.ok(plan(del).s.blocked.some(b => /Delete tests/.test(b)));
  assert.ok(plan({ ...del, hasRollback: true }).s.allowed.includes('Prepare sandbox delete tests'));
});

test('buildScopePlan: load test always blocked, forbidden areas echoed, lists de-duplicated', () => {
  const { s } = plan({ allowLoadTest: true, forbiddenAreas: '/admin', allowFileUpload: true, environment: 'production' });
  assert.ok(s.blocked.some(b => /Load testing/.test(b)));
  assert.ok(s.blocked.includes('Strictly excluded menus: /admin'));
  assert.strictEqual(new Set(s.blocked).size, s.blocked.length);
});

test('analyzeAuditProfile: risky production scope raises Critical findings', () => {
  const { p, s } = plan({ ownership: 'external-or-unknown', environment: 'production', allowDelete: true, allowLoadTest: true });
  const findings = [];
  analyzeAuditProfile(p, s, findings);
  const t = titles(findings);
  assert.ok(t.includes('Ownership/approval is unclear'));
  assert.ok(t.includes('A risky scope was selected against a live production system'));
  assert.ok(t.includes('A write-type test was selected but rollback is unconfirmed'));
  assert.ok(t.includes('Load testing was selected'));
  assert.ok(findings.every(f => f.area === 'Audit Scope'));
});

test('analyzeAuditProfile: clean owner profile yields no findings', () => {
  const { p, s } = plan({});
  const findings = [];
  analyzeAuditProfile(p, s, findings);
  assert.deepStrictEqual(findings, []);
});

const GOOD_HEADERS = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=()', 'strict-transport-security': 'max-age=31536000',
  'set-cookie': 'sid=1; HttpOnly; Secure; SameSite=Lax',
};

test('analyzeHeaders: fully hardened HTTPS response has no findings', () => {
  const findings = [];
  analyzeHeaders('https://example.test/', { headers: GOOD_HEADERS }, findings);
  assert.deepStrictEqual(findings, []);
});

test('analyzeHeaders: plain HTTP with no headers flags HTTPS/CSP/clickjacking but not HSTS', () => {
  const findings = [];
  analyzeHeaders('http://example.test/', {}, findings);
  const t = titles(findings);
  for (const x of ['Not served over HTTPS', 'Content-Security-Policy is missing', 'No clickjacking-defense header', 'No MIME-sniffing defense']) {
    assert.ok(t.includes(x), x);
  }
  assert.ok(!t.includes('HSTS is missing'));
});

test('analyzeHeaders: CSP frame-ancestors satisfies clickjacking check; weak cookie flagged', () => {
  const findings = [];
  analyzeHeaders('https://example.test/', { headers: { ...GOOD_HEADERS, 'set-cookie': 'sid=1' } }, findings);
  assert.deepStrictEqual(titles(findings).sort(), ['Cookie is missing HttpOnly', 'Cookie is missing SameSite', 'HTTPS cookie is missing Secure'].sort());
});

function viewport(metrics, extra = {}) {
  return { viewport: 'desktop', width: 1440, height: 1000, loadMs: 100, navError: null,
    consoleMessages: [], requestFailures: [], badResponses: [], apiCalls: [], metrics, ...extra };
}
const CLEAN_METRICS = {
  title: 'Product dashboard', lang: 'en', h1: 1, textLength: 500,
  landmarks: { main: 1, nav: 1 }, counts: { buttons: 2, links: 5, inputs: 0, forms: 0, nodes: 200, scripts: 3 },
  resourceCount: 10, navTiming: { transferSize: 1000 },
};

test('analyzeViewportResult: clean page yields no findings', () => {
  const findings = [];
  analyzeViewportResult(viewport(CLEAN_METRICS), findings);
  assert.deepStrictEqual(findings, []);
});

test('analyzeViewportResult: broken page flags each area with viewport label', () => {
  const findings = [];
  analyzeViewportResult(viewport({ title: '', textLength: 10, duplicateIds: [{ id: 'a', count: 2 }], unsafeBlankLinks: 1, counts: { nodes: 5000 } }, {
    navError: 'net::ERR', loadMs: 9000, consoleMessages: [{ type: 'error', text: 'boom' }], requestFailures: [{ url: 'u' }],
  }), findings);
  const t = titles(findings);
  for (const x of ['failed to load', 'initial load is very slow', 'console errors occurred', 'duplicate ids', 'document title is weak',
                   'has no H1', 'network failures occurred', 'excessive DOM nodes', 'target=_blank']) {
    assert.ok(t.some(y => y.startsWith('desktop 1440x1000 ') && y.includes(x)), x);
  }
  assert.ok(findings.find(f => f.title.includes('target=_blank')).area === 'Security');
});

test('analyzeViewportResult: 5-8s load is Medium, not High', () => {
  const findings = [];
  analyzeViewportResult(viewport(CLEAN_METRICS, { loadMs: 6000 }), findings);
  assert.deepStrictEqual(findings.map(f => [f.severity, f.title]), [['Medium', 'desktop 1440x1000 initial load is slow']]);
});

test('summarizeVerdict: empty -> 100 and usable', () => {
  const s = summarizeVerdict([]);
  assert.strictEqual(s.score, 100);
  assert.strictEqual(s.verdict, 'Usable in production');
  assert.deepStrictEqual(s.counts, { Critical: 0, High: 0, Medium: 0, Low: 0 });
});

test('summarizeVerdict: verdict thresholds', () => {
  const f = (sev, n) => Array.from({ length: n }, (_, i) => ({ severity: sev, area: 'A', title: `${sev}${i}` }));
  assert.match(summarizeVerdict(f('Critical', 1)).verdict, /Do not use/);
  assert.strictEqual(summarizeVerdict(f('High', 4)).verdict, 'Shell or high-risk demo level');
  assert.strictEqual(summarizeVerdict(f('High', 2)).verdict, 'Internal testing only');
  assert.strictEqual(summarizeVerdict(f('High', 1)).verdict, 'Needs more development');
  assert.strictEqual(summarizeVerdict(f('Medium', 5)).verdict, 'Needs more development');
  assert.strictEqual(summarizeVerdict(f('Medium', 4)).verdict, 'Usable in production');
});

test('summarizeVerdict: same finding on desktop+mobile is penalized once; score floors at 0', () => {
  const dup = [
    { severity: 'High', area: 'Design UX', title: 'desktop 1440x1000 has no H1' },
    { severity: 'High', area: 'Design UX', title: 'mobile 390x844 has no H1' },
  ];
  const s = summarizeVerdict(dup);
  assert.strictEqual(s.score, 100 - 18);
  assert.strictEqual(s.counts.High, 2, 'counts still reflect both');
  const many = Array.from({ length: 10 }, (_, i) => ({ severity: 'Critical', area: 'A', title: `t${i}` }));
  assert.strictEqual(summarizeVerdict(many).score, 0);
  assert.strictEqual(summarizeVerdict(many).topPriority.length, 6);
});

test('summarizeAreas: per-area totals and severity breakdown', () => {
  assert.deepStrictEqual(summarizeAreas([
    { area: 'Security', severity: 'High' }, { area: 'Security', severity: 'Low' }, { area: 'Architecture', severity: 'Medium' },
  ]), {
    Security: { total: 2, Critical: 0, High: 1, Medium: 0, Low: 1 },
    Architecture: { total: 1, Critical: 0, High: 0, Medium: 1, Low: 0 },
  });
});

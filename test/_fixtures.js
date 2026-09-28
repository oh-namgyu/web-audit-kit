// Shared offline fixtures for the unit tests (no network, no Playwright).
// node --test also loads this file; it defines no tests.
const XSS = `<script>alert("x")</script><img src=x onerror='y'>`;

function makeReport(overrides = {}) {
  return {
    id: '20260101000000',
    targetUrl: `http://example.test/?q=${XSS}`,
    generatedAt: '2026-01-01T00:00:00.000Z',
    profile: {
      labels: { ownership: XSS, environment: XSS, permissionLevel: XSS },
      reportRecipients: `a@example.com, ${XSS}`,
      testWindow: XSS, contact: XSS, forbiddenAreas: XSS, notes: XSS,
    },
    scopePlan: { label: XSS, allowed: [XSS], blocked: [XSS], manualRequired: [XSS], warnings: [XSS] },
    summary: {
      verdict: XSS, score: XSS,
      counts: { Critical: 1, High: 1, Medium: 0, Low: 0 },
      areas: { Security: { total: 1, Critical: 1, High: 0, Medium: 0, Low: 0 } },
    },
    findings: [
      { id: 'Security-1', severity: 'Critical', area: 'Security', title: XSS, evidence: XSS, impact: XSS, fix: XSS },
      { id: 'x-2', severity: `High"><script>`, area: XSS, title: XSS, evidence: XSS, impact: XSS, fix: XSS },
    ],
    viewports: [{
      viewport: XSS, width: 1440, height: 1000, status: XSS, loadMs: XSS,
      consoleMessages: [], requestFailures: [], metrics: { overflow: [] },
    }],
    mailDelivery: { status: XSS, error: XSS },
    ...overrides,
  };
}

module.exports = { XSS, makeReport };

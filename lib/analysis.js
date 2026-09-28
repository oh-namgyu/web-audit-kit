// Audit analysis entry point: Playwright loading, finding summarization, and
// re-exports of the scope, findings, and viewport modules.
const { env, severityWeight } = require('./util');
const scope = require('./scope');
const { analyzeHeaders, analyzeViewportResult } = require('./findings');
const { inspectViewport } = require('./viewport');

const PLAYWRIGHT_MODULE_PATH = env('PLAYWRIGHT_PATH') || '';

// Canonical audit area order — single source of truth for report rendering.
// Mirrored in public/app.js (AUDIT_AREAS) for the client-side balance view.
const AUDIT_AREAS = ['Security', 'Design UX', 'Functional QA', 'Architecture', 'Audit Scope'];

function loadPlaywright() {
  try {
    return require('playwright');
  } catch (error) {
    if (PLAYWRIGHT_MODULE_PATH) return require(PLAYWRIGHT_MODULE_PATH);
    const wrapped = new Error('Playwright is required. Run "npm install" or set WEB_AUDIT_KIT_PLAYWRIGHT_PATH to a local Playwright module path.');
    wrapped.cause = error;
    throw wrapped;
  }
}

// ---- Summary ----------------------------------------------------------------

function summarizeAreas(findings) {
  const areas = {};
  for (const item of findings) {
    if (!areas[item.area]) areas[item.area] = { total: 0, Critical: 0, High: 0, Medium: 0, Low: 0 };
    areas[item.area].total += 1;
    areas[item.area][item.severity] = (areas[item.area][item.severity] || 0) + 1;
  }
  return areas;
}

function summarizeVerdict(findings) {
  const counts = ['Critical', 'High', 'Medium', 'Low'].reduce((acc, key) => {
    acc[key] = findings.filter(item => item.severity === key).length;
    return acc;
  }, {});
  const scoredFindings = [...new Map(findings.map(item => {
    const normalizedTitle = String(item.title || '').replace(/^(desktop|mobile)\s+\d+x\d+\s+/i, '');
    return [`${item.area}:${normalizedTitle}`, item];
  })).values()];
  const penalty = scoredFindings.reduce((sum, item) => sum + severityWeight(item.severity), 0);
  const score = Math.max(0, Math.min(100, 100 - penalty));
  let verdict = 'Usable in production';
  if (counts.Critical) verdict = 'Do not use (security/functional blocker)';
  else if (counts.High >= 4) verdict = 'Shell or high-risk demo level';
  else if (counts.High >= 2) verdict = 'Internal testing only';
  else if (counts.High || counts.Medium >= 5) verdict = 'Needs more development';
  return {
    score,
    verdict,
    counts,
    areas: summarizeAreas(findings),
    topPriority: findings
      .filter(item => ['Critical', 'High'].includes(item.severity))
      .slice(0, 6)
      .map(item => item.title),
  };
}

module.exports = {
  AUDIT_AREAS,
  OWNERSHIP_OPTIONS: scope.OWNERSHIP_OPTIONS,
  ENVIRONMENT_OPTIONS: scope.ENVIRONMENT_OPTIONS,
  PERMISSION_OPTIONS: scope.PERMISSION_OPTIONS,
  loadPlaywright,
  optionValue: scope.optionValue,
  normalizeAuditProfile: scope.normalizeAuditProfile,
  buildScopePlan: scope.buildScopePlan,
  analyzeAuditProfile: scope.analyzeAuditProfile,
  analyzeHeaders,
  inspectViewport,
  analyzeViewportResult,
  summarizeAreas,
  summarizeVerdict,
};

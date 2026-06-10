// Report rendering: Markdown, email summary, and the standalone HTML report,
// plus persistence of the three report artifacts to the local data directory.
const path = require('path');
const fs = require('fs/promises');
const { escapeHtml, parseRecipients } = require('./util');
const { AUDIT_AREAS } = require('./analysis');

const REPORTS_DIR = path.join(__dirname, '..', 'data', 'reports');

function buildMarkdown(report) {
  const lines = [
    `# Site Audit Report`,
    ``,
    `- Target: ${report.targetUrl}`,
    `- Generated: ${report.generatedAt}`,
    `- Verdict: ${report.summary.verdict}`,
    `- Score: ${report.summary.score}`,
    `- Scope: ${report.scopePlan?.label || '-'}`,
    ``,
    `## Audit Profile`,
    ``,
    `- Ownership: ${report.profile?.labels?.ownership || '-'}`,
    `- Environment: ${report.profile?.labels?.environment || '-'}`,
    `- Permission: ${report.profile?.labels?.permissionLevel || '-'}`,
    `- Test Window: ${report.profile?.testWindow || '-'}`,
    `- Contact: ${report.profile?.contact || '-'}`,
    `- Report Recipients: ${report.profile?.reportRecipients || '-'}`,
    `- Forbidden Areas: ${report.profile?.forbiddenAreas || '-'}`,
    `- Notes: ${report.profile?.notes || '-'}`,
    ``,
    `## Mail Delivery`,
    ``,
    `- Status: ${report.mailDelivery?.status || 'pending'}`,
    `- Transport: ${report.mailDelivery?.transport || '-'}`,
    `- Recipients: ${(report.mailDelivery?.recipients || parseRecipients(report.profile?.reportRecipients)).join(', ') || '-'}`,
    `- Sent At: ${report.mailDelivery?.sentAt || '-'}`,
    `- Error: ${report.mailDelivery?.error || report.mailDelivery?.reason || '-'}`,
    ``,
    `## Scope Plan`,
    ``,
    `### Allowed`,
    ...(report.scopePlan?.allowed || []).map(item => `- ${item}`),
    ``,
    `### Blocked`,
    ...((report.scopePlan?.blocked || []).length ? report.scopePlan.blocked : ['None']).map(item => `- ${item}`),
    ``,
    `### Manual Required`,
    ...((report.scopePlan?.manualRequired || []).length ? report.scopePlan.manualRequired : ['None']).map(item => `- ${item}`),
    ``,
    `## Severity Counts`,
    ``,
    ...Object.entries(report.summary.counts).map(([key, value]) => `- ${key}: ${value}`),
    ``,
    `## Area Counts`,
    ``,
    ...Object.entries(report.summary.areas || {}).map(([area, value]) => `- ${area}: ${value.total || 0} (Critical ${value.Critical || 0}, High ${value.High || 0}, Medium ${value.Medium || 0}, Low ${value.Low || 0})`),
    ``,
    `## Findings`,
    ``,
    ...report.findings.flatMap((item, index) => [
      `### ${index + 1}. [${item.severity}] ${item.area} - ${item.title}`,
      ``,
      `- Evidence: ${item.evidence}`,
      `- Impact: ${item.impact}`,
      `- Fix: ${item.fix}`,
      ``,
    ]),
    `## Viewports`,
    ``,
    ...report.viewports.map(item => `- ${item.viewport}: status ${item.status || '-'}, load ${item.loadMs}ms, console ${item.consoleMessages.length}, network failures ${item.requestFailures.length}`),
  ];
  return lines.join('\n');
}

function buildEmailSummary(report) {
  const counts = report.summary?.counts || {};
  const areas = report.summary?.areas || {};
  const priority = (report.findings || [])
    .filter(item => ['Critical', 'High'].includes(item.severity))
    .slice(0, 5);
  return [
    `# ${report.summary?.verdict || 'Audit Result'}`,
    ``,
    `Target: ${report.targetUrl}`,
    `Generated: ${report.generatedAt}`,
    `Score: ${report.summary?.score ?? '-'}`,
    `Scope: ${report.scopePlan?.label || '-'}`,
    ``,
    `## Summary`,
    ``,
    `- Critical: ${counts.Critical || 0}`,
    `- High: ${counts.High || 0}`,
    `- Medium: ${counts.Medium || 0}`,
    `- Low: ${counts.Low || 0}`,
    `- Security: ${areas.Security?.total || 0}`,
    `- Design UX: ${areas['Design UX']?.total || 0}`,
    `- Functional QA: ${areas['Functional QA']?.total || 0}`,
    `- Architecture: ${areas.Architecture?.total || 0}`,
    ``,
    `## Look At First`,
    ``,
    ...(priority.length ? priority.map(item => `- [${item.severity}] ${item.title}`) : ['- No Critical/High items']),
    ``,
    `The HTML report is the attachment for human readers.`,
    `The Markdown report is the attachment for AI/agents.`,
  ].join('\n');
}

function severityClass(severity) {
  return String(severity || '').toLowerCase().replace(/[^a-z]/g, '') || 'low';
}

const REPORT_STYLES = `
    :root { --ink:#172033; --muted:#667085; --line:#d9e0ea; --bg:#f6f7f9; --blue:#1d4ed8; --critical:#7f1d1d; --high:#b42318; --medium:#b7791f; --low:#2563eb; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font-family:Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height:1.55; }
    .page { max-width:1120px; margin:0 auto; padding:32px 20px 48px; }
    .hero { background:#0f172a; color:white; border-radius:10px; padding:28px; margin-bottom:18px; }
    .hero p { color:#cbd5e1; margin:6px 0 0; overflow-wrap:anywhere; }
    .eyebrow { color:#93c5fd; font-size:12px; font-weight:900; letter-spacing:.08em; text-transform:uppercase; }
    h1 { font-size:32px; line-height:1.15; margin:8px 0 0; }
    h2 { font-size:20px; margin:0 0 12px; }
    h3 { font-size:16px; margin:0 0 8px; }
    .summary { display:grid; grid-template-columns:1.1fr repeat(4, minmax(110px, .5fr)); gap:12px; margin-bottom:18px; }
    .card, .section { background:white; border:1px solid var(--line); border-radius:8px; padding:16px; }
    .score b { display:block; font-size:40px; line-height:1; }
    .score span, .card span { color:var(--muted); font-size:12px; font-weight:800; }
    .metric b { display:block; font-size:28px; }
    .grid { display:grid; gap:16px; grid-template-columns:1fr 1fr; margin-bottom:16px; }
    .section { margin-bottom:16px; }
    .pill { display:inline-block; border-radius:999px; color:white; font-size:11px; font-weight:900; padding:4px 8px; }
    .critical { background:var(--critical); } .high { background:var(--high); } .medium { background:var(--medium); } .low { background:var(--low); }
    dl { display:grid; gap:8px; margin:0; }
    dl div { background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:9px; }
    dt { color:var(--muted); font-size:11px; font-weight:900; margin-bottom:2px; }
    dd { margin:0; font-size:13px; overflow-wrap:anywhere; }
    ul { margin:0; padding-left:20px; }
    li { margin:4px 0; }
    .finding { border:1px solid var(--line); border-left:5px solid var(--low); border-radius:8px; padding:14px; margin-bottom:12px; }
    .finding.critical-border { border-left-color:var(--critical); } .finding.high-border { border-left-color:var(--high); } .finding.medium-border { border-left-color:var(--medium); } .finding.low-border { border-left-color:var(--low); }
    .finding-head { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
    .finding-head strong { color:var(--muted); font-size:12px; }
    .direction { display:grid; gap:10px; grid-template-columns:repeat(3, minmax(0, 1fr)); }
    .direction article { background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:12px; }
    .area-grid { display:grid; gap:10px; grid-template-columns:repeat(5, minmax(0, 1fr)); margin-bottom:16px; }
    .area-grid article { background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:12px; }
    .area-grid b { display:block; font-size:18px; }
    .area-grid span { color:var(--muted); font-size:12px; font-weight:800; }
    .footer { color:var(--muted); font-size:12px; margin-top:20px; }
    @media (max-width:900px) { .summary, .grid, .direction, .area-grid { grid-template-columns:1fr; } h1 { font-size:25px; } }
    @media print { body { background:white; } .page { padding:0; } .hero { border-radius:0; } }`;

function htmlList(items) {
  return (items && items.length ? items : ['None']).map(item => `<li>${escapeHtml(item)}</li>`).join('');
}

function renderHero(report, scope, generated) {
  return `<header class="hero">
      <div class="eyebrow">Site Audit Report</div>
      <h1>${escapeHtml(report.summary?.verdict || 'Audit Result')}</h1>
      <p>${escapeHtml(report.targetUrl)} · ${escapeHtml(generated)}</p>
      <p>${escapeHtml(scope.label || 'Scope not set')}</p>
    </header>`;
}

function renderSummaryCards(report, counts) {
  return `<section class="summary">
      <article class="card score"><span>Audit Score</span><b>${escapeHtml(report.summary?.score ?? '-')}</b><p>${escapeHtml(report.summary?.verdict || '-')}</p></article>
      <article class="card metric"><span>Critical</span><b>${counts.Critical || 0}</b></article>
      <article class="card metric"><span>High</span><b>${counts.High || 0}</b></article>
      <article class="card metric"><span>Medium</span><b>${counts.Medium || 0}</b></article>
      <article class="card metric"><span>Low</span><b>${counts.Low || 0}</b></article>
    </section>`;
}

function renderOverview(report, profile, priority, areas) {
  return `<section class="grid">
      <article class="section">
        <h2>Summary</h2>
        <dl>
          <div><dt>Target</dt><dd>${escapeHtml(report.targetUrl)}</dd></div>
          <div><dt>Ownership/Stage/Permission</dt><dd>${escapeHtml(profile.labels?.ownership || '-')} · ${escapeHtml(profile.labels?.environment || '-')} · ${escapeHtml(profile.labels?.permissionLevel || '-')}</dd></div>
          <div><dt>Report Recipients</dt><dd>${escapeHtml(profile.reportRecipients || '-')}</dd></div>
          <div><dt>Mail Delivery</dt><dd>${escapeHtml(report.mailDelivery?.status || 'pending')} ${escapeHtml(report.mailDelivery?.error || report.mailDelivery?.reason || '')}</dd></div>
        </dl>
      </article>
      <article class="section">
        <h2>Key Risks</h2>
        ${priority.length ? `<ul>${priority.map(item => `<li><b>${escapeHtml(item.severity)}</b> ${escapeHtml(item.title)}</li>`).join('')}</ul>` : '<p>No Critical/High items.</p>'}
        <h3>Findings by Area</h3>
        ${areas.length ? `<ul>${areas.map(([area, count]) => `<li>${escapeHtml(area)}: ${count}</li>`).join('')}</ul>` : '<p>No issues detected.</p>'}
      </article>
    </section>`;
}

function renderAreaBalance(areaCounts) {
  return `<section class="section">
      <h2>Area Balance</h2>
      <div class="area-grid">
        ${AUDIT_AREAS.map(area => {
          const row = areaCounts[area] || {};
          return `<article><span>${escapeHtml(area)}</span><b>${row.total || 0}</b><small>C ${row.Critical || 0} · H ${row.High || 0} · M ${row.Medium || 0} · L ${row.Low || 0}</small></article>`;
        }).join('')}
      </div>
    </section>`;
}

function renderDirectionAndScope(scope, priority) {
  return `<section class="section">
      <h2>Direction</h2>
      <div class="direction">
        <article><h3>Fix Now</h3><ul>${htmlList(priority.map(item => item.fix).slice(0, 4))}</ul></article>
        <article><h3>Blocked This Run</h3><ul>${htmlList(scope.blocked)}</ul></article>
        <article><h3>Manual Confirmation Needed</h3><ul>${htmlList(scope.manualRequired)}</ul></article>
      </div>
    </section>

    <section class="section">
      <h2>Audit Scope</h2>
      <div class="grid">
        <article><h3>Allowed To Run</h3><ul>${htmlList(scope.allowed)}</ul></article>
        <article><h3>Warnings</h3><ul>${htmlList(scope.warnings)}</ul></article>
      </div>
    </section>`;
}

function renderFindings(findings) {
  return `<section class="section">
      <h2>Detailed Findings</h2>
      ${(findings || []).map((item, index) => `
        <article class="finding ${severityClass(item.severity)}-border">
          <div class="finding-head"><span class="pill ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span><strong>${escapeHtml(item.area)}</strong></div>
          <h3>${index + 1}. ${escapeHtml(item.title)}</h3>
          <dl>
            <div><dt>Evidence</dt><dd>${escapeHtml(item.evidence)}</dd></div>
            <div><dt>Impact</dt><dd>${escapeHtml(item.impact)}</dd></div>
            <div><dt>Fix</dt><dd>${escapeHtml(item.fix)}</dd></div>
          </dl>
        </article>`).join('') || '<p>No issues detected.</p>'}
    </section>`;
}

function renderEvidence(viewports) {
  return `<section class="section">
      <h2>Measured Evidence</h2>
      <div class="grid">
        ${(viewports || []).map(view => `<article>
          <h3>${escapeHtml(view.viewport)} · ${view.width}x${view.height}</h3>
          <dl>
            <div><dt>Status</dt><dd>${escapeHtml(view.status || '-')}</dd></div>
            <div><dt>Load</dt><dd>${escapeHtml(view.loadMs)}ms</dd></div>
            <div><dt>Console</dt><dd>${escapeHtml(view.consoleMessages?.length || 0)}</dd></div>
            <div><dt>Network Fail</dt><dd>${escapeHtml(view.requestFailures?.length || 0)}</dd></div>
            <div><dt>Overflow</dt><dd>${escapeHtml(view.metrics?.overflow?.length || 0)}</dd></div>
          </dl>
        </article>`).join('')}
      </div>
    </section>`;
}

function buildHtmlReport(report) {
  const counts = report.summary?.counts || {};
  const areaCounts = report.summary?.areas || {};
  const priority = (report.findings || []).filter(item => ['Critical', 'High'].includes(item.severity)).slice(0, 6);
  const areas = Object.entries((report.findings || []).reduce((acc, item) => {
    acc[item.area] = (acc[item.area] || 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]);
  const scope = report.scopePlan || {};
  const profile = report.profile || {};
  const generated = report.generatedAt ? new Date(report.generatedAt).toLocaleString('en-US') : '-';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Site Audit Report ${escapeHtml(report.id)}</title>
  <style>${REPORT_STYLES}
  </style>
</head>
<body>
  <main class="page">
    ${renderHero(report, scope, generated)}
    ${renderSummaryCards(report, counts)}
    ${renderOverview(report, profile, priority, areas)}
    ${renderAreaBalance(areaCounts)}
    ${renderDirectionAndScope(scope, priority)}
    ${renderFindings(report.findings)}
    ${renderEvidence(report.viewports)}
    <p class="footer">Generated by web-audit-kit · JSON/Markdown are kept for agents, this HTML file is for human readers.</p>
  </main>
</body>
</html>`;
}

async function saveReport(report) {
  await fs.mkdir(REPORTS_DIR, { recursive: true });
  const filePath = path.join(REPORTS_DIR, `${report.id}.json`);
  const htmlPath = path.join(REPORTS_DIR, `${report.id}.html`);
  const markdownPath = path.join(REPORTS_DIR, `${report.id}.md`);
  // Set paths on the report before the JSON write so a single saveReport call
  // persists them (no second write needed).
  report.reportPath = filePath;
  report.htmlPath = htmlPath;
  report.markdownPath = markdownPath;
  await fs.writeFile(htmlPath, report.htmlReport || buildHtmlReport(report));
  await fs.writeFile(markdownPath, report.markdown || buildMarkdown(report));
  await fs.writeFile(filePath, JSON.stringify(report, null, 2));
  return { filePath, htmlPath, markdownPath };
}

module.exports = {
  buildMarkdown,
  buildEmailSummary,
  severityClass,
  buildHtmlReport,
  saveReport,
  REPORTS_DIR,
};

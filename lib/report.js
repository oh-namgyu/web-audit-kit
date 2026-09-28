// Report rendering: Markdown and email summary (HTML lives in htmlReport.js),
// plus persistence of the three report artifacts to the local data directory.
const path = require('path');
const fs = require('fs/promises');
const { parseRecipients } = require('./util');
const { severityClass, buildHtmlReport } = require('./htmlReport');

const REPORTS_DIR = path.join(__dirname, '..', 'data', 'reports');

function bulletList(items, empty) {
  return ((items || []).length ? items : (empty ? [empty] : [])).map(item => `- ${item}`);
}

function markdownHeader(report) {
  const profile = report.profile || {};
  return [
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
    `- Ownership: ${profile.labels?.ownership || '-'}`,
    `- Environment: ${profile.labels?.environment || '-'}`,
    `- Permission: ${profile.labels?.permissionLevel || '-'}`,
    `- Test Window: ${profile.testWindow || '-'}`,
    `- Contact: ${profile.contact || '-'}`,
    `- Report Recipients: ${profile.reportRecipients || '-'}`,
    `- Forbidden Areas: ${profile.forbiddenAreas || '-'}`,
    `- Notes: ${profile.notes || '-'}`,
    ``,
  ];
}

function markdownMailAndScope(report) {
  const mail = report.mailDelivery || {};
  return [
    `## Mail Delivery`,
    ``,
    `- Status: ${mail.status || 'pending'}`,
    `- Transport: ${mail.transport || '-'}`,
    `- Recipients: ${(mail.recipients || parseRecipients(report.profile?.reportRecipients)).join(', ') || '-'}`,
    `- Sent At: ${mail.sentAt || '-'}`,
    `- Error: ${mail.error || mail.reason || '-'}`,
    ``,
    `## Scope Plan`,
    ``,
    `### Allowed`,
    ...bulletList(report.scopePlan?.allowed),
    ``,
    `### Blocked`,
    ...bulletList(report.scopePlan?.blocked, 'None'),
    ``,
    `### Manual Required`,
    ...bulletList(report.scopePlan?.manualRequired, 'None'),
    ``,
  ];
}

function markdownResults(report) {
  return [
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
}

function buildMarkdown(report) {
  return [...markdownHeader(report), ...markdownMailAndScope(report), ...markdownResults(report)].join('\n');
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

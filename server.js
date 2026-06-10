const http = require('http');
const path = require('path');
const fs = require('fs/promises');

const { bool, escapeHtml, severityWeight, addFinding, parseRecipients } = require('./lib/util');
const {
  HOST, isLoopbackHost, isPrivateIp, hostnameMatchesAllowlist,
  assertSafeHostBinding, assertTargetAllowed, shouldBlockPrivateIps,
  resolveHostIps, pinnedLookup, normalizeUrl, fetchHeaders,
} = require('./lib/targetGuard');
const {
  normalizeAuditProfile, buildScopePlan, analyzeAuditProfile, analyzeHeaders,
  loadPlaywright, inspectViewport, analyzeViewportResult, summarizeVerdict,
} = require('./lib/analysis');
const { buildMarkdown, buildHtmlReport, saveReport, REPORTS_DIR } = require('./lib/report');
const { sendReportEmail } = require('./lib/mail');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 6197);

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body, null, 2));
}

function text(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(body);
}

async function readBody(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) { const e = new Error('payload too large'); e.statusCode = 413; throw e; }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const e = new Error('invalid JSON body'); e.statusCode = 400; throw e;
  }
}

async function runAudit(input) {
  const targetUrl = await normalizeUrl(input.targetUrl);
  const profile = normalizeAuditProfile(input);
  const scopePlan = buildScopePlan(profile);
  const id = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const findings = [];
  analyzeAuditProfile(profile, scopePlan, findings);
  let headerResult = null;
  try {
    headerResult = await fetchHeaders(targetUrl);
    analyzeHeaders(targetUrl, headerResult, findings);
  } catch (error) {
    headerResult = { ok: false, error: error.message || String(error), headers: {} };
    addFinding(findings, 'Critical', 'Functional QA', 'Initial HTTP request failed', headerResult.error, 'Check the address, port, firewall, certificate, and server run state first.', 'Could not reach the basic screen needed to run the audit.');
  }
  const { chromium } = loadPlaywright();
  const browser = await chromium.launch({ headless: true });
  const viewports = [];
  try {
    for (const viewport of [{ name: 'desktop', width: 1440, height: 1000 }, { name: 'mobile', width: 390, height: 844 }]) {
      const result = await inspectViewport(browser, targetUrl, viewport);
      analyzeViewportResult(result, findings);
      viewports.push(result);
    }
  } finally {
    await browser.close().catch(() => null);
  }
  const report = {
    id,
    targetUrl,
    generatedAt: new Date().toISOString(),
    mode: 'non-invasive passive audit with scope gate',
    profile,
    scopePlan,
    headerResult,
    summary: summarizeVerdict(findings),
    findings,
    viewports,
    markdown: '',
    htmlReport: '',
  };
  // Send mail first, then build markdown/html once so they reflect the delivery result.
  report.mailDelivery = await sendReportEmail(report);
  report.markdown = buildMarkdown(report);
  report.htmlReport = buildHtmlReport(report);
  await saveReport(report);
  return report;
}

async function listReports() {
  try {
    const files = (await fs.readdir(REPORTS_DIR)).filter(name => name.endsWith('.json')).sort().reverse();
    const rows = [];
    for (const name of files.slice(0, 50)) {
      const report = JSON.parse(await fs.readFile(path.join(REPORTS_DIR, name), 'utf8'));
      rows.push({
        id: report.id,
        targetUrl: report.targetUrl,
        generatedAt: report.generatedAt,
        summary: report.summary,
        mailDelivery: report.mailDelivery,
      });
    }
    return rows;
  } catch {
    return [];
  }
}

async function readReport(id) {
  const safeId = String(id || '').replace(/[^0-9]/g, '');
  if (!safeId) return null;
  try {
    return JSON.parse(await fs.readFile(path.join(REPORTS_DIR, `${safeId}.json`), 'utf8'));
  } catch {
    return null;
  }
}

async function resendReport(id) {
  const report = await readReport(id);
  if (!report) return null;
  report.mailDelivery = await sendReportEmail(report);
  report.markdown = buildMarkdown(report);
  report.htmlReport = buildHtmlReport(report);
  await saveReport(report);
  return report;
}

async function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const full = path.resolve(PUBLIC_DIR, `.${pathname}`);
  if (full !== PUBLIC_DIR && !full.startsWith(`${PUBLIC_DIR}${path.sep}`)) return text(res, 403, 'forbidden');
  try {
    const body = await fs.readFile(full);
    const ext = path.extname(full).toLowerCase();
    const type = ext === '.html' ? 'text/html; charset=utf-8'
      : ext === '.css' ? 'text/css; charset=utf-8'
      : ext === '.js' ? 'application/javascript; charset=utf-8'
      : 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(body);
  } catch {
    text(res, 404, 'not found');
  }
}

function exportReport(res, report, format) {
  if (format === 'html') {
    const body = report.htmlReport || buildHtmlReport(report);
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Disposition': `attachment; filename="site-audit-${report.id}.html"`,
      'Cache-Control': 'no-store',
    });
    return res.end(body);
  }
  if (format === 'json') {
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="site-audit-${report.id}.json"`,
      'Cache-Control': 'no-store',
    });
    return res.end(JSON.stringify(report, null, 2));
  }
  res.writeHead(200, {
    'Content-Type': 'text/markdown; charset=utf-8',
    'Content-Disposition': `attachment; filename="site-audit-${report.id}.md"`,
    'Cache-Control': 'no-store',
  });
  return res.end(report.markdown || buildMarkdown(report));
}

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === 'GET' && url.pathname === '/api/health') {
      return json(res, 200, { ok: true, name: 'web-audit-kit', port: PORT, host: HOST, storage: 'local git-ignored data directory' });
    }
    if (req.method === 'GET' && url.pathname === '/api/reports') {
      return json(res, 200, { ok: true, items: await listReports() });
    }
    if (req.method === 'GET' && url.pathname === '/api/report') {
      const report = await readReport(url.searchParams.get('id'));
      if (!report) return json(res, 404, { ok: false, error: 'report not found' });
      return json(res, 200, { ok: true, report });
    }
    if (req.method === 'GET' && url.pathname === '/api/export') {
      const report = await readReport(url.searchParams.get('id'));
      if (!report) return text(res, 404, 'report not found');
      const format = String(url.searchParams.get('format') || 'markdown').toLowerCase();
      return exportReport(res, report, format);
    }
    if (req.method === 'POST' && url.pathname === '/api/audit') {
      const body = await readBody(req);
      const report = await runAudit(body);
      return json(res, 200, { ok: true, report });
    }
    if (req.method === 'POST' && url.pathname === '/api/resend') {
      const body = await readBody(req);
      const report = await resendReport(body.id);
      if (!report) return json(res, 404, { ok: false, error: 'report not found' });
      return json(res, 200, { ok: true, report });
    }
    return serveStatic(req, res);
  } catch (error) {
    return json(res, error.statusCode || 500, { ok: false, error: error.message || String(error) });
  }
}

assertSafeHostBinding();

if (require.main === module) {            // skip server boot on import (tests) so pure helpers can be unit-tested
  http.createServer(route).listen(PORT, HOST, () => {
    console.log(`web-audit-kit running at http://${HOST}:${PORT}`);
  });
}

module.exports = {                        // unit-test exports (pure helpers + SSRF guard)
  isPrivateIp, isLoopbackHost, hostnameMatchesAllowlist,
  escapeHtml, parseRecipients, severityWeight,
  assertTargetAllowed, shouldBlockPrivateIps,
  resolveHostIps, pinnedLookup, bool,
};

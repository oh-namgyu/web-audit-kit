const $ = (sel) => document.querySelector(sel);
let currentReport = null;

// Canonical audit area order — kept in sync with server.js (AUDIT_AREAS).
const AUDIT_AREAS = ['Security', 'Design UX', 'Functional QA', 'Architecture', 'Audit Scope'];

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    method: options.method || 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function setBusy(busy, message) {
  $('#runBtn').disabled = busy;
  $('#sampleBtn').disabled = busy;
  $('#refreshBtn').disabled = busy;
  $('#status').textContent = message;
}

function sevClass(severity) {
  return String(severity || '').toLowerCase();
}

function setActiveTab(name) {
  document.querySelectorAll('[data-tab-target]').forEach(button => {
    button.classList.toggle('active', button.dataset.tabTarget === name);
  });
  document.querySelectorAll('[data-tab]').forEach(section => {
    section.classList.toggle('active', section.dataset.tab === name);
  });
}

function getAuditProfile() {
  return {
    ownership: $('#ownership').value,
    environment: $('#environment').value,
    permissionLevel: $('#permissionLevel').value,
    hasExplicitApproval: $('#hasExplicitApproval').checked,
    hasTestAccount: $('#hasTestAccount').checked,
    hasAdminAccount: $('#hasAdminAccount').checked,
    hasRollback: $('#hasRollback').checked,
    allowCreate: $('#allowCreate').checked,
    allowModify: $('#allowModify').checked,
    allowDelete: $('#allowDelete').checked,
    allowFileUpload: $('#allowFileUpload').checked,
    allowAuthzProbe: $('#allowAuthzProbe').checked,
    allowLoadTest: $('#allowLoadTest').checked,
    testWindow: $('#testWindow').value.trim(),
    contact: $('#contact').value.trim(),
    reportRecipients: $('#reportRecipients').value.trim(),
    forbiddenAreas: $('#forbiddenAreas').value.trim(),
    rollbackPlan: $('#rollbackPlan').value.trim(),
    notes: $('#notes').value.trim(),
  };
}

function renderList(title, items, cls) {
  const rows = items && items.length ? items : ['None'];
  return `<article class="scope-card ${cls}">
    <h3>${esc(title)}</h3>
    <ul>${rows.map(item => `<li>${esc(item)}</li>`).join('')}</ul>
  </article>`;
}

function renderAreaBalance(areas = {}) {
  return AUDIT_AREAS.map(name => {
    const row = areas[name] || {};
    return `<article class="area-row">
      <b>${esc(name)}</b>
      <span>${esc(row.total || 0)}</span>
      <small>C ${esc(row.Critical || 0)} · H ${esc(row.High || 0)} · M ${esc(row.Medium || 0)} · L ${esc(row.Low || 0)}</small>
    </article>`;
  }).join('');
}

function renderReport(report) {
  currentReport = report;
  const counts = report.summary?.counts || {};
  $('#score').textContent = report.summary?.score ?? '-';
  $('#verdict').textContent = report.summary?.verdict || '-';
  $('#criticalCount').textContent = counts.Critical || 0;
  $('#highCount').textContent = counts.High || 0;
  $('#mediumCount').textContent = counts.Medium || 0;
  $('#lowCount').textContent = counts.Low || 0;
  $('#viewportCount').textContent = report.viewports?.length || 0;
  $('#findingCount').textContent = `${report.findings?.length || 0}`;
  $('#exportBtn').disabled = false;
  $('#exportHtmlBtn').disabled = false;
  $('#areaBalance').classList.remove('empty');
  $('#areaBalance').innerHTML = renderAreaBalance(report.summary?.areas || {});
  $('#scopeLabel').textContent = report.scopePlan?.label || 'Scope not set';
  $('#scopePlan').classList.toggle('empty', !report.scopePlan);
  $('#scopePlan').innerHTML = report.scopePlan ? `
    <article class="scope-card profile">
      <h3>Selected basis</h3>
      <dl>
        <div><dt>Ownership/approval</dt><dd>${esc(report.profile?.labels?.ownership || '-')}</dd></div>
        <div><dt>Stage</dt><dd>${esc(report.profile?.labels?.environment || '-')}</dd></div>
        <div><dt>Permission level</dt><dd>${esc(report.profile?.labels?.permissionLevel || '-')}</dd></div>
        <div><dt>Recipients</dt><dd>${esc(report.profile?.reportRecipients || '-')}</dd></div>
      </dl>
    </article>
    ${renderList('Allowed to run', report.scopePlan.allowed, 'allowed')}
    ${renderList('Blocked this run', report.scopePlan.blocked, 'blocked')}
    ${renderList('Manual confirmation needed', report.scopePlan.manualRequired, 'manual')}
    ${renderList('Warnings', report.scopePlan.warnings, 'warning')}
  ` : 'Run an audit to see the allowed / blocked / manual-confirmation scope based on the selected permission and stage.';

  const priority = (report.findings || []).filter(item => ['Critical', 'High'].includes(item.severity));
  $('#priority').classList.toggle('empty', !priority.length);
  $('#priority').innerHTML = priority.length
    ? priority.slice(0, 8).map(item => `<article class="priority-item ${sevClass(item.severity)}">
        <b>${esc(item.severity)}</b>
        <span>${esc(item.title)}</span>
      </article>`).join('')
    : 'No Critical/High items. Start by clearing the Medium items.';

  $('#findings').innerHTML = (report.findings || []).map(item => `
    <article class="finding ${sevClass(item.severity)}">
      <div class="finding-head">
        <span>${esc(item.severity)}</span>
        <b>${esc(item.area)}</b>
      </div>
      <h3>${esc(item.title)}</h3>
      <dl>
        <div><dt>Evidence</dt><dd>${esc(item.evidence)}</dd></div>
        <div><dt>Impact</dt><dd>${esc(item.impact)}</dd></div>
        <div><dt>Fix</dt><dd>${esc(item.fix)}</dd></div>
      </dl>
    </article>
  `).join('') || '<p class="empty">No issues detected.</p>';

  $('#evidence').innerHTML = `
    <article>
      <h3>Target</h3>
      <dl>
        <div><dt>URL</dt><dd>${esc(report.targetUrl)}</dd></div>
        <div><dt>Mode</dt><dd>${esc(report.mode)}</dd></div>
        <div><dt>Scope</dt><dd>${esc(report.scopePlan?.label || '-')}</dd></div>
        <div><dt>Report recipients</dt><dd>${esc(report.profile?.reportRecipients || '-')}</dd></div>
        <div><dt>Mail delivery</dt><dd>${esc(report.mailDelivery?.status || '-')}</dd></div>
        <div><dt>Mail detail</dt><dd>${esc(report.mailDelivery?.sentAt || report.mailDelivery?.error || report.mailDelivery?.reason || '-')}</dd></div>
        <div><dt>Generated</dt><dd>${esc(new Date(report.generatedAt).toLocaleString())}</dd></div>
        <div><dt>HTTP</dt><dd>${esc(report.headerResult?.status || report.headerResult?.error || '-')}</dd></div>
      </dl>
    </article>
    ${(report.viewports || []).map(view => `<article>
      <h3>${esc(view.viewport)} · ${view.width}x${view.height}</h3>
      <dl>
        <div><dt>Status</dt><dd>${esc(view.status || '-')}</dd></div>
        <div><dt>Load</dt><dd>${esc(view.loadMs)}ms</dd></div>
        <div><dt>Console</dt><dd>${esc(view.consoleMessages?.length || 0)}</dd></div>
        <div><dt>Network Fail</dt><dd>${esc(view.requestFailures?.length || 0)}</dd></div>
        <div><dt>Buttons</dt><dd>${esc(view.metrics?.counts?.buttons || 0)}</dd></div>
        <div><dt>Inputs</dt><dd>${esc(view.metrics?.counts?.inputs || 0)}</dd></div>
        <div><dt>DOM Nodes</dt><dd>${esc(view.metrics?.counts?.nodes || 0)}</dd></div>
        <div><dt>Overflow</dt><dd>${esc(view.metrics?.overflow?.length || 0)}</dd></div>
      </dl>
      <p>${esc(view.metrics?.textSample || '')}</p>
    </article>`).join('')}
  `;
}

async function runAudit(targetUrl) {
  setBusy(true, 'Auditing the site... opening real desktop/mobile browsers to check.');
  try {
    const data = await api('/api/audit', { method: 'POST', body: { targetUrl, profile: getAuditProfile() } });
    renderReport(data.report);
    await loadHistory();
    const mail = data.report.mailDelivery?.status ? ` · mail ${data.report.mailDelivery.status}` : '';
    setBusy(false, `Done: ${data.report.summary.verdict}${mail}`);
    setActiveTab('dashboard');
  } catch (error) {
    setBusy(false, `Failed: ${error.message}`);
  }
}

async function loadHistory() {
  const data = await api('/api/reports');
  const items = data.items || [];
  const latest = items[0];
  const previous = items[1];
  const trend = latest && previous
    ? `<article class="history-trend">
        <b>Recent change</b>
        <span>Score ${esc(previous.summary?.score ?? '-')} → ${esc(latest.summary?.score ?? '-')}</span>
        <small>${esc(previous.summary?.verdict || '-')} → ${esc(latest.summary?.verdict || '-')}</small>
      </article>`
    : '';
  $('#history').innerHTML = trend + (items || []).map(item => `
    <article class="history-row" data-id="${esc(item.id)}">
      <button type="button" class="history-open" data-action="open" data-id="${esc(item.id)}">
        <b>${esc(item.summary?.verdict || '-')}</b>
        <span>${esc(item.targetUrl)}</span>
        <small>${esc(new Date(item.generatedAt).toLocaleString())} · mail ${esc(item.mailDelivery?.status || '-')}</small>
      </button>
      <div class="history-actions">
        <button type="button" class="small ghost" data-action="html" data-id="${esc(item.id)}">Open HTML</button>
        <button type="button" class="small ghost" data-action="md" data-id="${esc(item.id)}">Markdown</button>
        <button type="button" class="small ghost" data-action="json" data-id="${esc(item.id)}">JSON</button>
        <button type="button" class="small ghost" data-action="resend" data-id="${esc(item.id)}">Resend mail</button>
      </div>
    </article>
  `).join('') || '<p class="empty">No saved reports.</p>';
  document.querySelectorAll('[data-action]').forEach(button => {
    button.addEventListener('click', async event => {
      event.stopPropagation();
      const id = button.dataset.id;
      const action = button.dataset.action;
      if (action === 'html') {
        window.open(`/api/export?id=${encodeURIComponent(id)}&format=html`, '_blank', 'noopener,noreferrer');
        return;
      }
      if (action === 'md') {
        window.location.href = `/api/export?id=${encodeURIComponent(id)}`;
        return;
      }
      if (action === 'json') {
        window.location.href = `/api/export?id=${encodeURIComponent(id)}&format=json`;
        return;
      }
      if (action === 'resend') {
        setBusy(true, 'Resending mail...');
        try {
          const data = await api('/api/resend', { method: 'POST', body: { id } });
          renderReport(data.report);
          await loadHistory();
          setBusy(false, `Resent: mail ${data.report.mailDelivery?.status || '-'}`);
          setActiveTab('reporting');
        } catch (error) {
          setBusy(false, `Resend failed: ${error.message}`);
        }
        return;
      }
      const data = await api(`/api/report?id=${encodeURIComponent(id)}`);
      renderReport(data.report);
      setActiveTab('reporting');
    });
  });
}

$('#auditForm').addEventListener('submit', event => {
  event.preventDefault();
  runAudit($('#targetUrl').value.trim());
});

$('#sampleBtn').addEventListener('click', () => {
  $('#targetUrl').value = 'https://example.com';
  $('#ownership').value = 'owner';
  $('#environment').value = 'internal-test';
  $('#permissionLevel').value = 'surface-only';
  runAudit($('#targetUrl').value);
});

$('#refreshBtn').addEventListener('click', loadHistory);

document.querySelectorAll('[data-tab-target]').forEach(button => {
  button.addEventListener('click', () => setActiveTab(button.dataset.tabTarget));
});

$('#exportBtn').addEventListener('click', () => {
  if (!currentReport) return;
  window.location.href = `/api/export?id=${encodeURIComponent(currentReport.id)}`;
});

$('#exportHtmlBtn').addEventListener('click', () => {
  if (!currentReport) return;
  window.location.href = `/api/export?id=${encodeURIComponent(currentReport.id)}&format=html`;
});

loadHistory().catch(error => {
  $('#history').innerHTML = `<p class="empty">Failed to load report list: ${esc(error.message)}</p>`;
});

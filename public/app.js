const $ = (sel) => document.querySelector(sel);
let currentReport = null;

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
  const rows = items && items.length ? items : ['없음'];
  return `<article class="scope-card ${cls}">
    <h3>${esc(title)}</h3>
    <ul>${rows.map(item => `<li>${esc(item)}</li>`).join('')}</ul>
  </article>`;
}

function renderAreaBalance(areas = {}) {
  const areaNames = ['Security', 'Design UX', 'Functional QA', 'Architecture', 'Audit Scope'];
  return areaNames.map(name => {
    const row = areas[name] || {};
    return `<article class="area-row">
      <b>${esc(name)}</b>
      <span>${esc(row.total || 0)}건</span>
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
  $('#findingCount').textContent = `${report.findings?.length || 0}건`;
  $('#exportBtn').disabled = false;
  $('#exportHtmlBtn').disabled = false;
  $('#areaBalance').classList.remove('empty');
  $('#areaBalance').innerHTML = renderAreaBalance(report.summary?.areas || {});
  $('#scopeLabel').textContent = report.scopePlan?.label || '범위 미설정';
  $('#scopePlan').classList.toggle('empty', !report.scopePlan);
  $('#scopePlan').innerHTML = report.scopePlan ? `
    <article class="scope-card profile">
      <h3>선택된 기준</h3>
      <dl>
        <div><dt>소유/승인</dt><dd>${esc(report.profile?.labels?.ownership || '-')}</dd></div>
        <div><dt>단계</dt><dd>${esc(report.profile?.labels?.environment || '-')}</dd></div>
        <div><dt>허용 수준</dt><dd>${esc(report.profile?.labels?.permissionLevel || '-')}</dd></div>
        <div><dt>수신자</dt><dd>${esc(report.profile?.reportRecipients || '-')}</dd></div>
      </dl>
    </article>
    ${renderList('실행 허용', report.scopePlan.allowed, 'allowed')}
    ${renderList('이번 검사에서 차단', report.scopePlan.blocked, 'blocked')}
    ${renderList('수동 확인 필요', report.scopePlan.manualRequired, 'manual')}
    ${renderList('주의', report.scopePlan.warnings, 'warning')}
  ` : '감사를 실행하면 선택한 권한/단계 기준으로 허용·차단·수동확인 범위가 표시됩니다.';

  const priority = (report.findings || []).filter(item => ['Critical', 'High'].includes(item.severity));
  $('#priority').classList.toggle('empty', !priority.length);
  $('#priority').innerHTML = priority.length
    ? priority.slice(0, 8).map(item => `<article class="priority-item ${sevClass(item.severity)}">
        <b>${esc(item.severity)}</b>
        <span>${esc(item.title)}</span>
      </article>`).join('')
    : 'Critical/High 항목은 없습니다. Medium 항목부터 정리하면 됩니다.';

  $('#findings').innerHTML = (report.findings || []).map(item => `
    <article class="finding ${sevClass(item.severity)}">
      <div class="finding-head">
        <span>${esc(item.severity)}</span>
        <b>${esc(item.area)}</b>
      </div>
      <h3>${esc(item.title)}</h3>
      <dl>
        <div><dt>증거</dt><dd>${esc(item.evidence)}</dd></div>
        <div><dt>영향</dt><dd>${esc(item.impact)}</dd></div>
        <div><dt>수정</dt><dd>${esc(item.fix)}</dd></div>
      </dl>
    </article>
  `).join('') || '<p class="empty">감지된 문제가 없습니다.</p>';

  $('#evidence').innerHTML = `
    <article>
      <h3>대상</h3>
      <dl>
        <div><dt>URL</dt><dd>${esc(report.targetUrl)}</dd></div>
        <div><dt>모드</dt><dd>${esc(report.mode)}</dd></div>
        <div><dt>범위</dt><dd>${esc(report.scopePlan?.label || '-')}</dd></div>
        <div><dt>리포트 수신자</dt><dd>${esc(report.profile?.reportRecipients || '-')}</dd></div>
        <div><dt>메일 발송</dt><dd>${esc(report.mailDelivery?.status || '-')}</dd></div>
        <div><dt>메일 상세</dt><dd>${esc(report.mailDelivery?.sentAt || report.mailDelivery?.error || report.mailDelivery?.reason || '-')}</dd></div>
        <div><dt>생성</dt><dd>${esc(new Date(report.generatedAt).toLocaleString())}</dd></div>
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
  setBusy(true, '사이트 감사 중... desktop/mobile 브라우저를 실제로 열어 확인합니다.');
  try {
    const data = await api('/api/audit', { method: 'POST', body: { targetUrl, profile: getAuditProfile() } });
    renderReport(data.report);
    await loadHistory();
    const mail = data.report.mailDelivery?.status ? ` · 메일 ${data.report.mailDelivery.status}` : '';
    setBusy(false, `완료: ${data.report.summary.verdict}${mail}`);
    setActiveTab('dashboard');
  } catch (error) {
    setBusy(false, `실패: ${error.message}`);
  }
}

async function loadHistory() {
  const data = await api('/api/reports');
  const items = data.items || [];
  const latest = items[0];
  const previous = items[1];
  const trend = latest && previous
    ? `<article class="history-trend">
        <b>최근 변화</b>
        <span>점수 ${esc(previous.summary?.score ?? '-')} → ${esc(latest.summary?.score ?? '-')}</span>
        <small>${esc(previous.summary?.verdict || '-')} → ${esc(latest.summary?.verdict || '-')}</small>
      </article>`
    : '';
  $('#history').innerHTML = trend + (items || []).map(item => `
    <article class="history-row" data-id="${esc(item.id)}">
      <button type="button" class="history-open" data-action="open" data-id="${esc(item.id)}">
        <b>${esc(item.summary?.verdict || '-')}</b>
        <span>${esc(item.targetUrl)}</span>
        <small>${esc(new Date(item.generatedAt).toLocaleString())} · 메일 ${esc(item.mailDelivery?.status || '-')}</small>
      </button>
      <div class="history-actions">
        <button type="button" class="small ghost" data-action="html" data-id="${esc(item.id)}">HTML 열기</button>
        <button type="button" class="small ghost" data-action="md" data-id="${esc(item.id)}">Markdown</button>
        <button type="button" class="small ghost" data-action="json" data-id="${esc(item.id)}">JSON</button>
        <button type="button" class="small ghost" data-action="resend" data-id="${esc(item.id)}">메일 재전송</button>
      </div>
    </article>
  `).join('') || '<p class="empty">저장된 리포트가 없습니다.</p>';
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
        setBusy(true, '메일 재전송 중...');
        try {
          const data = await api('/api/resend', { method: 'POST', body: { id } });
          renderReport(data.report);
          await loadHistory();
          setBusy(false, `재전송 완료: 메일 ${data.report.mailDelivery?.status || '-'}`);
          setActiveTab('reporting');
        } catch (error) {
          setBusy(false, `재전송 실패: ${error.message}`);
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
  $('#history').innerHTML = `<p class="empty">리포트 목록 로딩 실패: ${esc(error.message)}</p>`;
});

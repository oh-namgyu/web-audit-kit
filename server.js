const http = require('http');
const https = require('https');
const fs = require('fs/promises');
const path = require('path');
const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;
const { spawn } = require('child_process');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const REPORTS_DIR = path.join(DATA_DIR, 'reports');
const SCREENSHOTS_DIR = path.join(DATA_DIR, 'screenshots');
const PORT = Number(process.env.PORT || 6197);
const HOST = process.env.HOST || '127.0.0.1';
const PLAYWRIGHT_MODULE_PATH = process.env.TESTGPT7_PLAYWRIGHT_PATH || '';
const SENDMAIL_PATH = process.env.TESTGPT7_SENDMAIL_PATH || '/usr/sbin/sendmail';
const TARGET_ALLOWLIST = String(process.env.TESTGPT7_TARGET_ALLOWLIST || '')
  .split(',')
  .map(item => item.trim().toLowerCase())
  .filter(Boolean);
const MAX_REDIRECTS = Number(process.env.TESTGPT7_MAX_REDIRECTS || 5);

// Canonical audit area order — single source of truth for report rendering.
// Mirrored in public/app.js (AUDIT_AREAS) for the client-side balance view.
const AUDIT_AREAS = ['Security', 'Design UX', 'Functional QA', 'Architecture', 'Audit Scope'];

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

async function normalizeUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) throw new Error('targetUrl is required');
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  const parsed = new URL(withScheme);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http/https URLs are supported');
  await assertTargetAllowed(parsed);
  parsed.hash = '';
  return parsed.toString();
}

function loadPlaywright() {
  try {
    return require('playwright');
  } catch (error) {
    if (PLAYWRIGHT_MODULE_PATH) return require(PLAYWRIGHT_MODULE_PATH);
    const wrapped = new Error('Playwright is required. Run "npm install" or set TESTGPT7_PLAYWRIGHT_PATH to a local Playwright module path.');
    wrapped.cause = error;
    throw wrapped;
  }
}

function isLoopbackHost(host) {
  return ['127.0.0.1', 'localhost', '::1'].includes(String(host || '').toLowerCase());
}

function assertSafeHostBinding() {
  if (isLoopbackHost(HOST)) return;
  if (bool(process.env.TESTGPT7_ALLOW_NETWORK_EXPOSURE)) return;
  throw new Error(`Refusing to bind to ${HOST}. testGpt7 is local-only by default. Set TESTGPT7_ALLOW_NETWORK_EXPOSURE=true only on a trusted network with your own access controls.`);
}

function hostnameMatchesAllowlist(hostname, rule) {
  const host = hostname.toLowerCase();
  if (rule === host) return true;
  if (rule.startsWith('*.')) return host.endsWith(rule.slice(1));
  return false;
}

function assertTargetHostAllowed(parsedUrl) {
  if (isLoopbackHost(HOST)) return;
  if (TARGET_ALLOWLIST.some(rule => hostnameMatchesAllowlist(parsedUrl.hostname, rule))) return;
  if (bool(process.env.TESTGPT7_ALLOW_ANY_TARGET)) return;
  throw new Error('Network-exposed mode requires TESTGPT7_TARGET_ALLOWLIST. Set TESTGPT7_ALLOW_ANY_TARGET=true only for a trusted, access-controlled deployment.');
}

function shouldBlockPrivateIps() {
  if (!isLoopbackHost(HOST)) return !bool(process.env.TESTGPT7_ALLOW_PRIVATE_TARGETS);
  return bool(process.env.TESTGPT7_BLOCK_PRIVATE_IPS);
}

function isPrivateIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    return a === 0
      || a === 10
      || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0)
      || (a === 198 && (b === 18 || b === 19))
      || a >= 224;
  }
  if (version === 6) {
    const normalized = ip.toLowerCase();
    if (normalized.startsWith('::ffff:')) return isPrivateIp(normalized.slice(7));
    return normalized === '::'
      || normalized === '::1'
      || normalized.startsWith('fc')
      || normalized.startsWith('fd')
      || /^fe[89ab][0-9a-f]:/.test(normalized) // link-local fe80::/10 (fe80–febf)
      || normalized.startsWith('fec0:');
  }
  return false;
}

async function resolveHostIps(hostname) {
  if (net.isIP(hostname)) return [hostname];
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return [...new Set(records.map(record => record.address))];
}

// Returns { ips, pinnedIp } when DNS was resolved and validated, else null.
// Callers pin their connection lookup to pinnedIp so the IP that passed the
// guard is exactly the IP the socket connects to (closes the TOCTOU / DNS
// rebinding gap where fetch/undici would re-resolve independently).
async function assertTargetAllowed(parsedUrl) {
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error('Only http/https URLs are supported');
  assertTargetHostAllowed(parsedUrl);
  if (!shouldBlockPrivateIps()) return null;
  const ips = await resolveHostIps(parsedUrl.hostname);
  const blocked = ips.filter(isPrivateIp);
  if (blocked.length) {
    throw new Error(`Target resolves to blocked private/reserved IP: ${parsedUrl.hostname} -> ${blocked.join(', ')}`);
  }
  if (!ips.length) {
    throw new Error(`Target did not resolve to any address: ${parsedUrl.hostname}`);
  }
  return { ips, pinnedIp: ips[0] };
}

// Builds a dns.lookup-shaped callback that always returns the already-validated
// pinnedIp, so http/https never re-resolves the hostname at connect time.
function pinnedLookup(pinnedIp) {
  const family = net.isIP(pinnedIp);
  return (hostname, options, callback) => {
    const cb = typeof options === 'function' ? options : callback;
    const opts = typeof options === 'function' ? {} : (options || {});
    if (opts.all) return cb(null, [{ address: pinnedIp, family }]);
    return cb(null, pinnedIp, family);
  };
}

function severityWeight(severity) {
  return { Critical: 30, High: 18, Medium: 8, Low: 3 }[severity] || 1;
}

function addFinding(findings, severity, area, title, evidence, fix, impact) {
  findings.push({ id: `${area}-${findings.length + 1}`, severity, area, title, evidence, impact, fix });
}

function encodeHeader(value) {
  const raw = String(value || '').replace(/[\r\n]/g, ' ').trim();
  return /^[\x00-\x7F]*$/.test(raw) ? raw : `=?UTF-8?B?${Buffer.from(raw, 'utf8').toString('base64')}?=`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function parseRecipients(value) {
  return String(value || '')
    .split(/[,\n;]/)
    .map(item => item.trim())
    .filter(Boolean)
    .filter(item => /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(item))
    .slice(0, 20);
}

function getMailConfig() {
  const transport = String(process.env.TESTGPT7_MAIL_TRANSPORT || 'disabled').trim().toLowerCase();
  return {
    transport,
    from: process.env.TESTGPT7_MAIL_FROM || process.env.SMTP_FROM || 'testgpt7-audit@localhost',
    sendmailPath: SENDMAIL_PATH,
    smtp: {
      host: process.env.TESTGPT7_SMTP_HOST || process.env.SMTP_HOST || '',
      port: Number(process.env.TESTGPT7_SMTP_PORT || process.env.SMTP_PORT || 587),
      secure: bool(process.env.TESTGPT7_SMTP_SECURE || process.env.SMTP_SECURE),
      user: process.env.TESTGPT7_SMTP_USER || process.env.SMTP_USER || '',
      pass: process.env.TESTGPT7_SMTP_PASS || process.env.SMTP_PASS || '',
    },
  };
}

function foldBase64(value) {
  return Buffer.from(value, 'utf8').toString('base64').replace(/.{1,76}/g, '$&\r\n').trim();
}

function buildEmailMessage({ from, to, subject, body, attachments = [] }) {
  const safeFrom = String(from || '').replace(/[\r\n]/g, '').trim();
  const recipients = to.map(item => String(item).replace(/[\r\n]/g, '').trim()).join(', ');
  if (attachments.length) {
    const boundary = `testgpt7-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return [
      `From: ${safeFrom}`,
      `To: ${recipients}`,
      `Subject: ${encodeHeader(subject)}`,
      `Date: ${new Date().toUTCString()}`,
      `MIME-Version: 1.0`,
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      ``,
      `--${boundary}`,
      `Content-Type: text/markdown; charset=UTF-8`,
      `Content-Transfer-Encoding: 8bit`,
      ``,
      body,
      ``,
      ...attachments.flatMap(attachment => [
        `--${boundary}`,
        `Content-Type: ${attachment.contentType}; name="${attachment.filename}"`,
        `Content-Disposition: attachment; filename="${attachment.filename}"`,
        `Content-Transfer-Encoding: base64`,
        ``,
        foldBase64(attachment.content),
        ``,
      ]),
      `--${boundary}--`,
      ``,
    ].join('\r\n');
  }
  return [
    `From: ${safeFrom}`,
    `To: ${recipients}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/markdown; charset=UTF-8`,
    `Content-Transfer-Encoding: 8bit`,
    ``,
    body,
  ].join('\r\n');
}

function sendWithSendmail(config, recipients, message) {
  return new Promise((resolve, reject) => {
    const child = spawn(config.sendmailPath, ['-t', '-i'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
    child.on('error', reject);
    child.on('close', code => {
      if (code === 0) resolve({ transport: 'sendmail', recipients, accepted: recipients.length });
      else reject(new Error(stderr.trim() || `sendmail exited with ${code}`));
    });
    child.stdin.end(message);
  });
}

function createSmtpClient(config) {
  let socket = config.smtp.secure
    ? tls.connect(config.smtp.port, config.smtp.host, { servername: config.smtp.host, rejectUnauthorized: true })
    : net.connect(config.smtp.port, config.smtp.host);
  socket.setTimeout(20000);
  let buffer = '';
  function readResponse() {
    return new Promise((resolve, reject) => {
      const onData = chunk => {
        buffer += chunk.toString('utf8');
        const lines = buffer.split(/\r?\n/).filter(Boolean);
        const last = lines[lines.length - 1] || '';
        if (/^\d{3} /.test(last)) {
          socket.off('data', onData);
          socket.off('error', onError);
          socket.off('timeout', onTimeout);
          const response = buffer;
          buffer = '';
          resolve(response);
        }
      };
      const onError = error => {
        socket.off('data', onData);
        socket.off('timeout', onTimeout);
        reject(error);
      };
      const onTimeout = () => {
        socket.off('data', onData);
        socket.off('error', onError);
        socket.destroy(); // free the dangling socket on timeout instead of leaking it half-open
        reject(new Error('SMTP timeout'));
      };
      socket.on('data', onData);
      socket.once('error', onError);
      socket.once('timeout', onTimeout);
    });
  }
  async function command(line, ok = /^[23]/) {
    socket.write(`${line}\r\n`);
    const response = await readResponse();
    if (!ok.test(response)) throw new Error(response.trim());
    return response;
  }
  async function startTls() {
    await command('STARTTLS');
    await new Promise((resolve, reject) => {
      const secure = tls.connect({ socket, servername: config.smtp.host, rejectUnauthorized: true }, () => {
        socket = secure;
        socket.setTimeout(20000);
        resolve();
      });
      secure.once('error', reject);
    });
  }
  function write(value) {
    socket.write(value);
  }
  function end() {
    socket.end();
  }
  function destroy() {
    socket.destroy();
  }
  return { readResponse, command, startTls, write, end, destroy };
}

async function sendWithSmtp(config, recipients, message) {
  if (!config.smtp.host) throw new Error('SMTP host is not configured');
  const client = createSmtpClient(config);
  let graceful = false;
  try {
    await client.readResponse();
    await client.command(`EHLO ${HOST}`);
    if (!config.smtp.secure && [587, 25].includes(config.smtp.port)) {
      await client.startTls();
      await client.command(`EHLO ${HOST}`);
    }
    if (config.smtp.user || config.smtp.pass) {
      const token = Buffer.from(`\0${config.smtp.user}\0${config.smtp.pass}`, 'utf8').toString('base64');
      await client.command(`AUTH PLAIN ${token}`);
    }
    await client.command(`MAIL FROM:<${config.from}>`);
    for (const recipient of recipients) await client.command(`RCPT TO:<${recipient}>`);
    await client.command('DATA', /^354/);
    const safeMessage = message.replace(/^\./gm, '..');
    client.write(`${safeMessage}\r\n.\r\n`);
    const dataResponse = await client.readResponse();
    if (!/^[23]/.test(dataResponse)) throw new Error(dataResponse.trim());
    await client.command('QUIT').catch(() => null);
    graceful = true;
    return { transport: 'smtp', recipients, accepted: recipients.length };
  } finally {
    // Always release the socket: graceful end on success, hard destroy on any failure.
    if (graceful) client.end();
    else client.destroy();
  }
}

async function sendReportEmail(report) {
  const recipients = parseRecipients(report.profile?.reportRecipients);
  if (!recipients.length) return { status: 'skipped', reason: 'report recipients are empty', recipients: [] };
  const config = getMailConfig();
  if (config.transport === 'disabled' || config.transport === 'off') {
    return { status: 'skipped', reason: 'mail transport disabled', recipients };
  }
  const subject = `[testGpt7] ${report.summary.verdict} - ${report.targetUrl}`;
  const body = buildEmailSummary(report);
  const message = buildEmailMessage({
    from: config.from,
    to: recipients,
    subject,
    body,
    attachments: [{
      filename: `site-audit-${report.id}.html`,
      contentType: 'text/html; charset=UTF-8',
      content: report.htmlReport || buildHtmlReport(report),
    }, {
      filename: `site-audit-${report.id}.md`,
      contentType: 'text/markdown; charset=UTF-8',
      content: report.markdown || buildMarkdown(report),
    }],
  });
  try {
    const result = config.transport === 'smtp'
      ? await sendWithSmtp(config, recipients, message)
      : await sendWithSendmail(config, recipients, message);
    return { status: 'sent', ...result, sentAt: new Date().toISOString() };
  } catch (error) {
    return { status: 'failed', transport: config.transport, recipients, error: error.message || String(error) };
  }
}

const OWNERSHIP_OPTIONS = {
  owner: '내가 오너',
  'other-team-authorized': '다른 팀 시스템 - 승인 있음',
  'external-or-unknown': '오너/승인 불명확',
};

const ENVIRONMENT_OPTIONS = {
  'local-dev': '로컬 개발',
  'internal-test': '내부 테스트',
  staging: '스테이징',
  'production-readiness': '운영 배포 준비',
  production: '운영 중',
};

const PERMISSION_OPTIONS = {
  'surface-only': '비로그인 표면 감사',
  'login-readonly': '테스트 계정 읽기 감사',
  'test-data-write': '테스트 데이터 생성/수정 감사',
  'security-probe': '권한/업로드 보안 점검',
  'destructive-sandbox': '삭제/파괴 테스트 가능 샌드박스',
};

function bool(value) {
  return value === true || value === 'true' || value === 'on' || value === 1 || value === '1';
}

function optionValue(value, options, fallback) {
  return Object.prototype.hasOwnProperty.call(options, value) ? value : fallback;
}

function normalizeAuditProfile(input = {}) {
  const profile = input.profile && typeof input.profile === 'object' ? input.profile : input;
  const normalized = {
    ownership: optionValue(profile.ownership, OWNERSHIP_OPTIONS, 'owner'),
    environment: optionValue(profile.environment, ENVIRONMENT_OPTIONS, 'internal-test'),
    permissionLevel: optionValue(profile.permissionLevel, PERMISSION_OPTIONS, 'surface-only'),
    hasExplicitApproval: bool(profile.hasExplicitApproval),
    hasTestAccount: bool(profile.hasTestAccount),
    hasAdminAccount: bool(profile.hasAdminAccount),
    allowCreate: bool(profile.allowCreate),
    allowModify: bool(profile.allowModify),
    allowDelete: bool(profile.allowDelete),
    allowFileUpload: bool(profile.allowFileUpload),
    allowAuthzProbe: bool(profile.allowAuthzProbe),
    allowLoadTest: bool(profile.allowLoadTest),
    hasRollback: bool(profile.hasRollback),
    testWindow: String(profile.testWindow || '').trim().slice(0, 300),
    contact: String(profile.contact || '').trim().slice(0, 200),
    reportRecipients: String(profile.reportRecipients || '').trim().slice(0, 500),
    rollbackPlan: String(profile.rollbackPlan || '').trim().slice(0, 500),
    forbiddenAreas: String(profile.forbiddenAreas || '').trim().slice(0, 500),
    notes: String(profile.notes || input.notes || '').trim().slice(0, 1200),
  };
  normalized.labels = {
    ownership: OWNERSHIP_OPTIONS[normalized.ownership],
    environment: ENVIRONMENT_OPTIONS[normalized.environment],
    permissionLevel: PERMISSION_OPTIONS[normalized.permissionLevel],
  };
  return normalized;
}

function buildScopePlan(profile) {
  const allowed = ['HTTP 헤더와 공개 첫 화면 점검', '데스크톱/모바일 렌더링 확인', '접근성/레이아웃/콘솔/네트워크 오류 수집'];
  const blocked = [];
  const manualRequired = [];
  const warnings = [];
  const isApproved = profile.ownership === 'owner' || (profile.ownership === 'other-team-authorized' && profile.hasExplicitApproval);
  const isProduction = ['production', 'production-readiness'].includes(profile.environment);
  const wantsLogin = ['login-readonly', 'test-data-write', 'security-probe', 'destructive-sandbox'].includes(profile.permissionLevel);
  const wantsWrite = ['test-data-write', 'security-probe', 'destructive-sandbox'].includes(profile.permissionLevel)
    || profile.allowCreate || profile.allowModify || profile.allowDelete || profile.allowFileUpload;

  if (!isApproved) {
    blocked.push('승인 불명확 상태에서는 표면 감사 외 로그인/쓰기/권한우회/부하 테스트를 실행하지 않습니다.');
    warnings.push('오너 또는 명시 승인 확인 전에는 비침투 표면 감사만 가능합니다.');
  }
  if (wantsLogin && profile.hasTestAccount && isApproved) {
    allowed.push('제공된 테스트 계정 기준의 로그인 이후 읽기 점검 준비');
    manualRequired.push('테스트 계정 ID/비밀번호는 별도 보안 채널로 받아야 하며 리포트에 저장하지 않습니다.');
  } else if (wantsLogin) {
    blocked.push('테스트 계정 또는 승인 확인이 없어 로그인 이후 자동 점검은 제외합니다.');
  }
  if (wantsWrite && isApproved && profile.hasTestAccount && !isProduction) {
    allowed.push('테스트 데이터 생성/수정 범위 점검 준비');
    manualRequired.push('생성/수정 대상 메뉴와 테스트 데이터 prefix를 지정해야 실제 자동화로 확장할 수 있습니다.');
  } else if (wantsWrite) {
    blocked.push('운영/배포준비 또는 계정/승인 부족 상태에서는 생성/수정/업로드 점검을 실행하지 않습니다.');
  }
  if (profile.allowDelete) {
    if (profile.permissionLevel === 'destructive-sandbox' && !isProduction && profile.hasRollback && isApproved) {
      allowed.push('샌드박스 삭제 테스트 준비');
      manualRequired.push('삭제 대상이 테스트 데이터인지 확인하는 셀렉터/검증 규칙이 필요합니다.');
    } else {
      blocked.push('삭제 테스트는 샌드박스, 롤백, 승인, 테스트 데이터 확인이 모두 있을 때만 가능합니다.');
      warnings.push('삭제 허용이 선택되어 있어도 현재 MVP는 실제 삭제를 실행하지 않습니다.');
    }
  }
  if (profile.allowAuthzProbe) {
    if (isApproved && profile.hasTestAccount) {
      allowed.push('권한별 화면 노출 차이 점검 준비');
      manualRequired.push('일반/관리자 계정 쌍과 허용 URL 목록이 필요합니다.');
    } else {
      blocked.push('권한 우회 점검은 승인과 테스트 계정 없이는 제외합니다.');
    }
  }
  if (profile.allowFileUpload) {
    if (isApproved && profile.hasTestAccount && !isProduction) {
      allowed.push('파일 업로드 정책 점검 준비');
      manualRequired.push('허용 확장자, 최대 용량, 업로드 테스트 파일 종류를 지정해야 합니다.');
    } else {
      blocked.push('운영 또는 승인/계정 부족 상태에서는 파일 업로드 점검을 실행하지 않습니다.');
    }
  }
  if (profile.allowLoadTest) {
    blocked.push('부하 테스트는 현재 앱에서 자동 실행하지 않습니다. 별도 시간/한도/담당자 승인 후 전용 도구로 분리해야 합니다.');
    warnings.push('부하 테스트는 내부망이라도 장애를 만들 수 있으므로 프리패스 대상이 아닙니다.');
  }
  if (isProduction && !profile.testWindow) manualRequired.push('운영/배포준비 단계는 테스트 가능 시간대를 기록해야 합니다.');
  if (isProduction && !profile.contact) manualRequired.push('운영/배포준비 단계는 문제 발생 시 담당자 연락처를 기록해야 합니다.');
  if (isProduction && !profile.reportRecipients) manualRequired.push('운영/배포준비 단계는 리포트 수신자 메일을 기록해야 합니다.');
  if ((profile.allowDelete || profile.allowModify || profile.allowFileUpload) && !profile.hasRollback) {
    warnings.push('쓰기/업로드/삭제 범위를 선택했지만 롤백 확인이 없습니다.');
  }
  if (profile.forbiddenAreas) blocked.push(`절대 제외 메뉴: ${profile.forbiddenAreas}`);

  return {
    label: `${profile.labels.ownership} · ${profile.labels.environment} · ${profile.labels.permissionLevel}`,
    allowed,
    blocked: [...new Set(blocked)],
    manualRequired: [...new Set(manualRequired)],
    warnings: [...new Set(warnings)],
  };
}

function analyzeAuditProfile(profile, scopePlan, findings) {
  if (profile.ownership === 'external-or-unknown') {
    addFinding(findings, 'Critical', 'Audit Scope', '오너/승인 불명확 상태입니다', scopePlan.label, '테스트 권한, 담당자, 허용 범위를 먼저 문서화하고 승인된 표면 감사부터 시작합니다.', '허가 없는 로그인/쓰기/권한우회/부하 테스트는 법적·조직적 사고로 이어질 수 있습니다.');
  }
  if (profile.ownership === 'other-team-authorized' && !profile.hasExplicitApproval) {
    addFinding(findings, 'High', 'Audit Scope', '다른 팀 시스템인데 명시 승인이 체크되지 않았습니다', scopePlan.label, '감사 메모 또는 티켓에 승인자/가능 시간/금지 메뉴를 남긴 뒤 진행합니다.', '문제 발생 시 감사자가 허용 범위를 증명하기 어렵습니다.');
  }
  if (profile.environment === 'production' && (profile.allowModify || profile.allowDelete || profile.allowFileUpload || profile.allowLoadTest)) {
    addFinding(findings, 'Critical', 'Audit Scope', '운영 중 시스템에 위험 범위가 선택되었습니다', JSON.stringify({ allowModify: profile.allowModify, allowDelete: profile.allowDelete, allowFileUpload: profile.allowFileUpload, allowLoadTest: profile.allowLoadTest }), '운영에서는 읽기/표면 점검으로 제한하고 쓰기/삭제/부하는 스테이징 또는 샌드박스로 옮깁니다.', '실제 데이터 손상, 장애, 장애 전파 위험이 있습니다.');
  }
  if ((profile.allowModify || profile.allowDelete || profile.allowFileUpload) && !profile.hasRollback) {
    addFinding(findings, 'High', 'Audit Scope', '쓰기성 테스트인데 롤백 확인이 없습니다', 'hasRollback=false', '롤백/복구 방법과 테스트 데이터 식별 규칙을 먼저 적습니다.', '테스트 후 원복하지 못해 운영 데이터나 동료 작업을 망칠 수 있습니다.');
  }
  if (profile.allowLoadTest) {
    addFinding(findings, 'High', 'Audit Scope', '부하 테스트가 선택되었습니다', 'allowLoadTest=true', '부하 테스트는 현재 자동 실행하지 말고 별도 한도, 시간, 중단 조건, 담당자를 세팅합니다.', '사이트가 느려지거나 내부망/DB 장애를 만들 수 있습니다.');
  }
  if (scopePlan.manualRequired.length >= 3) {
    addFinding(findings, 'Medium', 'Audit Scope', '수동 확인 정보가 부족합니다', scopePlan.manualRequired.join(' / '), '테스트 계정, 시간대, 담당자, 금지 메뉴, 롤백 정보를 채운 뒤 자동화 범위를 넓힙니다.', '감사 결과가 좋아 보여도 실제 승인 범위와 맞지 않을 수 있습니다.');
  }
}

function headersObject(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    out[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

// Single non-redirecting request pinned to pinnedIp (when provided). Pinning the
// dns.lookup of http/https guarantees the socket connects to the exact IP that
// passed assertTargetAllowed, while Host header and TLS SNI stay on the original
// hostname (so vhosts and certificate validation keep working).
function requestOnce(currentUrl, pinnedIp, signal, maxBytes = 4000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(currentUrl);
    const agent = parsed.protocol === 'https:' ? https : http;
    const options = {
      method: 'GET',
      headers: { 'user-agent': 'testGpt7-audit', accept: '*/*' },
      signal,
    };
    if (pinnedIp) options.lookup = pinnedLookup(pinnedIp);
    let settled = false;
    const req = agent.request(currentUrl, options, res => {
      const chunks = [];
      let size = 0;
      const finish = () => {
        if (settled) return;
        settled = true;
        resolve({ status: res.statusCode || 0, headers: headersObject(res.headers), body: Buffer.concat(chunks).toString('utf8') });
      };
      res.on('data', chunk => {
        size += chunk.length;
        if (size <= maxBytes * 4) chunks.push(chunk);
        if (size > maxBytes * 8) res.destroy(); // cap how much of the body we buffer
      });
      res.on('end', finish);
      res.on('close', finish); // resolve even if we destroyed the stream early
      res.on('error', err => { if (!settled) { settled = true; reject(err); } });
    });
    req.on('error', err => { if (!settled) { settled = true; reject(err); } });
    req.end();
  });
}

async function fetchHeaders(targetUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  const redirectChain = [];
  let currentUrl = targetUrl;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      const parsed = new URL(currentUrl);
      const allow = await assertTargetAllowed(parsed);
      const res = await requestOnce(currentUrl, allow?.pinnedIp, controller.signal);
      const location = res.headers.location;
      if (res.status >= 300 && res.status < 400 && location) {
        const nextUrl = new URL(location, currentUrl).toString();
        await assertTargetAllowed(new URL(nextUrl));
        redirectChain.push({ status: res.status, from: currentUrl, to: nextUrl });
        currentUrl = nextUrl;
        continue;
      }
      return {
        ok: true,
        status: res.status,
        finalUrl: currentUrl,
        headers: res.headers,
        htmlPreview: res.body.slice(0, 4000),
        redirectChain,
      };
    }
    throw new Error(`Too many redirects; max ${MAX_REDIRECTS}`);
  } finally {
    clearTimeout(timer);
  }
}

function analyzeHeaders(targetUrl, headerResult, findings) {
  const url = new URL(targetUrl);
  const headers = headerResult.headers || {};
  if (url.protocol !== 'https:') {
    addFinding(findings, 'High', 'Security', 'HTTPS가 아닙니다', targetUrl, '운영/내부망이라도 로그인/쿠키/개인정보가 오가면 HTTPS를 기본으로 둡니다.', '중간자 공격, 세션 탈취, 인증정보 노출 위험이 커집니다.');
  }
  if (!headers['content-security-policy']) {
    addFinding(findings, 'High', 'Security', 'Content-Security-Policy가 없습니다', 'response header missing: content-security-policy', '최소 default-src/self, script-src, img-src, frame-ancestors 정책을 명시합니다.', 'XSS 피해 범위와 외부 리소스 주입 위험을 줄이지 못합니다.');
  }
  if (!headers['x-frame-options'] && !/frame-ancestors/i.test(headers['content-security-policy'] || '')) {
    addFinding(findings, 'Medium', 'Security', '클릭재킹 방어 헤더가 없습니다', 'x-frame-options missing and CSP frame-ancestors missing', 'CSP frame-ancestors 또는 X-Frame-Options를 추가합니다.', '관리자 화면이 외부 iframe에 묻혀 오작동을 유도할 수 있습니다.');
  }
  if (!headers['x-content-type-options']) {
    addFinding(findings, 'Medium', 'Security', 'MIME sniffing 방어가 없습니다', 'response header missing: x-content-type-options', 'X-Content-Type-Options: nosniff를 추가합니다.', '브라우저가 잘못된 타입으로 스크립트/파일을 해석할 수 있습니다.');
  }
  if (!headers['referrer-policy']) {
    addFinding(findings, 'Low', 'Security', 'Referrer-Policy가 없습니다', 'response header missing: referrer-policy', 'strict-origin-when-cross-origin 또는 더 엄격한 정책을 둡니다.', '외부 이동 시 내부 경로/쿼리 일부가 노출될 수 있습니다.');
  }
  if (!headers['permissions-policy']) {
    addFinding(findings, 'Low', 'Security', 'Permissions-Policy가 없습니다', 'response header missing: permissions-policy', 'camera, microphone, geolocation 등 불필요 기능을 명시적으로 막습니다.', '브라우저 권한 표면이 불필요하게 넓게 남습니다.');
  }
  if (url.protocol === 'https:' && !headers['strict-transport-security']) {
    addFinding(findings, 'Medium', 'Security', 'HSTS가 없습니다', 'response header missing: strict-transport-security', 'Strict-Transport-Security를 운영 도메인에 적용합니다.', 'HTTPS 다운그레이드 공격 방어가 약합니다.');
  }
  const setCookie = headers['set-cookie'] || '';
  if (setCookie) {
    if (!/httponly/i.test(setCookie)) addFinding(findings, 'High', 'Security', '쿠키에 HttpOnly가 없습니다', 'set-cookie without HttpOnly', '세션/인증 쿠키에는 HttpOnly를 적용합니다.', 'XSS가 세션 탈취로 이어질 수 있습니다.');
    if (url.protocol === 'https:' && !/secure/i.test(setCookie)) addFinding(findings, 'High', 'Security', 'HTTPS 쿠키에 Secure가 없습니다', 'set-cookie without Secure', 'HTTPS 세션 쿠키에는 Secure를 적용합니다.', '쿠키가 평문 채널로 전송될 수 있습니다.');
    if (!/samesite/i.test(setCookie)) addFinding(findings, 'Medium', 'Security', '쿠키 SameSite가 없습니다', 'set-cookie without SameSite', 'SameSite=Lax 또는 Strict를 검토합니다.', 'CSRF 방어 기본선이 약합니다.');
  }
}

async function inspectViewport(browser, targetUrl, viewport) {
  const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height } });
  const consoleMessages = [];
  const requestFailures = [];
  const badResponses = [];
  const apiCalls = [];
  await page.route('**/*', async route => {
    const requestUrl = route.request().url();
    try {
      const parsed = new URL(requestUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) return route.continue();
      await assertTargetAllowed(parsed);
      return route.continue();
    } catch (error) {
      requestFailures.push({ url: requestUrl, failure: `blocked by target policy: ${error.message || String(error)}` });
      return route.abort('blockedbyclient');
    }
  });
  page.on('console', msg => {
    if (['error', 'warning'].includes(msg.type())) consoleMessages.push({ type: msg.type(), text: msg.text().slice(0, 400) });
  });
  page.on('requestfailed', req => requestFailures.push({ url: req.url(), failure: req.failure()?.errorText || 'failed' }));
  page.on('response', res => {
    const status = res.status();
    const url = res.url();
    if (status >= 400) badResponses.push({ status, url });
    if (/\/api\/|graphql|rpc|json/i.test(url)) apiCalls.push({ method: res.request().method(), status, url });
  });
  const started = Date.now();
  let response = null;
  let navError = null;
  try {
    response = await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 20000 });
  } catch (error) {
    navError = error.message || String(error);
  }
  const loadMs = Date.now() - started;
  const metrics = await page.evaluate(() => {
    const text = document.body ? document.body.innerText.replace(/\s+/g, ' ').trim() : '';
    const visible = el => {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
    };
    const labelFor = input => {
      if (input.id && document.querySelector(`label[for="${CSS.escape(input.id)}"]`)) return true;
      if (input.closest('label')) return true;
      if (input.getAttribute('aria-label') || input.getAttribute('aria-labelledby')) return true;
      return false;
    };
    const buttons = [...document.querySelectorAll('button,[role="button"],input[type="button"],input[type="submit"]')].filter(visible);
    const links = [...document.querySelectorAll('a[href]')].filter(visible);
    const inputs = [...document.querySelectorAll('input,textarea,select')].filter(visible);
    const imgs = [...document.querySelectorAll('img')].filter(visible);
    const forms = [...document.querySelectorAll('form')].filter(visible);
    const headings = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')].filter(visible).map(el => ({ tag: el.tagName, text: el.innerText.trim().slice(0, 120) }));
    const headingLevels = headings.map(item => Number(item.tag.replace('H', '')));
    const genericLabel = text => /^(확인|취소|저장|등록|검색|선택|보기|더보기|click|button|submit|ok|more|next|go)$/i.test(text.trim());
    const textOf = el => (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
    const idCounts = [...document.querySelectorAll('[id]')].reduce((acc, el) => {
      acc[el.id] = (acc[el.id] || 0) + 1;
      return acc;
    }, {});
    const overflow = [...document.querySelectorAll('body *')].filter(visible).map(el => {
      const rect = el.getBoundingClientRect();
      return rect.width > window.innerWidth + 2 ? { tag: el.tagName, cls: String(el.className || '').slice(0, 80), width: Math.round(rect.width) } : null;
    }).filter(Boolean).slice(0, 12);
    const smallTargets = [...buttons, ...links].map(el => {
      const rect = el.getBoundingClientRect();
      return rect.width < 36 || rect.height < 32 ? { tag: el.tagName, text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 80), width: Math.round(rect.width), height: Math.round(rect.height) } : null;
    }).filter(Boolean).slice(0, 20);
    return {
      title: document.title || '',
      lang: document.documentElement.lang || '',
      textSample: text.slice(0, 1200),
      textLength: text.length,
      h1: headings.filter(h => h.tag === 'H1').length,
      headings,
      landmarks: {
        header: document.querySelectorAll('header').length,
        nav: document.querySelectorAll('nav').length,
        main: document.querySelectorAll('main').length,
        footer: document.querySelectorAll('footer').length,
      },
      counts: {
        buttons: buttons.length,
        links: links.length,
        inputs: inputs.length,
        forms: forms.length,
        images: imgs.length,
        scripts: document.scripts.length,
        stylesheets: document.querySelectorAll('link[rel="stylesheet"]').length,
        nodes: document.querySelectorAll('*').length,
      },
      duplicateIds: Object.entries(idCounts).filter(([, count]) => count > 1).map(([id, count]) => ({ id, count })).slice(0, 20),
      genericActions: [...buttons, ...links].map(textOf).filter(Boolean).filter(genericLabel).slice(0, 20),
      emptyActionText: [...buttons, ...links].map(textOf).filter(text => text.length === 0).length,
      formsWithoutSubmit: forms.filter(form => ![...form.querySelectorAll('button,input[type="submit"],input[type="button"]')].some(visible)).length,
      headingSkips: headingLevels.map((level, index) => index > 0 && level - headingLevels[index - 1] > 1 ? `${headingLevels[index - 1]}->${level}` : null).filter(Boolean),
      actionTexts: [...buttons, ...links].map(textOf).filter(Boolean).slice(0, 30),
      hasSearch: inputs.some(input => /search|검색/i.test(`${input.type || ''} ${input.name || ''} ${input.id || ''} ${input.placeholder || ''}`)),
      hasStatusRegion: Boolean(document.querySelector('[role="status"],[aria-live]')),
      hasDialogSemantics: Boolean(document.querySelector('[role="dialog"],dialog')),
      hasTable: Boolean(document.querySelector('table,[role="table"],[role="grid"]')),
      errorStateWords: /(오류|실패|필수|유효|잘못|error|invalid|required|failed)/i.test(text),
      emptyStateWords: /(없습니다|비어|empty|no data|no results)/i.test(text),
      unlabeledButtons: buttons.filter(el => !(el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title'))).length,
      deadLinks: links.filter(el => ['#', '', 'javascript:void(0)'].includes((el.getAttribute('href') || '').trim().toLowerCase())).length,
      unsafeBlankLinks: links.filter(el => el.target === '_blank' && !/noopener|noreferrer/i.test(el.rel || '')).length,
      unlabeledInputs: inputs.filter(input => !labelFor(input)).length,
      missingImageAlt: imgs.filter(img => !img.getAttribute('alt')).length,
      passwordInputs: inputs.filter(input => input.type === 'password').map(input => ({ autocomplete: input.getAttribute('autocomplete') || '' })),
      overflow,
      smallTargets,
      resourceCount: performance.getEntriesByType('resource').length,
      resourceKinds: performance.getEntriesByType('resource').reduce((acc, item) => {
        const key = item.initiatorType || 'other';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {}),
      navTiming: performance.getEntriesByType('navigation')[0] ? {
        domContentLoaded: Math.round(performance.getEntriesByType('navigation')[0].domContentLoadedEventEnd),
        loadEventEnd: Math.round(performance.getEntriesByType('navigation')[0].loadEventEnd),
        transferSize: Math.round(performance.getEntriesByType('navigation')[0].transferSize || 0),
      } : null,
    };
  }).catch(error => ({ error: error.message || String(error) }));
  const screenshotName = `${Date.now()}-${viewport.name}.png`;
  const screenshotPath = path.join(SCREENSHOTS_DIR, screenshotName);
  await fs.mkdir(SCREENSHOTS_DIR, { recursive: true });
  await page.screenshot({ path: screenshotPath, fullPage: true }).catch(() => null);
  await page.close();
  return {
    viewport: viewport.name,
    width: viewport.width,
    height: viewport.height,
    status: response ? response.status() : null,
    finalUrl: response ? response.url() : targetUrl,
    loadMs,
    navError,
    consoleMessages,
    requestFailures,
    badResponses: badResponses.slice(0, 25),
    apiCalls: apiCalls.slice(0, 50),
    metrics,
    screenshotPath: path.join('data', 'screenshots', screenshotName),
  };
}

function analyzeViewportResult(result, findings) {
  const m = result.metrics || {};
  const label = `${result.viewport} ${result.width}x${result.height}`;
  if (result.navError) addFinding(findings, 'Critical', 'Functional QA', `${label} 접속 실패`, result.navError, '라우팅/서버/인증 리다이렉트/인증서 문제를 먼저 해결합니다.', '사용자는 첫 화면에 도달하지 못합니다.');
  if (result.loadMs > 8000) addFinding(findings, 'High', 'Functional QA', `${label} 초기 로딩이 매우 느립니다`, `${result.loadMs}ms`, '초기 요청, 렌더 차단 리소스, 불필요한 API 대기를 줄이고 3초/5초 기준을 둡니다.', '사용자는 화면이 멈춘 것으로 느끼고 이탈하거나 중복 조작할 수 있습니다.');
  else if (result.loadMs > 5000) addFinding(findings, 'Medium', 'Functional QA', `${label} 초기 로딩이 느립니다`, `${result.loadMs}ms`, '첫 화면에 필요한 데이터와 후순위 데이터를 분리하고 lazy loading 기준을 둡니다.', '업무 화면에서 반복 사용 피로가 커집니다.');
  if (result.consoleMessages.filter(item => item.type === 'error').length) {
    addFinding(findings, 'High', 'Functional QA', `${label} 콘솔 에러 발생`, JSON.stringify(result.consoleMessages.filter(item => item.type === 'error').slice(0, 5)), '런타임 에러 원인을 제거하고 배포 전 콘솔 에러 0개를 기준으로 둡니다.', '기능 일부가 조용히 실패하거나 사용자 액션이 막힐 수 있습니다.');
  }
  if (result.requestFailures.length) {
    addFinding(findings, 'High', 'Architecture', `${label} 네트워크 실패 발생`, JSON.stringify(result.requestFailures.slice(0, 5)), '실패한 요청의 endpoint, CORS, 서버 상태, 정적 파일 경로를 점검합니다.', '화면은 떠도 데이터/이미지/기능이 부분 실패할 수 있습니다.');
  }
  if (result.badResponses.length) {
    addFinding(findings, 'Medium', 'Architecture', `${label} 4xx/5xx 응답이 있습니다`, JSON.stringify(result.badResponses.slice(0, 8)), '필요 없는 요청은 제거하고 필요한 요청은 정상 응답/에러 UI를 설계합니다.', '사용자에게 빈 화면, 깨진 이미지, 실패 상태가 보일 수 있습니다.');
  }
  if (m.duplicateIds && m.duplicateIds.length) addFinding(findings, 'High', 'Functional QA', `${label} 중복 id가 있습니다`, JSON.stringify(m.duplicateIds.slice(0, 8)), '컴포넌트 반복 렌더링에서 id를 고유하게 만들고 label/aria 연결을 다시 검증합니다.', '라벨 연결, 스크립트 선택자, 자동화 테스트가 엉뚱한 요소를 잡을 수 있습니다.');
  if (m.counts && m.counts.forms && m.formsWithoutSubmit) addFinding(findings, 'High', 'Functional QA', `${label} 제출 동작 없는 폼이 있습니다`, `${m.formsWithoutSubmit}/${m.counts.forms} forms without visible submit action`, '폼마다 저장/검색/취소 같은 명시 액션과 성공/실패 상태를 연결합니다.', '사용자가 값을 입력해도 다음 행동을 알 수 없거나 저장이 누락될 수 있습니다.');
  if (m.counts && m.counts.inputs >= 2 && !m.errorStateWords) addFinding(findings, 'Medium', 'Functional QA', `${label} 입력 오류 상태 단서가 약합니다`, `${m.counts.inputs} inputs, no visible validation/error wording`, '필수값, 형식 오류, 저장 실패, 서버 오류 메시지를 화면 상태로 설계합니다.', '실패했을 때 사용자가 무엇을 고쳐야 하는지 알기 어렵습니다.');
  if (m.counts && (m.counts.buttons + m.counts.links) === 0 && m.textLength > 300) addFinding(findings, 'Medium', 'Functional QA', `${label} 읽을 내용은 있지만 실행 동작이 없습니다`, `${m.textLength} chars, 0 actions`, '화면 목적에 맞는 주요 액션, 다음 단계, 문의/돌아가기 동작을 둡니다.', '사용자는 내용을 본 뒤 무엇을 해야 하는지 막힙니다.');
  if (!m.title || m.title.length < 6) addFinding(findings, 'Medium', 'Design UX', `${label} 문서 제목이 약합니다`, `title="${m.title || ''}"`, '제품명과 현재 기능을 포함한 title을 작성합니다.', '탭/히스토리/접근성에서 화면 목적이 드러나지 않습니다.');
  if (!m.lang) addFinding(findings, 'Low', 'Design UX', `${label} html lang 속성이 없습니다`, 'html[lang] missing', '한국어 서비스라면 lang="ko"를 지정합니다.', '스크린리더와 번역/입력 보조 품질이 떨어집니다.');
  if (!m.h1) addFinding(findings, 'Medium', 'Design UX', `${label} H1이 없습니다`, 'h1 count = 0', '첫 화면의 목적을 설명하는 H1을 하나 둡니다.', '사용자가 화면의 주 목적을 빠르게 파악하기 어렵습니다.');
  if (m.textLength < 120) addFinding(findings, 'Medium', 'Design UX', `${label} 첫 화면 정보량이 부족합니다`, `${m.textLength} visible characters`, '사용자가 대상, 상태, 다음 행동을 이해할 수 있는 제목/요약/주요 액션을 보강합니다.', '빈 껍데기나 미완성 화면처럼 보일 수 있습니다.');
  if (!m.landmarks || !m.landmarks.main) addFinding(findings, 'Medium', 'Design UX', `${label} main 랜드마크가 없습니다`, 'main landmark missing', '핵심 콘텐츠를 main 영역으로 감싸 화면 구조를 명확히 합니다.', '보조기기와 자동화 도구가 화면의 중심 콘텐츠를 파악하기 어렵습니다.');
  if (m.counts && m.counts.links >= 4 && !m.landmarks.nav) addFinding(findings, 'Low', 'Design UX', `${label} 링크가 많지만 nav 구조가 없습니다`, `${m.counts.links} links, nav=0`, '주요 이동 링크는 nav 영역으로 묶고 현재 위치/그룹을 드러냅니다.', '반복 업무 화면에서 이동 구조를 빠르게 스캔하기 어렵습니다.');
  if (m.headingSkips && m.headingSkips.length) addFinding(findings, 'Low', 'Design UX', `${label} heading 계층이 건너뜁니다`, JSON.stringify(m.headingSkips.slice(0, 6)), 'H1-H2-H3 순서로 정보 계층을 정리합니다.', '보고서/업무 화면을 훑어볼 때 구조 이해가 느려집니다.');
  if (m.overflow && m.overflow.length) addFinding(findings, 'High', 'Design UX', `${label} 가로 오버플로우가 있습니다`, JSON.stringify(m.overflow.slice(0, 5)), '고정 폭, 긴 텍스트, table/card grid를 responsive constraint로 수정합니다.', '모바일/작은 화면에서 화면이 밀리고 조작성이 급격히 떨어집니다.');
  if (m.unlabeledButtons) addFinding(findings, 'Medium', 'Design UX', `${label} 라벨 없는 버튼이 있습니다`, `${m.unlabeledButtons} unlabeled buttons`, '아이콘 버튼에는 aria-label/title을 반드시 둡니다.', '사용자는 버튼 의미를 모르고 보조기기도 읽지 못합니다.');
  if (m.genericActions && m.genericActions.length) addFinding(findings, 'Medium', 'Design UX', `${label} 버튼/링크 문구가 너무 일반적입니다`, JSON.stringify(m.genericActions.slice(0, 10)), '확인/보기/더보기 대신 결과가 드러나는 동사형 라벨을 씁니다.', '사용자는 클릭 후 무슨 일이 일어나는지 예측하기 어렵습니다.');
  if (m.unlabeledInputs) addFinding(findings, 'High', 'Design UX', `${label} 라벨 없는 입력폼이 있습니다`, `${m.unlabeledInputs} unlabeled inputs`, 'label, aria-label, aria-labelledby 중 하나를 연결합니다.', '폼 작성 오류와 접근성 실패 가능성이 큽니다.');
  if (m.deadLinks) addFinding(findings, 'Medium', 'Functional QA', `${label} 죽은 링크/더미 링크가 있습니다`, `${m.deadLinks} links with #/empty/javascript`, '실제 이동/동작을 연결하거나 버튼으로 바꾸고 disabled 상태를 명확히 합니다.', '껍데기 UI처럼 보이며 사용자 신뢰가 떨어집니다.');
  if (m.unsafeBlankLinks) addFinding(findings, 'Medium', 'Security', `${label} target=_blank 링크에 rel 보호가 없습니다`, `${m.unsafeBlankLinks} unsafe blank links`, 'rel="noopener noreferrer"를 추가합니다.', '새 탭 페이지가 원본 페이지를 조작할 수 있습니다.');
  if (m.missingImageAlt) addFinding(findings, 'Low', 'Design UX', `${label} alt 없는 이미지가 있습니다`, `${m.missingImageAlt} images without alt`, '장식 이미지는 alt=""로, 의미 이미지는 설명 alt를 둡니다.', '접근성/검색/오류 상황에서 의미 전달이 약합니다.');
  if (m.smallTargets && m.smallTargets.length) addFinding(findings, 'Medium', 'Design UX', `${label} 터치 타깃이 작습니다`, JSON.stringify(m.smallTargets.slice(0, 5)), '주요 클릭 영역은 최소 36x32 이상, 모바일은 44px 기준을 권장합니다.', '모바일에서 오터치와 조작 피로가 커집니다.');
  if (m.counts && m.counts.nodes > 3000) addFinding(findings, 'Medium', 'Architecture', `${label} DOM 노드가 과도합니다`, `${m.counts.nodes} DOM nodes`, '목록 가상화, 중첩 카드/불필요 wrapper 제거, 초기 렌더 범위를 줄입니다.', '렌더링/스크롤 성능과 유지보수성이 나빠집니다.');
  if (m.counts && m.counts.scripts > 30) addFinding(findings, 'Medium', 'Architecture', `${label} 스크립트 수가 많습니다`, `${m.counts.scripts} scripts`, '번들 분할 기준과 중복 라이브러리 로딩을 점검합니다.', '초기 로딩, 캐시, 장애 추적 복잡도가 커집니다.');
  if (m.resourceCount > 120) addFinding(findings, 'Medium', 'Architecture', `${label} 리소스 요청 수가 많습니다`, `${m.resourceCount} resources`, '번들/이미지/font 요청을 묶거나 lazy loading 기준을 세웁니다.', '느린 내부망/저사양 PC에서 체감 속도가 나빠집니다.');
  if (m.navTiming && m.navTiming.transferSize > 1500000) addFinding(findings, 'Medium', 'Architecture', `${label} 초기 문서 전송량이 큽니다`, `${m.navTiming.transferSize} bytes`, '초기 HTML/SSR payload와 중복 데이터 주입을 줄입니다.', '저사양 PC나 VPN 환경에서 첫 화면 체감 속도가 나빠집니다.');
  if (m.counts && m.counts.inputs >= 2 && !result.apiCalls.length) addFinding(findings, 'Low', 'Architecture', `${label} 입력 화면인데 관측된 API 흐름이 없습니다`, `${m.counts.inputs} inputs, observed API calls 0`, '저장/검색/검증 API가 실제 액션과 연결되는지 시나리오 감사에서 확인합니다.', '정적 껍데기 UI이거나 데이터 저장 흐름이 숨겨져 있을 수 있습니다.');
}

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
  let verdict = '실사용 가능';
  if (counts.Critical) verdict = '보안상/기능상 사용 금지';
  else if (counts.High >= 4) verdict = '껍데기 또는 고위험 데모 수준';
  else if (counts.High >= 2) verdict = '내부 테스트만 가능';
  else if (counts.High || counts.Medium >= 5) verdict = '개발 더 필요';
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
    ...((report.scopePlan?.blocked || []).length ? report.scopePlan.blocked : ['없음']).map(item => `- ${item}`),
    ``,
    `### Manual Required`,
    ...((report.scopePlan?.manualRequired || []).length ? report.scopePlan.manualRequired : ['없음']).map(item => `- ${item}`),
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
    `# ${report.summary?.verdict || '감사 결과'}`,
    ``,
    `대상: ${report.targetUrl}`,
    `생성: ${report.generatedAt}`,
    `점수: ${report.summary?.score ?? '-'}`,
    `범위: ${report.scopePlan?.label || '-'}`,
    ``,
    `## 요약`,
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
    `## 먼저 볼 항목`,
    ``,
    ...(priority.length ? priority.map(item => `- [${item.severity}] ${item.title}`) : ['- Critical/High 항목 없음']),
    ``,
    `HTML 보고서는 실사용자용 첨부 문서입니다.`,
    `Markdown 보고서는 AI/에이전트 확인용 첨부 문서입니다.`,
  ].join('\n');
}

function severityClass(severity) {
  return String(severity || '').toLowerCase().replace(/[^a-z]/g, '') || 'low';
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
  const generated = report.generatedAt ? new Date(report.generatedAt).toLocaleString('ko-KR') : '-';
  const htmlList = items => (items && items.length ? items : ['없음']).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Site Audit Report ${escapeHtml(report.id)}</title>
  <style>
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
    @media print { body { background:white; } .page { padding:0; } .hero { border-radius:0; } }
  </style>
</head>
<body>
  <main class="page">
    <header class="hero">
      <div class="eyebrow">Site Audit Report</div>
      <h1>${escapeHtml(report.summary?.verdict || '감사 결과')}</h1>
      <p>${escapeHtml(report.targetUrl)} · ${escapeHtml(generated)}</p>
      <p>${escapeHtml(scope.label || '범위 미설정')}</p>
    </header>

    <section class="summary">
      <article class="card score"><span>Audit Score</span><b>${escapeHtml(report.summary?.score ?? '-')}</b><p>${escapeHtml(report.summary?.verdict || '-')}</p></article>
      <article class="card metric"><span>Critical</span><b>${counts.Critical || 0}</b></article>
      <article class="card metric"><span>High</span><b>${counts.High || 0}</b></article>
      <article class="card metric"><span>Medium</span><b>${counts.Medium || 0}</b></article>
      <article class="card metric"><span>Low</span><b>${counts.Low || 0}</b></article>
    </section>

    <section class="grid">
      <article class="section">
        <h2>요약</h2>
        <dl>
          <div><dt>대상</dt><dd>${escapeHtml(report.targetUrl)}</dd></div>
          <div><dt>소유/단계/권한</dt><dd>${escapeHtml(profile.labels?.ownership || '-')} · ${escapeHtml(profile.labels?.environment || '-')} · ${escapeHtml(profile.labels?.permissionLevel || '-')}</dd></div>
          <div><dt>리포트 수신자</dt><dd>${escapeHtml(profile.reportRecipients || '-')}</dd></div>
          <div><dt>메일 발송</dt><dd>${escapeHtml(report.mailDelivery?.status || 'pending')} ${escapeHtml(report.mailDelivery?.error || report.mailDelivery?.reason || '')}</dd></div>
        </dl>
      </article>
      <article class="section">
        <h2>핵심 위험</h2>
        ${priority.length ? `<ul>${priority.map(item => `<li><b>${escapeHtml(item.severity)}</b> ${escapeHtml(item.title)}</li>`).join('')}</ul>` : '<p>Critical/High 항목은 없습니다.</p>'}
        <h3>영역별 발견</h3>
        ${areas.length ? `<ul>${areas.map(([area, count]) => `<li>${escapeHtml(area)}: ${count}건</li>`).join('')}</ul>` : '<p>감지된 문제가 없습니다.</p>'}
      </article>
    </section>

    <section class="section">
      <h2>영역별 균형</h2>
      <div class="area-grid">
        ${AUDIT_AREAS.map(area => {
          const row = areaCounts[area] || {};
          return `<article><span>${escapeHtml(area)}</span><b>${row.total || 0}</b><small>C ${row.Critical || 0} · H ${row.High || 0} · M ${row.Medium || 0} · L ${row.Low || 0}</small></article>`;
        }).join('')}
      </div>
    </section>

    <section class="section">
      <h2>방향</h2>
      <div class="direction">
        <article><h3>바로 고칠 것</h3><ul>${htmlList(priority.map(item => item.fix).slice(0, 4))}</ul></article>
        <article><h3>이번 검사에서 차단</h3><ul>${htmlList(scope.blocked)}</ul></article>
        <article><h3>수동 확인 필요</h3><ul>${htmlList(scope.manualRequired)}</ul></article>
      </div>
    </section>

    <section class="section">
      <h2>감사 범위</h2>
      <div class="grid">
        <article><h3>실행 허용</h3><ul>${htmlList(scope.allowed)}</ul></article>
        <article><h3>주의</h3><ul>${htmlList(scope.warnings)}</ul></article>
      </div>
    </section>

    <section class="section">
      <h2>상세 발견</h2>
      ${(report.findings || []).map((item, index) => `
        <article class="finding ${severityClass(item.severity)}-border">
          <div class="finding-head"><span class="pill ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span><strong>${escapeHtml(item.area)}</strong></div>
          <h3>${index + 1}. ${escapeHtml(item.title)}</h3>
          <dl>
            <div><dt>증거</dt><dd>${escapeHtml(item.evidence)}</dd></div>
            <div><dt>영향</dt><dd>${escapeHtml(item.impact)}</dd></div>
            <div><dt>수정 방향</dt><dd>${escapeHtml(item.fix)}</dd></div>
          </dl>
        </article>`).join('') || '<p>감지된 문제가 없습니다.</p>'}
    </section>

    <section class="section">
      <h2>측정 근거</h2>
      <div class="grid">
        ${(report.viewports || []).map(view => `<article>
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
    </section>

    <p class="footer">Generated by testGpt7 · JSON/Markdown are kept for agents, this HTML file is for human readers.</p>
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
    addFinding(findings, 'Critical', 'Functional QA', '초기 HTTP 요청 실패', headerResult.error, '주소, 포트, 방화벽, 인증서, 서버 실행 상태를 먼저 확인합니다.', '감사를 진행할 기본 화면에 접근하지 못했습니다.');
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

async function resendReport(id) {
  const report = await readReport(id);
  if (!report) return null;
  report.mailDelivery = await sendReportEmail(report);
  report.markdown = buildMarkdown(report);
  report.htmlReport = buildHtmlReport(report);
  await saveReport(report);
  return report;
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

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === 'GET' && url.pathname === '/api/health') {
      return json(res, 200, { ok: true, name: 'testGpt7', port: PORT, host: HOST, storage: 'local git-ignored data directory' });
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

if (require.main === module) {            // import(테스트) 시엔 서버 미기동 — 순수함수 단위테스트 가능
  http.createServer(route).listen(PORT, HOST, () => {
    console.log(`testGpt7 running at http://${HOST}:${PORT}`);
  });
}

module.exports = {                        // 단위테스트용 export (순수 헬퍼 + SSRF 가드)
  isPrivateIp, isLoopbackHost, hostnameMatchesAllowlist,
  escapeHtml, parseRecipients, severityWeight,
  assertTargetAllowed, shouldBlockPrivateIps,
  resolveHostIps, pinnedLookup,
};

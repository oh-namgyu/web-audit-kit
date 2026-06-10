// Email delivery: recipient parsing, MIME message building, and the sendmail /
// SMTP transports used to deliver audit reports.
const net = require('net');
const tls = require('tls');
const { spawn } = require('child_process');
const { bool, parseRecipients } = require('./util');
const { HOST } = require('./targetGuard');
const { buildEmailSummary, buildHtmlReport, buildMarkdown } = require('./report');

const SENDMAIL_PATH = process.env.TESTGPT7_SENDMAIL_PATH || '/usr/sbin/sendmail';

function encodeHeader(value) {
  const raw = String(value || '').replace(/[\r\n]/g, ' ').trim();
  return /^[\x00-\x7F]*$/.test(raw) ? raw : `=?UTF-8?B?${Buffer.from(raw, 'utf8').toString('base64')}?=`;
}

function getMailConfig() {
  const transport = String(process.env.TESTGPT7_MAIL_TRANSPORT || 'disabled').trim().toLowerCase();
  return {
    transport,
    from: process.env.TESTGPT7_MAIL_FROM || process.env.SMTP_FROM || 'web-audit-kit-audit@localhost',
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

function buildAttachmentParts(boundary, attachments) {
  return attachments.flatMap(attachment => [
    `--${boundary}`,
    `Content-Type: ${attachment.contentType}; name="${attachment.filename}"`,
    `Content-Disposition: attachment; filename="${attachment.filename}"`,
    `Content-Transfer-Encoding: base64`,
    ``,
    foldBase64(attachment.content),
    ``,
  ]);
}

function buildEmailMessage({ from, to, subject, body, attachments = [] }) {
  const safeFrom = String(from || '').replace(/[\r\n]/g, '').trim();
  const recipients = to.map(item => String(item).replace(/[\r\n]/g, '').trim()).join(', ');
  if (attachments.length) {
    const boundary = `web-audit-kit-${Date.now()}-${Math.random().toString(16).slice(2)}`;
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
      ...buildAttachmentParts(boundary, attachments),
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
  const subject = `[web-audit-kit] ${report.summary.verdict} - ${report.targetUrl}`;
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

module.exports = {
  encodeHeader,
  getMailConfig,
  foldBase64,
  buildEmailMessage,
  sendWithSendmail,
  createSmtpClient,
  sendWithSmtp,
  sendReportEmail,
};

// Shared low-level helpers used across the audit modules.

function bool(value) {
  return value === true || value === 'true' || value === 'on' || value === 1 || value === '1';
}

const ENV_PREFIX = 'WEB_AUDIT_KIT_';
const LEGACY_ENV_PREFIX = 'TESTGPT7_';
const warnedLegacyEnv = new Set();

// Reads WEB_AUDIT_KIT_<name>, falling back to the deprecated TESTGPT7_<name>.
// Empty values count as unset; the new name wins when both are set.
function env(name) {
  const current = process.env[ENV_PREFIX + name];
  if (current) return current;
  const legacy = process.env[LEGACY_ENV_PREFIX + name];
  if (legacy && !warnedLegacyEnv.has(name)) {
    warnedLegacyEnv.add(name);
    process.stderr.write(`[web-audit-kit] ${LEGACY_ENV_PREFIX}${name} is deprecated; use ${ENV_PREFIX}${name} instead.\n`);
  }
  return legacy || undefined;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function severityWeight(severity) {
  return { Critical: 30, High: 18, Medium: 8, Low: 3 }[severity] || 1;
}

function parseRecipients(value) {
  return String(value || '')
    .split(/[,\n;]/)
    .map(item => item.trim())
    .filter(Boolean)
    .filter(item => /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(item))
    .slice(0, 20);
}

function addFinding(findings, severity, area, title, evidence, fix, impact) {
  findings.push({ id: `${area}-${findings.length + 1}`, severity, area, title, evidence, impact, fix });
}

module.exports = { bool, env, escapeHtml, severityWeight, addFinding, parseRecipients };

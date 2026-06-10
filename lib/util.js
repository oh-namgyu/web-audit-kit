// Shared low-level helpers used across the audit modules.

function bool(value) {
  return value === true || value === 'true' || value === 'on' || value === 1 || value === '1';
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

module.exports = { bool, escapeHtml, severityWeight, addFinding, parseRecipients };

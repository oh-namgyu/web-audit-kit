// Audit scope: profile normalization, the permission/stage scope plan, and the
// findings raised by the audit profile itself.
const { bool, addFinding } = require('./util');

const OWNERSHIP_OPTIONS = {
  owner: 'I am the owner',
  'other-team-authorized': "Another team's system - approved",
  'external-or-unknown': 'Ownership/approval unclear',
};

const ENVIRONMENT_OPTIONS = {
  'local-dev': 'Local development',
  'internal-test': 'Internal test',
  staging: 'Staging',
  'production-readiness': 'Production-readiness',
  production: 'Production (live)',
};

const PERMISSION_OPTIONS = {
  'surface-only': 'Unauthenticated surface audit',
  'login-readonly': 'Test-account read-only audit',
  'test-data-write': 'Test-data create/update audit',
  'security-probe': 'Authorization/upload security check',
  'destructive-sandbox': 'Delete/destructive-test sandbox',
};

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

// ---- Scope planning ---------------------------------------------------------

function scopeFlags(profile) {
  return {
    isApproved: profile.ownership === 'owner' || (profile.ownership === 'other-team-authorized' && profile.hasExplicitApproval),
    isProduction: ['production', 'production-readiness'].includes(profile.environment),
    wantsLogin: ['login-readonly', 'test-data-write', 'security-probe', 'destructive-sandbox'].includes(profile.permissionLevel),
    wantsWrite: ['test-data-write', 'security-probe', 'destructive-sandbox'].includes(profile.permissionLevel)
      || profile.allowCreate || profile.allowModify || profile.allowDelete || profile.allowFileUpload,
  };
}

function planApprovalAndLogin(profile, flags, scope) {
  if (!flags.isApproved) {
    scope.blocked.push('While ownership/approval is unclear, no login, write, authorization-bypass, or load testing is performed beyond the surface audit.');
    scope.warnings.push('Until ownership or explicit approval is confirmed, only a non-invasive surface audit is possible.');
  }
  if (flags.wantsLogin && profile.hasTestAccount && flags.isApproved) {
    scope.allowed.push('Prepare post-login read-only checks using the provided test account');
    scope.manualRequired.push('Test-account credentials must be received through a separate secure channel and are not stored in the report.');
  } else if (flags.wantsLogin) {
    scope.blocked.push('Automated post-login checks are excluded because no test account or approval was confirmed.');
  }
}

function planWriteAndDelete(profile, flags, scope) {
  if (flags.wantsWrite && flags.isApproved && profile.hasTestAccount && !flags.isProduction) {
    scope.allowed.push('Prepare test-data create/update scope checks');
    scope.manualRequired.push('Specify the target menus and a test-data prefix before this can be extended into real automation.');
  } else if (flags.wantsWrite) {
    scope.blocked.push('Create/update/upload checks are not performed in production/readiness environments or without sufficient account/approval.');
  }
  if (profile.allowDelete) {
    if (profile.permissionLevel === 'destructive-sandbox' && !flags.isProduction && profile.hasRollback && flags.isApproved) {
      scope.allowed.push('Prepare sandbox delete tests');
      scope.manualRequired.push('Selectors/validation rules are needed to confirm the delete target is test data.');
    } else {
      scope.blocked.push('Delete tests are only possible when sandbox, rollback, approval, and test-data confirmation are all present.');
      scope.warnings.push('Even if delete is allowed, this MVP does not perform actual deletions.');
    }
  }
}

function planProbesAndUpload(profile, flags, scope) {
  if (profile.allowAuthzProbe) {
    if (flags.isApproved && profile.hasTestAccount) {
      scope.allowed.push('Prepare role-based screen exposure difference checks');
      scope.manualRequired.push('A pair of regular/admin accounts and an allowed-URL list are required.');
    } else {
      scope.blocked.push('Authorization-bypass checks are excluded without approval and a test account.');
    }
  }
  if (profile.allowFileUpload) {
    if (flags.isApproved && profile.hasTestAccount && !flags.isProduction) {
      scope.allowed.push('Prepare file-upload policy checks');
      scope.manualRequired.push('Specify allowed extensions, maximum size, and the kinds of upload test files.');
    } else {
      scope.blocked.push('File-upload checks are not performed in production or without sufficient approval/account.');
    }
  }
  if (profile.allowLoadTest) {
    scope.blocked.push('Load testing is not run automatically by this app. It must be split into a dedicated tool after a separate time window, limit, and owner approval.');
    scope.warnings.push('Load testing can cause outages even on an internal network, so it is not a free-pass item.');
  }
}

function planManualRequirements(profile, flags, scope) {
  if (flags.isProduction && !profile.testWindow) scope.manualRequired.push('Production/readiness stages must record an allowed test time window.');
  if (flags.isProduction && !profile.contact) scope.manualRequired.push('Production/readiness stages must record an on-call contact for incidents.');
  if (flags.isProduction && !profile.reportRecipients) scope.manualRequired.push('Production/readiness stages must record a report-recipient email.');
  if ((profile.allowDelete || profile.allowModify || profile.allowFileUpload) && !profile.hasRollback) {
    scope.warnings.push('A write/upload/delete scope was selected but rollback was not confirmed.');
  }
  if (profile.forbiddenAreas) scope.blocked.push(`Strictly excluded menus: ${profile.forbiddenAreas}`);
}

function buildScopePlan(profile) {
  const flags = scopeFlags(profile);
  const scope = {
    allowed: ['Check HTTP headers and the public first screen', 'Verify desktop/mobile rendering', 'Collect accessibility/layout/console/network errors'],
    blocked: [],
    manualRequired: [],
    warnings: [],
  };
  planApprovalAndLogin(profile, flags, scope);
  planWriteAndDelete(profile, flags, scope);
  planProbesAndUpload(profile, flags, scope);
  planManualRequirements(profile, flags, scope);
  return {
    label: `${profile.labels.ownership} · ${profile.labels.environment} · ${profile.labels.permissionLevel}`,
    allowed: scope.allowed,
    blocked: [...new Set(scope.blocked)],
    manualRequired: [...new Set(scope.manualRequired)],
    warnings: [...new Set(scope.warnings)],
  };
}

function analyzeAuditProfile(profile, scopePlan, findings) {
  if (profile.ownership === 'external-or-unknown') {
    addFinding(findings, 'Critical', 'Audit Scope', 'Ownership/approval is unclear', scopePlan.label, 'Document the test authorization, owner, and allowed scope first, then start with an approved surface audit.', 'Unauthorized login/write/authorization-bypass/load testing can lead to legal and organizational incidents.');
  }
  if (profile.ownership === 'other-team-authorized' && !profile.hasExplicitApproval) {
    addFinding(findings, 'High', 'Audit Scope', "Another team's system but explicit approval is unchecked", scopePlan.label, 'Record the approver, available time window, and forbidden menus in an audit note or ticket before proceeding.', 'If an incident occurs, the auditor cannot easily prove the allowed scope.');
  }
  if (profile.environment === 'production' && (profile.allowModify || profile.allowDelete || profile.allowFileUpload || profile.allowLoadTest)) {
    addFinding(findings, 'Critical', 'Audit Scope', 'A risky scope was selected against a live production system', JSON.stringify({ allowModify: profile.allowModify, allowDelete: profile.allowDelete, allowFileUpload: profile.allowFileUpload, allowLoadTest: profile.allowLoadTest }), 'In production, restrict to read/surface checks and move write/delete/load testing to staging or a sandbox.', 'There is a risk of real data corruption, outages, and outage propagation.');
  }
  if ((profile.allowModify || profile.allowDelete || profile.allowFileUpload) && !profile.hasRollback) {
    addFinding(findings, 'High', 'Audit Scope', 'A write-type test was selected but rollback is unconfirmed', 'hasRollback=false', 'Write down the rollback/recovery method and the test-data identification rules first.', 'You may be unable to undo after testing and could damage production data or coworkers\' work.');
  }
  if (profile.allowLoadTest) {
    addFinding(findings, 'High', 'Audit Scope', 'Load testing was selected', 'allowLoadTest=true', 'Do not run load testing automatically for now; set up a separate limit, time window, stop condition, and owner.', 'It can slow the site or cause internal-network/DB outages.');
  }
  if (scopePlan.manualRequired.length >= 3) {
    addFinding(findings, 'Medium', 'Audit Scope', 'Manual confirmation information is insufficient', scopePlan.manualRequired.join(' / '), 'Fill in the test account, time window, contact, forbidden menus, and rollback information, then widen the automation scope.', 'The audit result may look good but not match the actual approved scope.');
  }
}

module.exports = {
  OWNERSHIP_OPTIONS,
  ENVIRONMENT_OPTIONS,
  PERMISSION_OPTIONS,
  optionValue,
  normalizeAuditProfile,
  buildScopePlan,
  analyzeAuditProfile,
};

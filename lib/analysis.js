// Audit analysis: scope profile normalization, scope planning, and the
// security / UX / functional / architecture findings derived from HTTP headers
// and the Playwright viewport inspection.
const path = require('path');
const fs = require('fs/promises');
const { bool, addFinding, severityWeight } = require('./util');
const { assertTargetAllowed } = require('./targetGuard');

const PLAYWRIGHT_MODULE_PATH = process.env.TESTGPT7_PLAYWRIGHT_PATH || '';
const SCREENSHOTS_DIR = path.join(__dirname, '..', 'data', 'screenshots');

// Canonical audit area order — single source of truth for report rendering.
// Mirrored in public/app.js (AUDIT_AREAS) for the client-side balance view.
const AUDIT_AREAS = ['Security', 'Design UX', 'Functional QA', 'Architecture', 'Audit Scope'];

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

// ---- Header analysis --------------------------------------------------------

function analyzeHeaders(targetUrl, headerResult, findings) {
  const url = new URL(targetUrl);
  const headers = headerResult.headers || {};
  if (url.protocol !== 'https:') {
    addFinding(findings, 'High', 'Security', 'Not served over HTTPS', targetUrl, 'Even on a production/internal network, keep HTTPS by default whenever logins, cookies, or personal data are exchanged.', 'Man-in-the-middle attacks, session hijacking, and credential exposure become much more likely.');
  }
  if (!headers['content-security-policy']) {
    addFinding(findings, 'High', 'Security', 'Content-Security-Policy is missing', 'response header missing: content-security-policy', 'Specify at least a default-src/self, script-src, img-src, and frame-ancestors policy.', 'You cannot reduce the blast radius of XSS or the risk of external resource injection.');
  }
  if (!headers['x-frame-options'] && !/frame-ancestors/i.test(headers['content-security-policy'] || '')) {
    addFinding(findings, 'Medium', 'Security', 'No clickjacking-defense header', 'x-frame-options missing and CSP frame-ancestors missing', 'Add CSP frame-ancestors or X-Frame-Options.', 'Admin screens could be buried in an external iframe to induce mis-clicks.');
  }
  if (!headers['x-content-type-options']) {
    addFinding(findings, 'Medium', 'Security', 'No MIME-sniffing defense', 'response header missing: x-content-type-options', 'Add X-Content-Type-Options: nosniff.', 'The browser may interpret scripts/files as the wrong type.');
  }
  if (!headers['referrer-policy']) {
    addFinding(findings, 'Low', 'Security', 'Referrer-Policy is missing', 'response header missing: referrer-policy', 'Set strict-origin-when-cross-origin or a stricter policy.', 'Part of internal paths/queries can leak when navigating to external sites.');
  }
  if (!headers['permissions-policy']) {
    addFinding(findings, 'Low', 'Security', 'Permissions-Policy is missing', 'response header missing: permissions-policy', 'Explicitly block unneeded features such as camera, microphone, and geolocation.', 'The browser permission surface stays unnecessarily wide.');
  }
  if (url.protocol === 'https:' && !headers['strict-transport-security']) {
    addFinding(findings, 'Medium', 'Security', 'HSTS is missing', 'response header missing: strict-transport-security', 'Apply Strict-Transport-Security to the production domain.', 'Defense against HTTPS-downgrade attacks is weak.');
  }
  const setCookie = headers['set-cookie'] || '';
  if (setCookie) {
    if (!/httponly/i.test(setCookie)) addFinding(findings, 'High', 'Security', 'Cookie is missing HttpOnly', 'set-cookie without HttpOnly', 'Apply HttpOnly to session/auth cookies.', 'XSS can lead to session hijacking.');
    if (url.protocol === 'https:' && !/secure/i.test(setCookie)) addFinding(findings, 'High', 'Security', 'HTTPS cookie is missing Secure', 'set-cookie without Secure', 'Apply Secure to HTTPS session cookies.', 'Cookies could be transmitted over a plaintext channel.');
    if (!/samesite/i.test(setCookie)) addFinding(findings, 'Medium', 'Security', 'Cookie is missing SameSite', 'set-cookie without SameSite', 'Consider SameSite=Lax or Strict.', 'The baseline CSRF defense is weak.');
  }
}

// ---- Viewport inspection ----------------------------------------------------

// Runs inside the page context to collect rendering / accessibility metrics.
function collectViewportMetrics() {
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
  const genericLabel = value => /^(ok|cancel|save|register|search|select|view|more|click|button|submit|next|go)$/i.test(value.trim());
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
    emptyActionText: [...buttons, ...links].map(textOf).filter(value => value.length === 0).length,
    formsWithoutSubmit: forms.filter(form => ![...form.querySelectorAll('button,input[type="submit"],input[type="button"]')].some(visible)).length,
    headingSkips: headingLevels.map((level, index) => index > 0 && level - headingLevels[index - 1] > 1 ? `${headingLevels[index - 1]}->${level}` : null).filter(Boolean),
    actionTexts: [...buttons, ...links].map(textOf).filter(Boolean).slice(0, 30),
    hasSearch: inputs.some(input => /search/i.test(`${input.type || ''} ${input.name || ''} ${input.id || ''} ${input.placeholder || ''}`)),
    hasStatusRegion: Boolean(document.querySelector('[role="status"],[aria-live]')),
    hasDialogSemantics: Boolean(document.querySelector('[role="dialog"],dialog')),
    hasTable: Boolean(document.querySelector('table,[role="table"],[role="grid"]')),
    errorStateWords: /(error|invalid|required|failed)/i.test(text),
    emptyStateWords: /(empty|no data|no results)/i.test(text),
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
}

// Attaches console / network listeners to a page and returns the collectors.
function attachPageListeners(page) {
  const consoleMessages = [];
  const requestFailures = [];
  const badResponses = [];
  const apiCalls = [];
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
  return { consoleMessages, requestFailures, badResponses, apiCalls };
}

async function inspectViewport(browser, targetUrl, viewport) {
  const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height } });
  const { consoleMessages, requestFailures, badResponses, apiCalls } = attachPageListeners(page);
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
  const started = Date.now();
  let response = null;
  let navError = null;
  try {
    response = await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 20000 });
  } catch (error) {
    navError = error.message || String(error);
  }
  const loadMs = Date.now() - started;
  const metrics = await page.evaluate(collectViewportMetrics).catch(error => ({ error: error.message || String(error) }));
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

// ---- Viewport findings ------------------------------------------------------

function analyzeViewportFunctional(result, label, findings) {
  const m = result.metrics || {};
  if (result.navError) addFinding(findings, 'Critical', 'Functional QA', `${label} failed to load`, result.navError, 'Resolve routing/server/auth-redirect/certificate issues first.', 'The user never reaches the first screen.');
  if (result.loadMs > 8000) addFinding(findings, 'High', 'Functional QA', `${label} initial load is very slow`, `${result.loadMs}ms`, 'Reduce the initial request, render-blocking resources, and unnecessary API waits, and set a 3s/5s target.', 'The user perceives the screen as frozen and may leave or repeat the action.');
  else if (result.loadMs > 5000) addFinding(findings, 'Medium', 'Functional QA', `${label} initial load is slow`, `${result.loadMs}ms`, 'Separate first-screen data from lower-priority data and set lazy-loading thresholds.', 'Repeated use of the work screen becomes more fatiguing.');
  if (result.consoleMessages.filter(item => item.type === 'error').length) {
    addFinding(findings, 'High', 'Functional QA', `${label} console errors occurred`, JSON.stringify(result.consoleMessages.filter(item => item.type === 'error').slice(0, 5)), 'Remove the root cause of runtime errors and set zero console errors as a pre-release bar.', 'Some features may silently fail or user actions may be blocked.');
  }
  if (m.duplicateIds && m.duplicateIds.length) addFinding(findings, 'High', 'Functional QA', `${label} has duplicate ids`, JSON.stringify(m.duplicateIds.slice(0, 8)), 'Make ids unique across repeated component renders and re-verify label/aria associations.', 'Label associations, script selectors, and automated tests may target the wrong element.');
  if (m.counts && m.counts.forms && m.formsWithoutSubmit) addFinding(findings, 'High', 'Functional QA', `${label} has forms without a submit action`, `${m.formsWithoutSubmit}/${m.counts.forms} forms without visible submit action`, 'Connect each form to an explicit action such as save/search/cancel and to success/failure states.', 'The user can enter values but cannot tell the next action, or the save may be missing.');
  if (m.counts && m.counts.inputs >= 2 && !m.errorStateWords) addFinding(findings, 'Medium', 'Functional QA', `${label} has weak input-error state cues`, `${m.counts.inputs} inputs, no visible validation/error wording`, 'Design required-value, format-error, save-failure, and server-error messages as visible screen states.', 'When something fails, the user cannot tell what to fix.');
  if (m.counts && (m.counts.buttons + m.counts.links) === 0 && m.textLength > 300) addFinding(findings, 'Medium', 'Functional QA', `${label} has content to read but no actions`, `${m.textLength} chars, 0 actions`, 'Add the main action, next step, and contact/back actions that fit the screen purpose.', 'After reading the content, the user is stuck on what to do.');
  if (m.deadLinks) addFinding(findings, 'Medium', 'Functional QA', `${label} has dead/dummy links`, `${m.deadLinks} links with #/empty/javascript`, 'Wire real navigation/actions or convert them to buttons and make disabled states clear.', 'It looks like a shell UI and reduces user trust.');
}

function analyzeViewportDesign(result, label, findings) {
  const m = result.metrics || {};
  if (!m.title || m.title.length < 6) addFinding(findings, 'Medium', 'Design UX', `${label} document title is weak`, `title="${m.title || ''}"`, 'Write a title that includes the product name and the current feature.', 'The screen purpose is not clear in the tab/history/accessibility tree.');
  if (!m.lang) addFinding(findings, 'Low', 'Design UX', `${label} html lang attribute is missing`, 'html[lang] missing', 'Set the html lang attribute to the primary content language.', 'Screen-reader and translation/input-assist quality drop.');
  if (!m.h1) addFinding(findings, 'Medium', 'Design UX', `${label} has no H1`, 'h1 count = 0', 'Add one H1 that describes the purpose of the first screen.', 'It is hard for users to quickly grasp the screen\'s main purpose.');
  if (m.textLength < 120) addFinding(findings, 'Medium', 'Design UX', `${label} first screen has little information`, `${m.textLength} visible characters`, 'Add a title/summary/main action so users understand the subject, state, and next step.', 'It can look like an empty shell or an unfinished screen.');
  if (!m.landmarks || !m.landmarks.main) addFinding(findings, 'Medium', 'Design UX', `${label} has no main landmark`, 'main landmark missing', 'Wrap the core content in a main region to clarify the screen structure.', 'Assistive tools and automation cannot easily identify the central content.');
  if (m.counts && m.counts.links >= 4 && !m.landmarks.nav) addFinding(findings, 'Low', 'Design UX', `${label} has many links but no nav structure`, `${m.counts.links} links, nav=0`, 'Group the main navigation links in a nav region and surface the current position/group.', 'On repeated work screens it is hard to scan the navigation structure quickly.');
  if (m.headingSkips && m.headingSkips.length) addFinding(findings, 'Low', 'Design UX', `${label} heading levels skip`, JSON.stringify(m.headingSkips.slice(0, 6)), 'Organize the information hierarchy in H1-H2-H3 order.', 'Scanning reports/work screens becomes slower to understand structurally.');
  if (m.overflow && m.overflow.length) addFinding(findings, 'High', 'Design UX', `${label} has horizontal overflow`, JSON.stringify(m.overflow.slice(0, 5)), 'Fix fixed widths, long text, and table/card grids with responsive constraints.', 'On mobile/small screens the layout shifts and usability drops sharply.');
  if (m.unlabeledButtons) addFinding(findings, 'Medium', 'Design UX', `${label} has unlabeled buttons`, `${m.unlabeledButtons} unlabeled buttons`, 'Always give icon buttons an aria-label/title.', 'Users cannot tell what the button does and assistive tools cannot read it.');
  if (m.genericActions && m.genericActions.length) addFinding(findings, 'Medium', 'Design UX', `${label} button/link wording is too generic`, JSON.stringify(m.genericActions.slice(0, 10)), 'Use verb-style labels that reveal the result instead of OK/View/More.', 'Users cannot predict what happens after clicking.');
  if (m.unlabeledInputs) addFinding(findings, 'High', 'Design UX', `${label} has unlabeled input fields`, `${m.unlabeledInputs} unlabeled inputs`, 'Connect one of label, aria-label, or aria-labelledby.', 'Form-entry errors and accessibility failures are likely.');
  if (m.missingImageAlt) addFinding(findings, 'Low', 'Design UX', `${label} has images without alt`, `${m.missingImageAlt} images without alt`, 'Use alt="" for decorative images and descriptive alt for meaningful images.', 'Meaning is weakly conveyed for accessibility/search/error situations.');
  if (m.smallTargets && m.smallTargets.length) addFinding(findings, 'Medium', 'Design UX', `${label} has small touch targets`, JSON.stringify(m.smallTargets.slice(0, 5)), 'Keep main click areas at least 36x32, and prefer a 44px target on mobile.', 'Mis-touches and operation fatigue increase on mobile.');
  if (m.unsafeBlankLinks) addFinding(findings, 'Medium', 'Security', `${label} target=_blank links lack rel protection`, `${m.unsafeBlankLinks} unsafe blank links`, 'Add rel="noopener noreferrer".', 'The new-tab page could manipulate the original page.');
}

function analyzeViewportArchitecture(result, label, findings) {
  const m = result.metrics || {};
  if (result.requestFailures.length) {
    addFinding(findings, 'High', 'Architecture', `${label} network failures occurred`, JSON.stringify(result.requestFailures.slice(0, 5)), 'Check the failed requests\' endpoint, CORS, server status, and static-file paths.', 'The screen may appear but data/images/features can partially fail.');
  }
  if (result.badResponses.length) {
    addFinding(findings, 'Medium', 'Architecture', `${label} has 4xx/5xx responses`, JSON.stringify(result.badResponses.slice(0, 8)), 'Remove unneeded requests and design proper response/error UI for needed ones.', 'Users may see blank screens, broken images, or failure states.');
  }
  if (m.counts && m.counts.nodes > 3000) addFinding(findings, 'Medium', 'Architecture', `${label} has excessive DOM nodes`, `${m.counts.nodes} DOM nodes`, 'Use list virtualization, remove nested cards/unnecessary wrappers, and reduce the initial render scope.', 'Rendering/scroll performance and maintainability degrade.');
  if (m.counts && m.counts.scripts > 30) addFinding(findings, 'Medium', 'Architecture', `${label} has many scripts`, `${m.counts.scripts} scripts`, 'Review bundle-split boundaries and duplicate library loading.', 'Initial loading, caching, and incident-tracing complexity grow.');
  if (m.resourceCount > 120) addFinding(findings, 'Medium', 'Architecture', `${label} has many resource requests`, `${m.resourceCount} resources`, 'Bundle/merge image/font requests or set lazy-loading thresholds.', 'Perceived speed degrades on slow internal networks or low-spec PCs.');
  if (m.navTiming && m.navTiming.transferSize > 1500000) addFinding(findings, 'Medium', 'Architecture', `${label} initial document transfer is large`, `${m.navTiming.transferSize} bytes`, 'Reduce the initial HTML/SSR payload and duplicate data injection.', 'First-screen perceived speed degrades on low-spec PCs or VPN environments.');
  if (m.counts && m.counts.inputs >= 2 && !result.apiCalls.length) addFinding(findings, 'Low', 'Architecture', `${label} is an input screen but no API flow was observed`, `${m.counts.inputs} inputs, observed API calls 0`, 'Confirm in a scenario audit that save/search/validate APIs are wired to the real actions.', 'It may be a static shell UI or the data-save flow may be hidden.');
}

function analyzeViewportResult(result, findings) {
  const label = `${result.viewport} ${result.width}x${result.height}`;
  analyzeViewportFunctional(result, label, findings);
  analyzeViewportDesign(result, label, findings);
  analyzeViewportArchitecture(result, label, findings);
}

// ---- Summary ----------------------------------------------------------------

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
  let verdict = 'Usable in production';
  if (counts.Critical) verdict = 'Do not use (security/functional blocker)';
  else if (counts.High >= 4) verdict = 'Shell or high-risk demo level';
  else if (counts.High >= 2) verdict = 'Internal testing only';
  else if (counts.High || counts.Medium >= 5) verdict = 'Needs more development';
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

module.exports = {
  AUDIT_AREAS,
  OWNERSHIP_OPTIONS,
  ENVIRONMENT_OPTIONS,
  PERMISSION_OPTIONS,
  loadPlaywright,
  optionValue,
  normalizeAuditProfile,
  buildScopePlan,
  analyzeAuditProfile,
  analyzeHeaders,
  inspectViewport,
  analyzeViewportResult,
  summarizeAreas,
  summarizeVerdict,
};

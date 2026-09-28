// Viewport inspection: opens the target in a Playwright page per viewport,
// records console/network activity, and collects rendering / accessibility
// metrics inside the page context.
const path = require('path');
const fs = require('fs/promises');
const { assertTargetAllowed } = require('./targetGuard');

const SCREENSHOTS_DIR = path.join(__dirname, '..', 'data', 'screenshots');

// ---- Page-context helpers ---------------------------------------------------
// Everything below up to PAGE_HELPERS runs inside the browser page, not Node:
// the functions are serialized into METRICS_SCRIPT, so they may only reference
// each other and browser globals.

function isVisible(el) {
  const style = window.getComputedStyle(el);
  const rect = el.getBoundingClientRect();
  return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
}

function hasLabel(input) {
  if (input.id && document.querySelector(`label[for="${CSS.escape(input.id)}"]`)) return true;
  if (input.closest('label')) return true;
  if (input.getAttribute('aria-label') || input.getAttribute('aria-labelledby')) return true;
  return false;
}

function isGenericLabel(value) {
  return /^(ok|cancel|save|register|search|select|view|more|click|button|submit|next|go)$/i.test(value.trim());
}

function actionText(el) {
  return (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
}

function visibleAll(selector) {
  return [...document.querySelectorAll(selector)].filter(isVisible);
}

function collectElements() {
  return {
    buttons: visibleAll('button,[role="button"],input[type="button"],input[type="submit"]'),
    links: visibleAll('a[href]'),
    inputs: visibleAll('input,textarea,select'),
    imgs: visibleAll('img'),
    forms: visibleAll('form'),
    headings: visibleAll('h1,h2,h3,h4,h5,h6').map(el => ({ tag: el.tagName, text: el.innerText.trim().slice(0, 120) })),
  };
}

function findDuplicateIds() {
  const idCounts = [...document.querySelectorAll('[id]')].reduce((acc, el) => {
    acc[el.id] = (acc[el.id] || 0) + 1;
    return acc;
  }, {});
  return Object.entries(idCounts).filter(([, count]) => count > 1).map(([id, count]) => ({ id, count })).slice(0, 20);
}

function findOverflow() {
  return visibleAll('body *').map(el => {
    const rect = el.getBoundingClientRect();
    return rect.width > window.innerWidth + 2 ? { tag: el.tagName, cls: String(el.className || '').slice(0, 80), width: Math.round(rect.width) } : null;
  }).filter(Boolean).slice(0, 12);
}

function findSmallTargets(actions) {
  return actions.map(el => {
    const rect = el.getBoundingClientRect();
    return rect.width < 36 || rect.height < 32 ? { tag: el.tagName, text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 80), width: Math.round(rect.width), height: Math.round(rect.height) } : null;
  }).filter(Boolean).slice(0, 20);
}

function describeDocument(text, el) {
  return {
    title: document.title || '',
    lang: document.documentElement.lang || '',
    textSample: text.slice(0, 1200),
    textLength: text.length,
    h1: el.headings.filter(h => h.tag === 'H1').length,
    headings: el.headings,
    landmarks: {
      header: document.querySelectorAll('header').length,
      nav: document.querySelectorAll('nav').length,
      main: document.querySelectorAll('main').length,
      footer: document.querySelectorAll('footer').length,
    },
    counts: {
      buttons: el.buttons.length,
      links: el.links.length,
      inputs: el.inputs.length,
      forms: el.forms.length,
      images: el.imgs.length,
      scripts: document.scripts.length,
      stylesheets: document.querySelectorAll('link[rel="stylesheet"]').length,
      nodes: document.querySelectorAll('*').length,
    },
  };
}

function describeQuality(text, el) {
  const actions = [...el.buttons, ...el.links];
  const levels = el.headings.map(item => Number(item.tag.replace('H', '')));
  return {
    duplicateIds: findDuplicateIds(),
    genericActions: actions.map(actionText).filter(Boolean).filter(isGenericLabel).slice(0, 20),
    emptyActionText: actions.map(actionText).filter(value => value.length === 0).length,
    formsWithoutSubmit: el.forms.filter(form => ![...form.querySelectorAll('button,input[type="submit"],input[type="button"]')].some(isVisible)).length,
    headingSkips: levels.map((level, index) => index > 0 && level - levels[index - 1] > 1 ? `${levels[index - 1]}->${level}` : null).filter(Boolean),
    actionTexts: actions.map(actionText).filter(Boolean).slice(0, 30),
    hasSearch: el.inputs.some(input => /search/i.test(`${input.type || ''} ${input.name || ''} ${input.id || ''} ${input.placeholder || ''}`)),
    hasStatusRegion: Boolean(document.querySelector('[role="status"],[aria-live]')),
    hasDialogSemantics: Boolean(document.querySelector('[role="dialog"],dialog')),
    hasTable: Boolean(document.querySelector('table,[role="table"],[role="grid"]')),
    errorStateWords: /(error|invalid|required|failed)/i.test(text),
    emptyStateWords: /(empty|no data|no results)/i.test(text),
    unlabeledButtons: el.buttons.filter(b => !(b.innerText || b.value || b.getAttribute('aria-label') || b.getAttribute('title'))).length,
    deadLinks: el.links.filter(a => ['#', '', 'javascript:void(0)'].includes((a.getAttribute('href') || '').trim().toLowerCase())).length,
    unsafeBlankLinks: el.links.filter(a => a.target === '_blank' && !/noopener|noreferrer/i.test(a.rel || '')).length,
    unlabeledInputs: el.inputs.filter(input => !hasLabel(input)).length,
    missingImageAlt: el.imgs.filter(img => !img.getAttribute('alt')).length,
    passwordInputs: el.inputs.filter(input => input.type === 'password').map(input => ({ autocomplete: input.getAttribute('autocomplete') || '' })),
    overflow: findOverflow(),
    smallTargets: findSmallTargets(actions),
  };
}

function collectPerformance() {
  const resources = performance.getEntriesByType('resource');
  const nav = performance.getEntriesByType('navigation')[0];
  return {
    resourceCount: resources.length,
    resourceKinds: resources.reduce((acc, item) => {
      const key = item.initiatorType || 'other';
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {}),
    navTiming: nav ? {
      domContentLoaded: Math.round(nav.domContentLoadedEventEnd),
      loadEventEnd: Math.round(nav.loadEventEnd),
      transferSize: Math.round(nav.transferSize || 0),
    } : null,
  };
}

function collectViewportMetrics() {
  const text = document.body ? document.body.innerText.replace(/\s+/g, ' ').trim() : '';
  const el = collectElements();
  return { ...describeDocument(text, el), ...describeQuality(text, el), ...collectPerformance() };
}

const PAGE_HELPERS = [
  isVisible, hasLabel, isGenericLabel, actionText, visibleAll, collectElements, findDuplicateIds,
  findOverflow, findSmallTargets, describeDocument, describeQuality, collectPerformance, collectViewportMetrics,
];
const METRICS_SCRIPT = `(() => {\n${PAGE_HELPERS.map(String).join('\n\n')}\nreturn collectViewportMetrics();\n})()`;

// ---- Node-side inspection ---------------------------------------------------

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
  const metrics = await page.evaluate(METRICS_SCRIPT).catch(error => ({ error: error.message || String(error) }));
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

module.exports = { SCREENSHOTS_DIR, METRICS_SCRIPT, inspectViewport };

// Security / UX / functional / architecture findings derived from HTTP headers
// and the Playwright viewport inspection results.
const { addFinding } = require('./util');

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

module.exports = { analyzeHeaders, analyzeViewportResult };

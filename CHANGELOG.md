# Changelog

All notable changes to web-audit-kit. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Renamed the project from `testGpt7` to `web-audit-kit`.** `package.json` `name`,
  the startup log, the `/api/health` `name` field, the report footer, the email
  subject prefix/`From` default, and the MIME boundary all use the new name.
- **Environment variables are now `WEB_AUDIT_KIT_*`.** All configuration is read
  through a single `env(name)` helper in `lib/util.js`; the new name wins when
  both are set. `.env.example`, README, and SECURITY use the new names, and the
  target-guard / Playwright error messages point at them.
- **Translated the entire user-facing surface to English (i18n).** The web UI
  (`public/index.html`, `public/app.js`), all audit findings and scope/profile
  labels, and the Markdown / HTML / email reports now render in English. The HTML
  report uses `lang="en"` and an `en-US` timestamp.
- **Split the monolithic `server.js` (~1290 lines) into focused modules** under
  `lib/`, leaving `server.js` as HTTP routing, the audit orchestration, and
  test-facing re-exports:
  - `lib/util.js` — shared helpers (`bool`, `escapeHtml`, `severityWeight`,
    `addFinding`, `parseRecipients`).
  - `lib/targetGuard.js` — SSRF / target guard, private-IP classification, DNS
    pinning, and the guarded header fetch.
  - `lib/mail.js` — recipient parsing, MIME building, and the sendmail / SMTP
    transports.
  - `lib/analysis.js` — scope profile, scope planning, and header/viewport
    findings.
  - `lib/report.js` — Markdown / email-summary / HTML rendering and report
    persistence.
- **Broke up functions longer than 50 lines** via helper extraction, including
  `buildScopePlan`, `inspectViewport` (page-context metric collection +
  listener wiring), `analyzeViewportResult` (functional / design / architecture
  sub-analyzers), and `buildHtmlReport` (per-section renderers). Behavior is
  unchanged.
- **Split `lib/analysis.js` (508 lines) and `lib/report.js` (319 lines)** into
  cohesive modules; every previously exported symbol is still exported from its
  original module:
  - `lib/scope.js` — profile normalization, scope planning, profile findings.
  - `lib/findings.js` — header and viewport findings.
  - `lib/viewport.js` — Playwright viewport inspection and in-page metrics.
  - `lib/htmlReport.js` — standalone HTML report rendering.
- **Broke up the remaining functions longer than 50 lines**:
  `collectViewportMetrics` (in-page helpers, serialized together into one
  `page.evaluate` script), `createSmtpClient` (`readSmtpResponse`,
  `upgradeToTls`), `buildMarkdown` (per-section builders), and in
  `public/app.js` `renderReport` and `loadHistory`. Behavior is unchanged.

### Deprecated
- **`TESTGPT7_*` environment variables.** They are still read as a fallback when
  the matching `WEB_AUDIT_KIT_*` name is unset, and print a one-time warning per
  variable to stderr. They will be removed in a future major release.

### Security
- **Defense-in-depth escaping in report renderers.** Viewport width/height and
  the severity/area count numbers in the HTML report and the web UI now go
  through `escapeHtml`/`esc`, and the web UI's severity CSS class is reduced to
  letters (matching the HTML report's `severityClass`), so a tampered stored
  report can no longer break out of a `class` attribute.
- **Pinned DNS to close the SSRF rebinding gap.** The IP validated by
  `assertTargetAllowed` is reused as the connection pin so the socket connects to
  exactly the checked IP, preventing TOCTOU / DNS-rebinding re-resolution to a
  private address. Enforced on the initial request, every redirect hop, and
  Playwright subresource requests.
- **Hardened resource cleanup.** SMTP sockets are released on success and hard
  destroyed on failure; a half-open socket is destroyed on timeout instead of
  leaking; the browser is always closed in a `finally` block.
- **SMTP TLS now verifies certificates** (`rejectUnauthorized: true`) for direct
  TLS and STARTTLS connections.
- **Invalid JSON request bodies return `400`** instead of a generic server error.
- **Mail delivery fails closed on an unknown transport.** Any
  `WEB_AUDIT_KIT_MAIL_TRANSPORT` value other than `sendmail` / `smtp` (for example a
  typo such as `smpt`) is now skipped with `unknown mail transport` instead of
  silently falling through to sendmail.

### Tests
- Added `test/env.test.js` covering the `WEB_AUDIT_KIT_*` name, the legacy
  `TESTGPT7_*` fallback with its one-time warning, and precedence.
- Added an SSRF guard regression suite (`test/ssrf.test.js`) covering
  private/metadata/loopback blocking, IPv4-mapped IPv6 bypass prevention,
  non-http(s) rejection, and DNS-rebinding pin behavior.
- Added a pure-helper smoke suite (`test/smoke.test.js`) as a refactor safety net.
- Added offline behavioral suites for the `lib/` modules (no network, no new
  dependencies):
  - `test/report.test.js` — HTML report escaping of every target/user-controlled
    field (`<script>` / quote / attribute-breakout payloads, `<title>`, severity
    class), Markdown and email-summary structure.
  - `test/analysis.test.js` — profile normalization, scope-gate decisions,
    header and viewport findings on fixture data, verdict thresholds and scoring
    (desktop/mobile de-duplication, 0 floor).
  - `test/mail.test.js` — CR/LF header-injection hardening in
    subject/from/to, RFC 2047 encoding, MIME attachment folding, and the
    no-config / unknown-transport / missing-SMTP-host no-send gates.
  - `test/util.test.js` — `bool`, `escapeHtml`, `severityWeight`, `addFinding`,
    `parseRecipients` (CR/LF rejection, 20-recipient cap).
- Full suite: 58 passing.

# Changelog

All notable changes to web-audit-kit. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Renamed the project from `testGpt7` to `web-audit-kit`.** `package.json` `name`,
  the startup log, the `/api/health` `name` field, the report footer, the email
  subject prefix/`From` default, and the MIME boundary all use the new name. The
  `TESTGPT7_*` environment variables keep their prefix as a stable configuration
  contract.
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

### Security
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

### Tests
- Added an SSRF guard regression suite (`test/ssrf.test.js`) covering
  private/metadata/loopback blocking, IPv4-mapped IPv6 bypass prevention,
  non-http(s) rejection, and DNS-rebinding pin behavior.
- Added a pure-helper smoke suite (`test/smoke.test.js`) as a refactor safety net.
- Full suite: 14 passing.

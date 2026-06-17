# Contributing to web-audit-kit

Thanks for your interest!

## Development setup

```bash
npm install
npm run check       # syntax check all sources
npm test            # node --test (pure helpers + SSRF guard; no network needed)
npm start           # serves on the configured port
```

## Guidelines

- **Only audit sites you own or are authorized to test.**
- This tool fetches remote URLs, so the SSRF guard in `lib/targetGuard.js`
  (DNS pinning, redirect re-validation, private/reserved IP blocking) is
  security-critical — keep it intact and covered by tests.
- Run `npm run check` and `npm test` before opening a PR; describe what changed
  and how you verified it.

# Security Policy

testGpt7 is a local-first, non-invasive site audit tool.

## Supported Use

Use this tool only against systems you own or have explicit authorization to test.

The default configuration binds to `127.0.0.1`, disables mail delivery, ignores generated reports, and refuses non-loopback binding unless explicitly enabled.

## Shared or Hosted Deployments

Before exposing testGpt7 to a network, add your own:

- Authentication
- Target allowlist
- Rate limiting
- Access logs
- Network segmentation

If `HOST` is not loopback, audit target URLs require `TESTGPT7_TARGET_ALLOWLIST` unless `TESTGPT7_ALLOW_ANY_TARGET=true` is set.

Network-exposed deployments also block private/reserved IP ranges after DNS resolution by default. This protection is applied to the initial target URL, HTTP redirects, and Playwright subresource requests.

## Reporting Issues

Do not include credentials, private target URLs, generated reports, or screenshots in public issues.

For sensitive reports, contact the repository owner through a private channel.

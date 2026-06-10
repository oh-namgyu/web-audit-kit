// SSRF / target guard: host-binding safety, allowlist matching, private-IP
// classification, DNS pinning (closes the TOCTOU / rebinding gap), and the
// guarded HTTP fetch used for header analysis.
const http = require('http');
const https = require('https');
const net = require('net');
const dns = require('dns').promises;
const { bool } = require('./util');

const HOST = process.env.HOST || '127.0.0.1';
const TARGET_ALLOWLIST = String(process.env.TESTGPT7_TARGET_ALLOWLIST || '')
  .split(',')
  .map(item => item.trim().toLowerCase())
  .filter(Boolean);
const MAX_REDIRECTS = Number(process.env.TESTGPT7_MAX_REDIRECTS || 5);

function isLoopbackHost(host) {
  return ['127.0.0.1', 'localhost', '::1'].includes(String(host || '').toLowerCase());
}

function assertSafeHostBinding() {
  if (isLoopbackHost(HOST)) return;
  if (bool(process.env.TESTGPT7_ALLOW_NETWORK_EXPOSURE)) return;
  throw new Error(`Refusing to bind to ${HOST}. web-audit-kit is local-only by default. Set TESTGPT7_ALLOW_NETWORK_EXPOSURE=true only on a trusted network with your own access controls.`);
}

function hostnameMatchesAllowlist(hostname, rule) {
  const host = hostname.toLowerCase();
  if (rule === host) return true;
  if (rule.startsWith('*.')) return host.endsWith(rule.slice(1));
  return false;
}

function assertTargetHostAllowed(parsedUrl) {
  if (isLoopbackHost(HOST)) return;
  if (TARGET_ALLOWLIST.some(rule => hostnameMatchesAllowlist(parsedUrl.hostname, rule))) return;
  if (bool(process.env.TESTGPT7_ALLOW_ANY_TARGET)) return;
  throw new Error('Network-exposed mode requires TESTGPT7_TARGET_ALLOWLIST. Set TESTGPT7_ALLOW_ANY_TARGET=true only for a trusted, access-controlled deployment.');
}

function shouldBlockPrivateIps() {
  if (!isLoopbackHost(HOST)) return !bool(process.env.TESTGPT7_ALLOW_PRIVATE_TARGETS);
  return bool(process.env.TESTGPT7_BLOCK_PRIVATE_IPS);
}

function isPrivateIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    return a === 0
      || a === 10
      || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0)
      || (a === 198 && (b === 18 || b === 19))
      || a >= 224;
  }
  if (version === 6) {
    const normalized = ip.toLowerCase();
    if (normalized.startsWith('::ffff:')) return isPrivateIp(normalized.slice(7));
    return normalized === '::'
      || normalized === '::1'
      || normalized.startsWith('fc')
      || normalized.startsWith('fd')
      || /^fe[89ab][0-9a-f]:/.test(normalized) // link-local fe80::/10 (fe80–febf)
      || normalized.startsWith('fec0:');
  }
  return false;
}

async function resolveHostIps(hostname) {
  if (net.isIP(hostname)) return [hostname];
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return [...new Set(records.map(record => record.address))];
}

// Returns { ips, pinnedIp } when DNS was resolved and validated, else null.
// Callers pin their connection lookup to pinnedIp so the IP that passed the
// guard is exactly the IP the socket connects to (closes the TOCTOU / DNS
// rebinding gap where fetch/undici would re-resolve independently).
async function assertTargetAllowed(parsedUrl) {
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error('Only http/https URLs are supported');
  assertTargetHostAllowed(parsedUrl);
  if (!shouldBlockPrivateIps()) return null;
  const ips = await resolveHostIps(parsedUrl.hostname);
  const blocked = ips.filter(isPrivateIp);
  if (blocked.length) {
    throw new Error(`Target resolves to blocked private/reserved IP: ${parsedUrl.hostname} -> ${blocked.join(', ')}`);
  }
  if (!ips.length) {
    throw new Error(`Target did not resolve to any address: ${parsedUrl.hostname}`);
  }
  return { ips, pinnedIp: ips[0] };
}

// Builds a dns.lookup-shaped callback that always returns the already-validated
// pinnedIp, so http/https never re-resolves the hostname at connect time.
function pinnedLookup(pinnedIp) {
  const family = net.isIP(pinnedIp);
  return (hostname, options, callback) => {
    const cb = typeof options === 'function' ? options : callback;
    const opts = typeof options === 'function' ? {} : (options || {});
    if (opts.all) return cb(null, [{ address: pinnedIp, family }]);
    return cb(null, pinnedIp, family);
  };
}

async function normalizeUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) throw new Error('targetUrl is required');
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  const parsed = new URL(withScheme);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http/https URLs are supported');
  await assertTargetAllowed(parsed);
  parsed.hash = '';
  return parsed.toString();
}

function headersObject(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    out[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

// Single non-redirecting request pinned to pinnedIp (when provided). Pinning the
// dns.lookup of http/https guarantees the socket connects to the exact IP that
// passed assertTargetAllowed, while Host header and TLS SNI stay on the original
// hostname (so vhosts and certificate validation keep working).
function requestOnce(currentUrl, pinnedIp, signal, maxBytes = 4000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(currentUrl);
    const agent = parsed.protocol === 'https:' ? https : http;
    const options = {
      method: 'GET',
      headers: { 'user-agent': 'web-audit-kit', accept: '*/*' },
      signal,
    };
    if (pinnedIp) options.lookup = pinnedLookup(pinnedIp);
    let settled = false;
    const req = agent.request(currentUrl, options, res => {
      const chunks = [];
      let size = 0;
      const finish = () => {
        if (settled) return;
        settled = true;
        resolve({ status: res.statusCode || 0, headers: headersObject(res.headers), body: Buffer.concat(chunks).toString('utf8') });
      };
      res.on('data', chunk => {
        size += chunk.length;
        if (size <= maxBytes * 4) chunks.push(chunk);
        if (size > maxBytes * 8) res.destroy(); // cap how much of the body we buffer
      });
      res.on('end', finish);
      res.on('close', finish); // resolve even if we destroyed the stream early
      res.on('error', err => { if (!settled) { settled = true; reject(err); } });
    });
    req.on('error', err => { if (!settled) { settled = true; reject(err); } });
    req.end();
  });
}

async function fetchHeaders(targetUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  const redirectChain = [];
  let currentUrl = targetUrl;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      const parsed = new URL(currentUrl);
      const allow = await assertTargetAllowed(parsed);
      const res = await requestOnce(currentUrl, allow?.pinnedIp, controller.signal);
      const location = res.headers.location;
      if (res.status >= 300 && res.status < 400 && location) {
        const nextUrl = new URL(location, currentUrl).toString();
        await assertTargetAllowed(new URL(nextUrl));
        redirectChain.push({ status: res.status, from: currentUrl, to: nextUrl });
        currentUrl = nextUrl;
        continue;
      }
      return {
        ok: true,
        status: res.status,
        finalUrl: currentUrl,
        headers: res.headers,
        htmlPreview: res.body.slice(0, 4000),
        redirectChain,
      };
    }
    throw new Error(`Too many redirects; max ${MAX_REDIRECTS}`);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  HOST,
  isLoopbackHost,
  assertSafeHostBinding,
  hostnameMatchesAllowlist,
  isPrivateIp,
  resolveHostIps,
  assertTargetAllowed,
  pinnedLookup,
  shouldBlockPrivateIps,
  normalizeUrl,
  headersObject,
  requestOnce,
  fetchHeaders,
};

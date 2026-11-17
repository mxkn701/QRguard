// QRguard — Cloudflare Worker
//
// Worker drží API klíče a slouží jako proxy k reputačním službám.
// ZÁSADY SOUKROMÍ:
//  - Celá URL sem chodí JEN při rozbalování přesměrování. Jinak dostává jen
//    hashe (VirusTotal, Safe Browsing) nebo samotnou doménu (RDAP).
//  - Nic se neloguje (žádné console.log s daty, observability vypnuté).
//  - Všechna API volání jsou POST s JSON tělem, takže nic citlivého není v URL
//    požadavku (ty se v Cloudflare mohou objevit v metrikách).
//  - Nic se neodesílá do VirusTotalu ke skenování, kromě holé domény
//    „https://domena/“ a to jen na výslovné kliknutí.

import { SHORTENERS } from '../public/lists.js';
import { preview } from './preview.js';
import { isAuthorized, login, logout } from './auth.js';

const VT = 'https://www.virustotal.com/api/v3';
const SB = 'https://safebrowsing.googleapis.com/v5/hashes:search';
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self' data: blob:",
    "media-src 'self' blob:", "connect-src 'self'", "worker-src 'self'", "manifest-src 'self'",
    "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'", "object-src 'none'",
  ].join('; '),
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(self), microphone=(), geolocation=(), payment=(), usb=()',
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Strict-Transport-Security': 'max-age=31536000',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      let res;
      try {
        res = await handleApi(request, env, url.pathname);
      } catch (e) {
        res = json({ error: 'internal', message: String(e?.message || e).slice(0, 200) }, 500);
      }
      return withHeaders(res, { 'Cache-Control': 'no-store' });
    }
    return withHeaders(await env.ASSETS.fetch(request));
  },
};

function withHeaders(res, extra = {}) {
  const r = new Response(res.body, res);
  for (const [k, v] of Object.entries({ ...SECURITY_HEADERS, ...extra })) r.headers.set(k, v);
  return r;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function handleApi(request, env, path) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  // Same-origin only — žádný CORS, cizí weby API volat nemohou.
  const origin = request.headers.get('Origin');
  if (origin && origin !== new URL(request.url).origin) return json({ error: 'origin' }, 403);

  let body = {};
  try { body = await request.json(); } catch { /* prázdné tělo */ }

  if (path === '/api/login') return login(request, env, body, json);
  if (path === '/api/logout') return logout(json);

  if (!env.APP_PASSWORD && !env.APP_TOKEN) return json({ error: 'not_configured', message: 'Na serveru chybí APP_PASSWORD.' }, 503);
  if (!(await isAuthorized(request, env))) return json({ error: 'unauthorized' }, 401);

  switch (path) {
    case '/api/config': return json({ vt: !!env.VT_API_KEY, sb: !!env.SB_API_KEY, rdap: true, unroll: true, preview: !!env.BROWSER });
    case '/api/vt/url': return vtUrl(env, body);
    case '/api/vt/domain': return vtDomain(env, body);
    case '/api/vt/submit-domain': return vtSubmitDomain(env, body);
    case '/api/vt/analysis': return vtAnalysis(env, body);
    case '/api/sb': return safeBrowsing(env, body);
    case '/api/rdap': return rdap(body);
    case '/api/unroll': return unroll(body);
    case '/api/preview': return previewApi(env, body);
    default: return json({ error: 'not_found' }, 404);
  }
}

// ---------------- VirusTotal ----------------

async function vtFetch(env, path, init = {}) {
  if (!env.VT_API_KEY) return { status: 503, data: { error: 'not_configured' } };
  const r = await fetch(VT + path, { ...init, headers: { 'x-apikey': env.VT_API_KEY, ...(init.headers || {}) } });
  let data = null;
  try { data = await r.json(); } catch { /* ignore */ }
  return { status: r.status, data };
}

function vtStatusError(status) {
  if (status === 429) return json({ error: 'rate_limited', message: 'Vyčerpán limit VirusTotalu (free: 4 dotazy/min, 500/den).' }, 429);
  if (status === 401 || status === 403) return json({ error: 'vt_auth', message: 'Neplatný VirusTotal API klíč.' }, 502);
  if (status === 503) return json({ error: 'not_configured' }, 503);
  return json({ error: 'vt_error', status }, 502);
}

// Vstup: { ids: [sha256 hex, ...] } — žádná URL.
async function vtUrl(env, { ids }) {
  if (!Array.isArray(ids) || !ids.length || ids.length > 3 || !ids.every((x) => /^[0-9a-f]{64}$/.test(x))) {
    return json({ error: 'bad_request' }, 400);
  }
  for (const id of ids) {
    const r = await vtFetch(env, `/urls/${id}`);
    if (r.status === 404) continue;
    if (r.status !== 200) return vtStatusError(r.status);
    const a = r.data?.data?.attributes || {};
    return json({
      found: true,
      id,
      stats: a.last_analysis_stats || null,
      lastAnalysis: a.last_analysis_date || null,
      reputation: a.reputation ?? null,
      categories: Object.values(a.categories || {}).slice(0, 4),
      engines: Object.entries(a.last_analysis_results || {})
        .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
        .slice(0, 8).map(([k, v]) => `${k}: ${v.result}`),
    });
  }
  return json({ found: false });
}

// Vstup: { domain } — jen registrovatelná doména, bez subdomén a cesty.
async function vtDomain(env, { domain }) {
  domain = String(domain || '').toLowerCase();
  if (!DOMAIN_RE.test(domain)) return json({ error: 'bad_request' }, 400);
  const r = await vtFetch(env, `/domains/${domain}`);
  if (r.status === 404) return json({ found: false });
  if (r.status !== 200) return vtStatusError(r.status);
  const a = r.data?.data?.attributes || {};
  return json({
    found: true,
    stats: a.last_analysis_stats || null,
    reputation: a.reputation ?? null,
    created: a.creation_date || null,
    categories: Object.values(a.categories || {}).slice(0, 4),
  });
}

// Odešle ke skenu POUZE „https://domena/“ — server sám skládá URL, klient nemůže poslat cestu.
async function vtSubmitDomain(env, { domain }) {
  domain = String(domain || '').toLowerCase();
  if (!DOMAIN_RE.test(domain)) return json({ error: 'bad_request' }, 400);
  const form = new URLSearchParams({ url: `https://${domain}/` });
  const r = await vtFetch(env, '/urls', {
    method: 'POST', body: form, headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  if (r.status !== 200) return vtStatusError(r.status);
  return json({ analysisId: r.data?.data?.id || null });
}

async function vtAnalysis(env, { id }) {
  if (!/^[A-Za-z0-9=_-]{8,200}$/.test(String(id || ''))) return json({ error: 'bad_request' }, 400);
  const r = await vtFetch(env, `/analyses/${id}`);
  if (r.status !== 200) return vtStatusError(r.status);
  const a = r.data?.data?.attributes || {};
  return json({ status: a.status, stats: a.stats || null });
}

// ---------------- Google Safe Browsing v5 ----------------

// Vstup: { prefixes: [base64 4 bajty] } — Google uvidí jen prefixy hashů.
async function safeBrowsing(env, { prefixes }) {
  if (!env.SB_API_KEY) return json({ error: 'not_configured' }, 503);
  if (!Array.isArray(prefixes) || !prefixes.length || prefixes.length > 30 ||
      !prefixes.every((p) => /^[A-Za-z0-9+/]{6}==$/.test(p))) {
    return json({ error: 'bad_request' }, 400);
  }
  const q = new URLSearchParams({ key: env.SB_API_KEY });
  for (const p of prefixes) q.append('hashPrefixes', p);
  const r = await fetch(`${SB}?${q}`);
  if (r.status === 429) return json({ error: 'rate_limited' }, 429);
  if (!r.ok) return json({ error: 'sb_error', status: r.status }, 502);
  // v5 odpovídá jen protobufem (JSON nepodporuje)
  const data = decodeSearchHashesResponse(new Uint8Array(await r.arrayBuffer()));
  return json({ fullHashes: data });
}

// ---------------- minimální protobuf dekodér pro SearchHashesResponse ----------------
// SearchHashesResponse { repeated FullHash full_hashes = 1; Duration cache_duration = 2; }
// FullHash { bytes full_hash = 1; repeated FullHashDetail full_hash_details = 2; }
// FullHashDetail { ThreatType threat_type = 1; repeated ThreatAttribute attributes = 2; }

const SB_THREAT_TYPES = { 1: 'MALWARE', 2: 'SOCIAL_ENGINEERING', 3: 'UNWANTED_SOFTWARE', 4: 'POTENTIALLY_HARMFUL_APPLICATION' };

function* pbFields(buf) {
  let i = 0;
  const varint = () => {
    let v = 0, shift = 0, b;
    do {
      if (i >= buf.length) throw new Error('protobuf: truncated');
      b = buf[i++];
      v += (b & 0x7f) * 2 ** shift;
      shift += 7;
    } while (b & 0x80);
    return v;
  };
  while (i < buf.length) {
    const key = varint();
    const field = Math.floor(key / 8), wire = key & 7;
    if (wire === 0) yield { field, value: varint() };
    else if (wire === 2) {
      const len = varint();
      if (i + len > buf.length) throw new Error('protobuf: truncated');
      yield { field, bytes: buf.subarray(i, i + len) };
      i += len;
    } else if (wire === 1) i += 8;
    else if (wire === 5) i += 4;
    else throw new Error('protobuf: unsupported wire type');
  }
}

function decodeSearchHashesResponse(buf) {
  const out = [];
  for (const f of pbFields(buf)) {
    if (f.field !== 1 || !f.bytes) continue;
    let hash = null;
    const threats = [];
    for (const g of pbFields(f.bytes)) {
      if (g.field === 1 && g.bytes) hash = g.bytes;
      else if (g.field === 2 && g.bytes) {
        for (const d of pbFields(g.bytes)) {
          if (d.field === 1 && d.value != null) threats.push(SB_THREAT_TYPES[d.value] || `THREAT_${d.value}`);
        }
      }
    }
    if (hash && hash.length === 32) out.push({ fullHash: btoa(String.fromCharCode(...hash)), threats });
  }
  return out;
}

// ---------------- RDAP (stáří domény) ----------------

// Seznam RDAP serverů podle TLD přímo od IANA — doménu tak uvidí jen registr dané koncovky.
let bootstrap = null;
let bootstrapAt = 0;
async function rdapBase(tld) {
  if (!bootstrap || Date.now() - bootstrapAt > 86400000) {
    const r = await fetch('https://data.iana.org/rdap/dns.json', { headers: { 'User-Agent': UA } });
    if (!r.ok) throw new Error('bootstrap ' + r.status);
    const d = await r.json();
    bootstrap = new Map();
    for (const [tlds, urls] of d.services || []) {
      const url = urls.find((u) => u.startsWith('https://')) || urls[0];
      for (const t of tlds) bootstrap.set(t.toLowerCase(), url.endsWith('/') ? url : url + '/');
    }
    bootstrapAt = Date.now();
  }
  return bootstrap.get(tld) || null;
}

const UA = 'Mozilla/5.0 (compatible; QRguard/1.0)';

async function rdap({ domain }) {
  domain = String(domain || '').toLowerCase();
  if (!DOMAIN_RE.test(domain)) return json({ error: 'bad_request' }, 400);
  const base = await rdapBase(domain.split('.').pop());
  if (!base) return json({ error: 'rdap_unsupported', message: 'Registr této koncovky RDAP nepodporuje.' }, 502);
  const r = await fetch(`${base}domain/${domain}`, {
    headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': UA },
    redirect: 'follow',
  });
  if (r.status === 404) return json({ found: false });
  if (!r.ok) return json({ error: 'rdap_error', status: r.status }, 502);
  const d = await r.json();
  const ev = (name) => (d.events || []).find((e) => e.eventAction === name)?.eventDate || null;
  const registrar = (d.entities || []).find((e) => (e.roles || []).includes('registrar'));
  const fn = registrar?.vcardArray?.[1]?.find((x) => x[0] === 'fn')?.[3] || registrar?.handle || null;
  return json({ found: true, created: ev('registration'), expires: ev('expiration'), registrar: fn });
}

// ---------------- Bezpečný náhled ----------------

async function previewApi(env, { url }) {
  let u;
  try { u = new URL(String(url)); } catch { return json({ error: 'bad_request' }, 400); }
  if (!['http:', 'https:'].includes(u.protocol) || isPrivateHost(u.hostname)) return json({ error: 'bad_request' }, 400);
  const r = await preview(env, u.href, isPrivateHost);
  if (r.error) return json(r, r.error === 'rate_limited' ? 429 : 502);
  return json(r);
}

// ---------------- Rozbalení přesměrování ----------------

function isPrivateHost(host) {
  host = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host.includes('.') && !host.includes(':')) return true;
  if (/(^|\.)(localhost|local|internal|lan|home|arpa|test|invalid)$/.test(host)) return true;
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (host.includes(':')) return host === '::1' || /^(fc|fd|fe80)/.test(host) || host.startsWith('::ffff:');
  return false;
}

// Vstup: { url, mode: 'shorteners' | 'all' }
//  - 'shorteners': navštíví jen hopy na známých zkracovačích. Na cílový web se nepřipojí,
//    takže nespotřebuje jednorázové odkazy (přihlašovací, reset hesla, vstupenky...).
//  - 'all': projde všechna přesměrování (uživatel to musí výslovně potvrdit).
async function unroll({ url, mode }) {
  mode = mode === 'all' ? 'all' : 'shorteners';
  let current;
  try { current = new URL(String(url)); } catch { return json({ error: 'bad_request' }, 400); }
  const chain = [];
  let stopped = null;

  for (let hop = 0; hop < 10; hop++) {
    if (!['http:', 'https:'].includes(current.protocol)) { stopped = 'scheme'; break; }
    if (isPrivateHost(current.hostname)) { stopped = 'private'; break; }
    if (mode === 'shorteners' && !SHORTENERS.has(current.hostname.toLowerCase())) { stopped = 'not_shortener'; break; }

    let r;
    try {
      r = await fetch(current.href, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 14) QRguard/1.0', Accept: 'text/html,*/*' },
        signal: AbortSignal.timeout(8000),
      });
    } catch (e) {
      chain.push({ url: current.href, status: 0 });
      stopped = 'network';
      break;
    }
    const loc = r.headers.get('Location');
    chain.push({ url: current.href, status: r.status });

    let next = null;
    if (r.status >= 300 && r.status < 400 && loc) {
      next = new URL(loc, current);
    } else if (r.ok && (r.headers.get('Content-Type') || '').includes('text/html')) {
      // Dynamické QR služby často přesměrovávají přes <meta http-equiv="refresh">.
      const html = (await readLimited(r, 65536));
      const meta = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)/i);
      if (meta) next = new URL(meta[1].replace(/&amp;/g, '&'), current);
    }
    try { r.body?.cancel(); } catch { /* ignore */ }

    if (!next) { stopped = 'final'; break; }
    current = next;
    if (hop === 9) stopped = 'too_many';
  }
  return json({ chain, final: current.href, stopped });
}

async function readLimited(res, max) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < max) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  try { await reader.cancel(); } catch { /* ignore */ }
  const all = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { all.set(c, o); o += c.length; }
  return new TextDecoder().decode(all.slice(0, max));
}

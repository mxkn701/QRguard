// Síťové pomocníky: rozpoznání soukromých adres (ochrana proti SSRF) a klíč pro omezení pokusů.

const PRIVATE_NAME = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|arpa|test|invalid|example)$/;

/** Je to soukromá / rezervovaná IPv4? */
function privateV4(a, b, c) {
  return a === 0 || a === 10 || a === 127 || a >= 224 ||           // „this“, privátní, loopback, multicast + rezervované
    (a === 100 && b >= 64 && b <= 127) ||                          // CGNAT
    (a === 169 && b === 254) ||                                    // link-local (metadata cloudů)
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||               // IETF, TEST-NET-1
    (a === 198 && (b === 18 || b === 19)) ||                        // benchmark
    (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113); // TEST-NET-2/3
}

/** Rozbalí IPv6 na 8 čísel (nebo null). Podporuje „::“ i vloženou IPv4 na konci. */
export function expandV6(ip) {
  ip = ip.replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (!ip.includes(':')) return null;
  let tail = [];
  const v4 = ip.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const p = v4[2].split('.').map(Number);
    if (p.some((x) => x > 255)) return null;
    tail = [(p[0] << 8) | p[1], (p[2] << 8) | p[3]];
    ip = v4[1].endsWith('::') ? v4[1] : v4[1].slice(0, -1);
  }
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const parse = (s) => (s ? s.split(':').map((h) => (/^[0-9a-f]{1,4}$/.test(h) ? parseInt(h, 16) : NaN)) : []);
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  const fill = 8 - head.length - rest.length - tail.length;
  if (halves.length === 1 && fill !== 0) return null;
  if (fill < 0 || [...head, ...rest].some(Number.isNaN)) return null;
  return [...head, ...Array(halves.length === 2 ? fill : 0).fill(0), ...rest, ...tail];
}

/** Je IP adresa (v4 nebo v6) soukromá / rezervovaná? */
export function isPrivateIp(ip) {
  const m = String(ip).match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) return privateV4(+m[1], +m[2], +m[3]);
  const w = expandV6(String(ip));
  if (!w) return true; // nesrozumitelné = raději zablokovat
  if (w.every((x) => x === 0)) return true;                                   // ::
  if (w.slice(0, 7).every((x) => x === 0) && w[7] === 1) return true;          // ::1
  if (w.slice(0, 5).every((x) => x === 0) && (w[5] === 0xffff || w[5] === 0)) {  // ::ffff:a.b.c.d, ::a.b.c.d
    return privateV4(w[6] >> 8, w[6] & 255, w[7] >> 8);
  }
  if (w[0] === 0x64 && w[1] === 0xff9b) return privateV4(w[6] >> 8, w[6] & 255, w[7] >> 8); // NAT64
  if ((w[0] & 0xfe00) === 0xfc00) return true;   // fc00::/7 unique local
  if ((w[0] & 0xffc0) === 0xfe80) return true;   // fe80::/10 link-local
  if ((w[0] & 0xffc0) === 0xfec0) return true;   // fec0::/10 site-local (zastaralé)
  if ((w[0] & 0xff00) === 0xff00) return true;   // multicast
  if (w[0] === 0x2001 && w[1] === 0x0db8) return true; // dokumentace
  if (w[0] === 0x2002) return privateV4(w[1] >> 8, w[1] & 255, w[2] >> 8); // 6to4
  return false;
}

/** Soukromý název nebo IP (bez DNS dotazu). */
export function isPrivateHost(host) {
  host = String(host).replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!host) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) return isPrivateIp(host);
  if (!host.includes('.')) return true;
  return PRIVATE_NAME.test(host);
}

// DNS přes HTTPS (Cloudflare 1.1.1.1): zjistí, kam název skutečně vede, aby
// „interni.example.com → 10.0.0.5“ neprošlo. Krátká cache v rámci instance.
const dnsCache = new Map();
async function resolve(host, type) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
    headers: { Accept: 'application/dns-json' },
    signal: AbortSignal.timeout(4000),
  });
  if (!r.ok) throw new Error('dns ' + r.status);
  const d = await r.json();
  return (d.Answer || []).filter((a) => a.type === (type === 'A' ? 1 : 28)).map((a) => a.data);
}

/** true = název nebo kterákoliv jeho adresa je soukromá. Chyba DNS ≠ soukromé (cíl se pak stejně nenačte). */
export async function resolvesPrivate(host) {
  host = String(host).replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (isPrivateHost(host)) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) return false;
  const hit = dnsCache.get(host);
  if (hit && hit.until > Date.now()) return hit.priv;
  let priv = false;
  try {
    const [a, aaaa] = await Promise.all([resolve(host, 'A'), resolve(host, 'AAAA').catch(() => [])]);
    priv = [...a, ...aaaa].some((ip) => isPrivateIp(ip));
  } catch { /* DNS nedostupné */ }
  if (dnsCache.size > 500) dnsCache.clear();
  dnsCache.set(host, { priv, until: Date.now() + 60_000 });
  return priv;
}

/** Klíč pro omezení pokusů: IPv4 celá, IPv6 jen síť /64 (jinak by útočník jen měnil adresy). */
export function clientKey(ip) {
  ip = String(ip || '').trim();
  const w = expandV6(ip);
  if (w) return 'v6:' + w.slice(0, 4).map((x) => x.toString(16)).join(':');
  return 'v4:' + (ip || 'unknown');
}

/** Načte tělo požadavku nejvýš do `max` bajtů (jinak null). */
export async function readBodyLimited(request, max) {
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > max) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > max) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { all.set(c, o); o += c.length; }
  return new TextDecoder().decode(all);
}

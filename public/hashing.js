// Hashování URL tak, aby celá adresa nikdy neopustila telefon.
//
// - Google Safe Browsing v5: posíláme jen 4bajtové prefixy SHA-256 hashů
//   (k-anonymita — stejný prefix sdílí obrovské množství URL). Plné hashy,
//   které Google vrátí, porovnáme lokálně.
// - VirusTotal: posíláme SHA-256 hash URL (API ho přijímá jako identifikátor).
//   Neznámou tajnou URL z hashe nikdo nezrekonstruuje.

// ---------- pomocné funkce nad "binárními" řetězci (1 znak = 1 bajt) ----------

function binToBytes(s) {
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
  return b;
}

function utf8ToBin(s) {
  let out = '';
  for (const byte of new TextEncoder().encode(s)) out += String.fromCharCode(byte);
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// ---------- kanonizace podle Google Safe Browsing ----------

function unescapeRepeatedly(s) {
  for (let i = 0; i < 1024; i++) {
    const next = s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    if (next === s) return s;
    s = next;
  }
  return s;
}

function sbEscape(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f || c === 0x23 /* # */ || c === 0x25 /* % */) {
      out += '%' + c.toString(16).toUpperCase().padStart(2, '0');
    } else {
      out += s[i];
    }
  }
  return out;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Vrátí {host, path, query|null} kanonizované dle Safe Browsing, nebo null. */
export function sbCanonicalize(input) {
  let raw = String(input).replace(/[\t\r\n]/g, '').trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = 'http://' + raw;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

  // URL API už převedlo IDN na punycode, normalizovalo IP a vyřešilo /./ a /../.
  let host = unescapeRepeatedly(u.hostname);
  host = host.replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.').toLowerCase();

  let path = unescapeRepeatedly(u.pathname || '/');
  path = path.replace(/\/{2,}/g, '/');
  // opětovné vyřešení /./ a /../ po odescapování
  const segs = [];
  for (const seg of path.split('/').slice(1)) {
    if (seg === '.') continue;
    if (seg === '..') { segs.pop(); continue; }
    segs.push(seg);
  }
  path = '/' + segs.join('/');

  const query = u.search ? unescapeRepeatedly(u.search.slice(1)) : (u.href.split('#')[0].includes('?') ? '' : null);

  return {
    host: sbEscape(host),
    path: sbEscape(path),
    query: query === null ? null : sbEscape(query),
  };
}

/** Kombinace host-suffix × path-prefix (max. 30), viz Safe Browsing "URLs and Hashing". */
export function sbExpressions(input) {
  const c = sbCanonicalize(input);
  if (!c) return [];

  const hosts = [c.host];
  if (!IPV4.test(c.host) && !c.host.startsWith('[')) {
    const parts = c.host.split('.');
    const last5 = parts.slice(-5);
    for (let i = last5.length === parts.length ? 1 : 0; i <= last5.length - 2; i++) {
      const h = last5.slice(i).join('.');
      if (!hosts.includes(h)) hosts.push(h);
      if (hosts.length >= 5) break;
    }
  }

  const paths = [];
  if (c.query !== null) paths.push(c.path + '?' + c.query);
  paths.push(c.path);
  const comps = c.path.split('/').slice(1, -1); // bez posledního segmentu
  let prefix = '/';
  if (!paths.includes(prefix)) paths.push(prefix);
  for (const comp of comps.slice(0, 3)) {
    prefix += comp + '/';
    if (paths.length >= 6) break;
    if (!paths.includes(prefix)) paths.push(prefix);
  }

  const out = [];
  for (const h of hosts) for (const p of paths) out.push(h + p);
  return out.slice(0, 30);
}

/** Pro Safe Browsing: {expressions:[{expr, fullHashB64}], prefixesB64:[...]} */
export async function sbHashes(input) {
  const exprs = sbExpressions(input);
  const items = [];
  for (const expr of exprs) {
    const full = await sha256(binToBytes(expr));
    items.push({ expr, fullHashB64: toBase64(full), prefixB64: toBase64(full.slice(0, 4)) });
  }
  return { items, prefixesB64: [...new Set(items.map((i) => i.prefixB64))] };
}

// ---------- VirusTotal ----------

/** Varianty, jak mohl VirusTotal URL kanonizovat; vrací SHA-256 v hex. */
export async function vtUrlIds(input) {
  const variants = new Set();
  const trimmed = String(input).trim();
  variants.add(trimmed);
  try {
    const u = new URL(trimmed);
    u.hash = '';
    const base = u.protocol + '//' + u.host + (u.pathname || '/') + u.search;
    variants.add(base);
    variants.add(u.href);
  } catch { /* nevalidní URL — zkusíme jen syrovou podobu */ }
  const ids = [];
  for (const v of variants) ids.push(toHex(await sha256(new TextEncoder().encode(v))));
  return [...new Set(ids)].slice(0, 3);
}

export { utf8ToBin };

// Lokální (offline) analýza obsahu QR kódu. Nic neodesílá.
import {
  SHORTENERS, TRUSTED_SHORTENERS, MULTI_SUFFIXES, FREE_HOSTING, ABUSED_TLDS, BRANDS,
  SHORT_BRANDS, PHISHY_WORDS, DANGEROUS_EXTENSIONS, CZ_BANKS,
} from './lists.js';

// Úrovně nálezů: danger > warn > info > ok
const f = (level, text) => ({ level, text });

// ---------------- Punycode (RFC 3492) — jen dekódování pro zobrazení ----------------

function punyDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const out = [];
  let b = input.lastIndexOf('-');
  if (b < 0) b = 0;
  for (let j = 0; j < b; j++) out.push(input.charCodeAt(j));
  const adapt = (delta, numPoints, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) throw new Error('bad punycode');
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit >= base) throw new Error('bad punycode');
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

export function decodeHost(host) {
  return host.split('.').map((l) => {
    if (!l.startsWith('xn--')) return l;
    try { return punyDecode(l.slice(4)); } catch { return l; }
  }).join('.');
}

function scriptsOf(s) {
  const scripts = new Set();
  for (const ch of s) {
    if (/[a-z]/i.test(ch)) scripts.add('latin');
    else if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add('cyrillic');
    else if (/\p{Script=Greek}/u.test(ch)) scripts.add('greek');
    else if (/\p{Script=Latin}/u.test(ch)) scripts.add('latin'); // diakritika
    else if (/[\p{L}]/u.test(ch)) scripts.add('other');
  }
  return scripts;
}

// ---------------- Domény ----------------

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function registrableDomain(host) {
  host = host.toLowerCase().replace(/\.$/, '');
  if (IPV4.test(host) || host.startsWith('[')) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  for (let n = Math.min(4, parts.length - 1); n >= 2; n--) {
    const suffix = parts.slice(-n).join('.');
    if (MULTI_SUFFIXES.has(suffix) || FREE_HOSTING.has(suffix)) {
      return parts.slice(-(n + 1)).join('.');
    }
  }
  return parts.slice(-2).join('.');
}

function freeHostingSuffix(host) {
  const parts = host.split('.');
  for (let n = Math.min(4, parts.length - 1); n >= 2; n--) {
    const s = parts.slice(-n).join('.');
    if (FREE_HOSTING.has(s)) return s;
  }
  return null;
}

function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

// Převede typické záměny znaků na "kostru" (paypa1 → paypal, rn → m, cyrilice → latinka).
function skeleton(s) {
  const map = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
    'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ⅼ': 'l', 'ı': 'i', 'ο': 'o', 'α': 'a', 'ν': 'v', 'κ': 'k' };
  let out = '';
  for (const ch of s.toLowerCase().normalize('NFKD').replace(/\p{M}/gu, '')) out += map[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[il]/g, 'l').replace(/-/g, '');
}

function isOfficial(registrable, list) {
  return list.some((d) => registrable === d);
}

function brandChecks(host, registrable, pathAndQuery) {
  const out = [];
  const decoded = decodeHost(host);
  const regDecoded = decodeHost(registrable);
  const regLabel = regDecoded.split('.')[0];
  const subLabels = decoded.slice(0, Math.max(0, decoded.length - regDecoded.length - 1))
    .split('.').filter(Boolean);
  const seen = new Set();
  const tokens = (s) => s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const regTokens = tokens(regLabel);
  const subTokens = subLabels.flatMap(tokens);
  const pathTokens = tokens(pathAndQuery);
  const phishy = PHISHY_WORDS.some((w) => pathTokens.includes(w) || regTokens.includes(w) || subTokens.includes(w));

  for (const [brand, official] of Object.entries(BRANDS)) {
    if (isOfficial(registrable, official) || seen.size) continue;
    // 1) značka jako samostatné slovo v doméně: paypal-secure.com, apple-id.net
    if (regLabel !== brand && regTokens.includes(brand)) {
      out.push(f('danger', `Doména „${regDecoded}“ obsahuje název „${brand}“, ale není to oficiální doména (${official[0]}).`));
      seen.add(brand); continue;
    }
    // 1b) značka slepená s dalším textem: paypalverify.com — jen spolu s "přihlašovacími"
    //     slovy, jinak by to chytalo náhody jako pineapple.com
    if (phishy && regLabel !== brand && regLabel.includes(brand) && brand.length >= 5) {
      out.push(f('danger', `Doména „${regDecoded}“ obsahuje „${brand}“, ale oficiální doména je ${official[0]}.`));
      seen.add(brand); continue;
    }
    // 2) podobná doména: paypa1.com, pаypal.com (cyrilice), rnicrosoft.com
    if (regLabel !== brand && brand.length >= 5) {
      const sk = skeleton(regLabel);
      if (sk === skeleton(brand)) {
        out.push(f('danger', `Doména „${regDecoded}“ napodobuje značku „${brand}“ (${official[0]}) záměnou znaků. Typický trik podvodníků.`));
        seen.add(brand); continue;
      }
      if (brand.length >= 6 && levenshtein(sk, skeleton(brand)) === 1) {
        out.push(f(phishy ? 'danger' : 'warn', `Doména „${regDecoded}“ se nápadně podobá „${brand}“ (${official[0]}).`));
        seen.add(brand); continue;
      }
    }
    // 3) značka v subdoméně: paypal.com.evil.net, login-paypal.evil.net
    if (subTokens.includes(brand)) {
      out.push(f('danger', `Značka „${brand}“ je jen v subdoméně — skutečná doména je „${regDecoded}“.`));
      seen.add(brand); continue;
    }
    // 4) značka v cestě spolu s "přihlašovacími" slovy: evil.com/paypal/login
    if (phishy && pathTokens.includes(brand)) {
      out.push(f('warn', `Adresa zmiňuje „${brand}“, ale vede na „${regDecoded}“, ne na ${official[0]}.`));
      seen.add(brand);
    }
  }
  if (!seen.size) {
    for (const [brand, official] of Object.entries(SHORT_BRANDS)) {
      if (isOfficial(registrable, official)) continue;
      if (subLabels.includes(brand)) {
        out.push(f('danger', `Subdoména „${brand}“ napodobuje ${official[0]} — skutečná doména je „${regDecoded}“.`));
        break;
      }
    }
  }
  return out;
}

// ---------------- Analýza URL ----------------

export function looksLikeSecret(u) {
  const names = /^(token|access_token|auth|key|apikey|api_key|secret|sig|signature|code|session|sid|password|pass|pwd|otp|ticket|invite|magic|reset)$/i;
  for (const [k, v] of u.searchParams) {
    if (names.test(k) && v.length >= 6) return true;
    if (v.length >= 24 && /^[A-Za-z0-9_\-.~+/=]+$/.test(v) && /\d/.test(v) && /[a-zA-Z]/.test(v)) return true;
  }
  return u.pathname.split('/').some((s) => s.length >= 24 && /^[A-Za-z0-9_\-]+$/.test(s) && /\d/.test(s) && /[a-zA-Z]/.test(s));
}

export function analyzeUrl(raw) {
  const findings = [];
  let u;
  try { u = new URL(raw); } catch { return { findings: [f('danger', 'Neplatná adresa.')], url: null }; }

  const host = u.hostname.toLowerCase();
  const registrable = registrableDomain(host);
  const decodedHost = decodeHost(host);
  const tld = host.split('.').pop();
  const pathAndQuery = decodeURIComponentSafe(u.pathname + u.search);

  if (u.protocol === 'http:') findings.push(f('warn', 'Nešifrované spojení (http) — obsah lze cestou podvrhnout nebo odposlechnout.'));
  if (u.username || u.password) {
    findings.push(f('danger', `Adresa obsahuje „@“ — vše před ním je jen maskování. Skutečný cíl je „${decodedHost}“.`));
  }
  if (IPV4.test(host) || host.startsWith('[')) {
    findings.push(f('danger', 'Místo domény je použita přímo IP adresa — legitimní služby to dělají jen výjimečně.'));
  }
  if (u.port && !['80', '443'].includes(u.port)) {
    findings.push(f('warn', `Nestandardní port ${u.port}.`));
  }
  if (host.split('.').some((l) => l.startsWith('xn--'))) {
    const scripts = scriptsOf(decodedHost.replace(/\./g, ''));
    const mixed = scripts.size > 1;
    findings.push(f(mixed ? 'danger' : 'warn',
      `Doména používá mezinárodní znaky: „${decodedHost}“${mixed ? ' — míchá různá písma (např. latinku s cyrilicí), což je klasický podvod.' : '.'}`));
  }
  findings.push(...brandChecks(host, registrable, pathAndQuery));

  const fh = freeHostingSuffix(host);
  if (fh) findings.push(f('warn', `Stránka běží na „${fh}“ — tam si web může zdarma založit kdokoliv.`));

  if (SHORTENERS.has(host)) {
    findings.push(TRUSTED_SHORTENERS.has(host)
      ? f('info', `Zkrácený odkaz (${host}) — skutečný cíl se zjistí rozbalením.`)
      : f('warn', `Zkracovač / dynamický QR (${host}) skrývá skutečný cíl.`));
  }
  if (ABUSED_TLDS.has(tld)) findings.push(f('warn', `Koncovka „.${tld}“ je často zneužívaná podvodníky.`));

  const sub = host.split('.').length - registrable.split('.').length;
  if (sub >= 3) findings.push(f('warn', `Neobvykle mnoho subdomén (${sub}).`));
  if (raw.length > 300) findings.push(f('info', `Velmi dlouhá adresa (${raw.length} znaků).`));

  const ext = (u.pathname.split('/').pop() || '').split('.').slice(1).pop()?.toLowerCase();
  if (ext && DANGEROUS_EXTENSIONS.danger.includes(ext)) {
    findings.push(f('danger', `Odkaz stahuje spustitelný soubor (.${ext}). ${ext === 'apk' ? 'Instalace aplikací mimo Google Play je nejčastější způsob, jak se do telefonu dostane malware.' : ''}`.trim()));
  } else if (ext && DANGEROUS_EXTENSIONS.warn.includes(ext)) {
    findings.push(f('warn', `Odkaz vede na soubor .${ext}.`));
  }

  const lowerPQ = pathAndQuery.toLowerCase();
  const words = PHISHY_WORDS.filter((w) => new RegExp(`(^|[^a-z])${w}([^a-z]|$)`).test(lowerPQ) || host.includes(w));
  if (words.length) findings.push(f('info', `Obsahuje slova typická pro phishing: ${words.slice(0, 4).join(', ')}.`));

  for (const [k, v] of u.searchParams) {
    if (/^(url|redirect|redirect_uri|redir|next|target|dest|destination|goto|link|return|returnurl|continue|u|r)$/i.test(k) && /^https?:\/\//i.test(v)) {
      try {
        const inner = new URL(v);
        if (registrableDomain(inner.hostname) !== registrable) {
          findings.push(f('warn', `Odkaz přesměrovává jinam: „${decodeHost(inner.hostname)}“.`));
        }
      } catch { /* ignore */ }
      break;
    }
  }

  if (looksLikeSecret(u)) {
    findings.push(f('info', 'Adresa zřejmě obsahuje osobní/tajný token. Celá URL proto neopouští telefon — služby dostanou jen hash.'));
  }

  return { findings, url: u, host, registrable, decodedHost, isShortener: SHORTENERS.has(host) };
}

function decodeURIComponentSafe(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

// ---------------- IBAN / QR Platba ----------------

export function validIban(iban) {
  const s = iban.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
  const re = (s.slice(4) + s.slice(0, 4)).replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let mod = 0;
  for (const ch of re) mod = (mod * 10 + Number(ch)) % 97;
  return mod === 1;
}

export function czAccountFromIban(iban) {
  const s = iban.replace(/\s+/g, '').toUpperCase();
  if (!s.startsWith('CZ') || s.length !== 24) return null;
  const bank = s.slice(4, 8);
  const prefix = s.slice(8, 14).replace(/^0+/, '');
  const number = s.slice(14).replace(/^0+/, '');
  return { text: `${prefix ? prefix + '-' : ''}${number}/${bank}`, bank, bankName: CZ_BANKS[bank] || null };
}

function parseSpd(text) {
  const fields = {};
  for (const part of text.split('*').slice(2)) {
    const i = part.indexOf(':');
    if (i > 0) fields[part.slice(0, i).toUpperCase()] = part.slice(i + 1);
  }
  return fields;
}

// ---------------- Klasifikace obsahu ----------------

function splitEsc(s, sep) {
  // WIFI: formát používá \ jako escape
  const out = []; let cur = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && i + 1 < s.length) { cur += s[++i]; continue; }
    if (s[i] === sep) { out.push(cur); cur = ''; continue; }
    cur += s[i];
  }
  out.push(cur);
  return out;
}

function premiumCz(num) {
  const n = num.replace(/[^\d+]/g, '').replace(/^(\+|00)420/, '');
  return /^90[0-9]/.test(n) || /^976/.test(n);
}

export function extractUrls(text) {
  return [...new Set((text.match(/https?:\/\/[^\s<>"'`]+/gi) || []).map((s) => s.replace(/[),.;:!?]+$/, '')))].slice(0, 5);
}

/**
 * Hlavní vstup: vrátí {kind, title, details:[[label, value]], findings, url?, links?}
 */
export function classify(rawText) {
  const text = String(rawText ?? '');
  const t = text.trim();
  const details = [];
  const findings = [];
  const res = (kind, title, extra = {}) => ({ kind, title, details, findings, raw: text, ...extra });

  if (!t) return res('empty', 'Prázdný kód');

  const scheme = (t.match(/^([a-z][a-z0-9+.-]*):/i)?.[1] || '').toLowerCase();

  // --- nebezpečná schémata ---
  if (['javascript', 'vbscript', 'data', 'file', 'blob', 'jar', 'filesystem', 'chrome', 'about'].includes(scheme)) {
    findings.push(f('danger', `Schéma „${scheme}:“ může spustit kód nebo otevřít lokální data. Neotvírej.`));
    return res('dangerous', 'Nebezpečný obsah');
  }
  if (scheme === 'intent' || scheme === 'market' || t.startsWith('intent://')) {
    findings.push(f('danger', 'Android „intent“ odkaz — může přímo spouštět aplikace nebo instalace.'));
    const fb = t.match(/S\.browser_fallback_url=([^;]+)/);
    if (fb) details.push(['Záložní URL', decodeURIComponentSafe(fb[1])]);
    return res('dangerous', 'Odkaz na aplikaci');
  }

  // --- URL ---
  let urlText = null;
  if (scheme === 'http' || scheme === 'https') urlText = t;
  else if (!scheme && /^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/\S*)?$/i.test(t) && !/\s/.test(t)) urlText = 'https://' + t;
  if (urlText) {
    const a = analyzeUrl(urlText);
    findings.push(...a.findings);
    if (a.url) {
      details.push(['Doména', a.decodedHost]);
      if (a.decodedHost !== a.host) details.push(['Doména (punycode)', a.host]);
    }
    return res('url', 'Webový odkaz', { url: a.url ? a.url.href : null, analysis: a });
  }

  // --- Wi-Fi ---
  if (/^WIFI:/i.test(t)) {
    const fields = {};
    for (const p of splitEsc(t.slice(5), ';')) {
      const i = p.indexOf(':');
      if (i > 0) fields[p.slice(0, i).toUpperCase()] = p.slice(i + 1);
    }
    details.push(['Síť (SSID)', fields.S || '—']);
    details.push(['Zabezpečení', fields.T || 'žádné']);
    if (fields.P) details.push(['Heslo', '•'.repeat(Math.min(fields.P.length, 12)) + ' (skryto)']);
    if (!fields.T || /^nopass$/i.test(fields.T)) findings.push(f('warn', 'Otevřená síť bez hesla — provoz může kdokoliv v okolí odposlouchávat.'));
    else if (/^WEP$/i.test(fields.T)) findings.push(f('warn', 'Zastaralé zabezpečení WEP, lze prolomit během minut.'));
    if (fields.H === 'true') findings.push(f('info', 'Skrytá síť.'));
    findings.push(f('info', 'Falešné Wi‑Fi sítě (např. „Free_WiFi“) slouží k odposlechu. Připoj se jen pokud víš, čí síť je.'));
    return res('wifi', 'Wi‑Fi síť', { wifi: fields });
  }

  // --- QR Platba (SPD) ---
  if (/^SPD\*1\.0\*/i.test(t)) {
    const p = parseSpd(t);
    const acc = (p.ACC || '').split('+')[0];
    const czAcc = czAccountFromIban(acc);
    details.push(['Účet (IBAN)', acc || '—']);
    if (czAcc) details.push(['Číslo účtu', `${czAcc.text}${czAcc.bankName ? ' (' + czAcc.bankName + ')' : ''}`]);
    if (p.AM) details.push(['Částka', `${p.AM} ${p.CC || 'CZK'}`]);
    if (p['X-VS']) details.push(['Variabilní symbol', p['X-VS']]);
    if (p['X-SS']) details.push(['Specifický symbol', p['X-SS']]);
    if (p.RN) details.push(['Příjemce', p.RN]);
    if (p.MSG) details.push(['Zpráva', p.MSG]);
    if (p.DT) details.push(['Splatnost', p.DT]);
    if (acc && !validIban(acc)) findings.push(f('danger', 'IBAN nemá platný kontrolní součet — kód je poškozený nebo podvržený.'));
    if (!p.AM) findings.push(f('info', 'Kód neobsahuje částku — vyplníš ji ručně.'));
    findings.push(f('warn', 'Před odesláním porovnej číslo účtu s fakturou nebo jiným zdrojem. Podvodníci přelepují QR kódy (parkovací automaty, faktury).'));
    return res('payment', 'QR Platba');
  }

  // --- EPC / SEPA QR ---
  if (/^BCD\r?\n/.test(t)) {
    const l = t.split(/\r?\n/);
    details.push(['Příjemce', l[5] || '—']);
    details.push(['IBAN', l[6] || '—']);
    if (l[7]) details.push(['Částka', l[7].replace(/^([A-Z]{3})(.*)$/, '$2 $1')]);
    if (l[9] || l[10]) details.push(['Zpráva', l[9] || l[10]]);
    if (l[6] && !validIban(l[6])) findings.push(f('danger', 'IBAN nemá platný kontrolní součet — kód je poškozený nebo podvržený.'));
    findings.push(f('warn', 'Před platbou porovnej příjemce a IBAN s jiným zdrojem.'));
    return res('payment', 'SEPA platba');
  }

  // --- 2FA ---
  if (scheme === 'otpauth') {
    try {
      const u = new URL(t);
      details.push(['Typ', u.hostname.toUpperCase()]);
      details.push(['Účet', decodeURIComponentSafe(u.pathname.slice(1))]);
      if (u.searchParams.get('issuer')) details.push(['Vydavatel', u.searchParams.get('issuer')]);
    } catch { /* ignore */ }
    findings.push(f('warn', 'Obsahuje tajný klíč pro dvoufázové ověření. Přidej ho jen pokud si 2FA právě nastavuješ ty sám — a kód nikomu neukazuj.'));
    return res('otp', 'Dvoufázové ověření (2FA)');
  }

  // --- kryptoměny ---
  if (['bitcoin', 'ethereum', 'litecoin', 'monero', 'dogecoin', 'bitcoincash', 'solana', 'tron', 'usdt'].includes(scheme)) {
    const body = t.slice(scheme.length + 1);
    const [addr, q] = body.split('?');
    details.push(['Měna', scheme]);
    details.push(['Adresa', addr.replace(/^\/\//, '')]);
    const amt = new URLSearchParams(q || '').get('amount') || new URLSearchParams(q || '').get('value');
    if (amt) details.push(['Částka', amt]);
    findings.push(f('warn', 'Platby kryptoměnou nejdou vrátit. Ověř adresu jinou cestou — QR kódy s adresami se často podvrhují.'));
    return res('crypto', 'Kryptoměnová platba');
  }

  // --- telefon / SMS ---
  if (scheme === 'tel') {
    const num = t.slice(4);
    details.push(['Číslo', num]);
    if (premiumCz(num)) findings.push(f('danger', 'Prémiové (zpoplatněné) číslo — hovor může být velmi drahý.'));
    else if (/^\+(?!420|421)/.test(num.replace(/\s/g, ''))) findings.push(f('warn', 'Zahraniční číslo — hovor může být zpoplatněn.'));
    return res('tel', 'Telefonní číslo');
  }
  if (scheme === 'sms' || scheme === 'smsto' || scheme === 'mms' || scheme === 'mmsto') {
    const body = t.slice(scheme.length + 1);
    let num, msg;
    if (scheme.endsWith('to')) [num, ...msg] = body.split(':'), msg = msg.join(':');
    else { [num, msg] = body.split('?'); msg = new URLSearchParams(msg || '').get('body') || ''; }
    details.push(['Číslo', num]);
    if (msg) details.push(['Text zprávy', msg]);
    if (premiumCz(num)) findings.push(f('danger', 'Prémiová SMS — odeslání může stát desítky až stovky korun.'));
    else if (/^\d{3,6}$/.test(num.replace(/\s/g, ''))) findings.push(f('warn', 'Krátké číslo — často jde o placené služby.'));
    return res('sms', 'SMS zpráva');
  }
  if (scheme === 'mailto' || /^MATMSG:/i.test(t)) {
    details.push(['E‑mail', t.replace(/^mailto:/i, '').split('?')[0]]);
    findings.push(f('info', 'Otevře e‑mail. Zkontroluj adresáta i text, než ho odešleš.'));
    return res('mail', 'E‑mail');
  }
  if (scheme === 'geo') {
    details.push(['Souřadnice', t.slice(4).split('?')[0]]);
    return res('geo', 'Poloha na mapě');
  }

  // --- vizitka / událost ---
  const links = extractUrls(t);
  if (/^BEGIN:VCARD/i.test(t)) {
    const fn = t.match(/^FN[^:]*:(.*)$/im)?.[1];
    const tel = t.match(/^TEL[^:]*:(.*)$/im)?.[1];
    const email = t.match(/^EMAIL[^:]*:(.*)$/im)?.[1];
    if (fn) details.push(['Jméno', fn]);
    if (tel) details.push(['Telefon', tel]);
    if (email) details.push(['E‑mail', email]);
    return res('vcard', 'Kontakt (vizitka)', { links });
  }
  if (/^MECARD:/i.test(t)) {
    const n = t.match(/N:([^;]*)/)?.[1];
    if (n) details.push(['Jméno', n]);
    return res('vcard', 'Kontakt (vizitka)', { links });
  }
  if (/^BEGIN:(VEVENT|VCALENDAR)/i.test(t)) {
    const s = t.match(/^SUMMARY[^:]*:(.*)$/im)?.[1];
    if (s) details.push(['Událost', s]);
    return res('event', 'Událost v kalendáři', { links });
  }

  if (scheme && !['http', 'https'].includes(scheme) && /^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    findings.push(f('warn', `Odkaz otevře aplikaci přes schéma „${scheme}:“.`));
    return res('app', 'Odkaz do aplikace', { links });
  }

  if (links.length) findings.push(f('info', `Text obsahuje ${links.length === 1 ? 'odkaz' : 'odkazy'} — můžeš ${links.length === 1 ? 'ho' : 'je'} zkontrolovat.`));
  return res('text', 'Text', { links });
}

/** Spojí lokální a online nálezy do výsledného verdiktu. */
export function verdict(findings) {
  if (findings.some((x) => x.level === 'danger')) return 'danger';
  if (findings.some((x) => x.level === 'warn')) return 'warn';
  return 'ok';
}

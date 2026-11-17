// Přihlášení heslem + podepsaná session cookie.
//
// - Heslo je uložené jen jako Cloudflare secret APP_PASSWORD.
// - Po přihlášení dostane zařízení cookie platnou SESSION_DAYS dní:
//   HttpOnly (JavaScript ji nepřečte), Secure, SameSite=Strict (cizí weby ji nepošlou).
// - Cookie je podepsaná NÁHODNÝM klíčem uloženým v Durable Objectu (src/guard.js),
//   ne klíčem odvozeným z hesla, takže z ukradené cookie nejde heslo hádat offline.
//   Klíč je svázaný s heslem: změna hesla vygeneruje nový klíč a odhlásí všechna zařízení.
// - Pokusy o přihlášení počítá Durable Object přesně a globálně (viz LIMITS v guard.js).

import { clientKey } from './net.js';

const COOKIE = 'qrg_session';
const SESSION_DAYS = 90;
export const MIN_PASSWORD = 12;
const enc = new TextEncoder();

function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

function guard(env) {
  return env.LOGIN_GUARD.get(env.LOGIN_GUARD.idFromName('global'));
}

// Podpisový klíč se v rámci instance Workeru drží v paměti, ať se Durable Object neptáme při každém požadavku.
let keyCache = { fp: null, key: null };
async function sessionKey(env) {
  const fp = b64url(await sha256('qrguard-fp-v2:' + env.APP_PASSWORD));
  if (keyCache.fp === fp) return keyCache.key;
  const secret = await guard(env).sessionSecret(fp);
  const raw = Uint8Array.from(atob(secret), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  keyCache = { fp, key };
  return key;
}

async function sign(env, payload) {
  return b64url(await crypto.subtle.sign('HMAC', await sessionKey(env), enc.encode(payload)));
}

export async function timingSafeEqual(a, b) {
  const [x, y] = await Promise.all([sha256(String(a)), sha256(String(b))]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

function readCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function cookieHeader(value, maxAge) {
  return `${COOKIE}=${value}; Path=/api; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function passwordUsable(env) {
  return typeof env.APP_PASSWORD === 'string' && env.APP_PASSWORD.length >= MIN_PASSWORD;
}

/** Je požadavek přihlášený? (platná cookie, nebo Bearer APP_TOKEN pro skripty) */
export async function isAuthorized(request, env) {
  if (passwordUsable(env) && env.LOGIN_GUARD) {
    const c = readCookie(request, COOKIE);
    const m = c && c.match(/^v2\.(\d{10})\.([A-Za-z0-9_-]{43})$/);
    if (m && Number(m[1]) > Date.now() / 1000 && (await timingSafeEqual(m[2], await sign(env, 'v2.' + m[1])))) {
      return true;
    }
  }
  if (typeof env.APP_TOKEN === 'string' && env.APP_TOKEN.length >= 32) {
    const auth = request.headers.get('Authorization') || '';
    if (auth.startsWith('Bearer ') && (await timingSafeEqual(auth.slice(7), env.APP_TOKEN))) return true;
  }
  return false;
}

export async function login(request, env, body, json) {
  if (!env.APP_PASSWORD) return json({ error: 'not_configured', message: 'Na serveru chybí APP_PASSWORD.' }, 503);
  if (!passwordUsable(env)) {
    // Krátké heslo by šlo uhodnout — přihlášení raději vůbec nepovolit.
    return json({ error: 'weak_password', message: `Heslo na serveru je příliš krátké (min. ${MIN_PASSWORD} znaků). Nastav delší: npm run setup` }, 503);
  }
  if (!env.LOGIN_GUARD) {
    // Bez počítadla pokusů by šlo heslo hádat bez omezení — raději odmítnout.
    return json({ error: 'not_configured', message: 'Na serveru chybí LOGIN_GUARD (Durable Object). Nasaď znovu: npm run deploy' }, 503);
  }

  const client = clientKey(request.headers.get('CF-Connecting-IP') || 'local');
  const g = guard(env);
  const gate = await g.attempt(client);
  if (!gate.ok) {
    const min = Math.max(1, Math.ceil(gate.retryAfter / 60));
    const res = json({ error: 'rate_limited', message: `Příliš mnoho pokusů o přihlášení. Zkus to za ${min} min.` }, 429);
    res.headers.set('Retry-After', String(gate.retryAfter));
    return res;
  }

  const password = typeof body?.password === 'string' ? body.password : '';
  if (!password || !(await timingSafeEqual(password, env.APP_PASSWORD))) {
    await new Promise((r) => setTimeout(r, 500));
    return json({ error: 'bad_password', message: 'Špatné heslo.' }, 401);
  }

  await g.success(client);
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  const value = `v2.${exp}.${await sign(env, 'v2.' + exp)}`;
  const res = json({ ok: true, days: SESSION_DAYS });
  res.headers.append('Set-Cookie', cookieHeader(value, SESSION_DAYS * 86400));
  return res;
}

export function logout(json) {
  const res = json({ ok: true });
  res.headers.append('Set-Cookie', cookieHeader('', 0));
  return res;
}

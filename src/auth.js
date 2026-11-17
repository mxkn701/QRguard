// Přihlášení heslem + podepsaná session cookie.
//
// - Heslo je uložené jen jako Cloudflare secret APP_PASSWORD.
// - Po přihlášení dostane zařízení cookie platnou SESSION_DAYS dní:
//   HttpOnly (JavaScript ji nepřečte), Secure, SameSite=Strict (cizí weby ji nepošlou).
// - Cookie je podepsaná HMAC klíčem odvozeným z hesla, takže změna hesla
//   okamžitě odhlásí všechna zařízení.

const COOKIE = 'qrg_session';
const SESSION_DAYS = 90;
const enc = new TextEncoder();

function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sessionKey(env) {
  const material = await crypto.subtle.digest('SHA-256', enc.encode('qrguard-session-v1:' + env.APP_PASSWORD));
  return crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function sign(env, payload) {
  return b64url(await crypto.subtle.sign('HMAC', await sessionKey(env), enc.encode(payload)));
}

export async function timingSafeEqual(a, b) {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b))),
  ]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
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

/** Je požadavek přihlášený? (platná cookie, nebo Bearer APP_TOKEN pro skripty) */
export async function isAuthorized(request, env) {
  if (env.APP_PASSWORD) {
    const c = readCookie(request, COOKIE);
    const m = c && c.match(/^v1\.(\d{10})\.([A-Za-z0-9_-]{43})$/);
    if (m && Number(m[1]) > Date.now() / 1000 && (await timingSafeEqual(m[2], await sign(env, 'v1.' + m[1])))) {
      return true;
    }
  }
  if (env.APP_TOKEN) {
    const auth = request.headers.get('Authorization') || '';
    if (auth.startsWith('Bearer ') && (await timingSafeEqual(auth.slice(7), env.APP_TOKEN))) return true;
  }
  return false;
}

export async function login(request, env, body, json) {
  if (!env.APP_PASSWORD) return json({ error: 'not_configured', message: 'Na serveru chybí APP_PASSWORD.' }, 503);
  if (env.APP_PASSWORD.length < 8) {
    // Krátké heslo se dá uhodnout i přes omezení pokusů — raději přihlášení vůbec nepovolit.
    return json({ error: 'weak_password', message: 'Heslo na serveru je příliš krátké (min. 8 znaků). Nastav delší: npm run setup' }, 503);
  }

  // Omezení pokusů: jen přibližné a po lokalitách Cloudflare, proto k tomu i zpoždění
  // po chybném hesle. Hlavní ochranou je dostatečně dlouhé heslo.
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  try {
    if (env.LOGIN_LIMITER && !(await env.LOGIN_LIMITER.limit({ key: 'login:' + ip })).success) {
      return json({ error: 'rate_limited', message: 'Příliš mnoho pokusů. Zkus to za minutu.' }, 429);
    }
  } catch { /* limiter nedostupný — pokračujeme se zpožděním */ }

  const password = typeof body?.password === 'string' ? body.password : '';
  if (!password || !(await timingSafeEqual(password, env.APP_PASSWORD))) {
    await new Promise((r) => setTimeout(r, 1000));
    return json({ error: 'bad_password', message: 'Špatné heslo.' }, 401);
  }

  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  const value = `v1.${exp}.${await sign(env, 'v1.' + exp)}`;
  const res = json({ ok: true, days: SESSION_DAYS });
  res.headers.append('Set-Cookie', cookieHeader(value, SESSION_DAYS * 86400));
  return res;
}

export function logout(json) {
  const res = json({ ok: true });
  res.headers.append('Set-Cookie', cookieHeader('', 0));
  return res;
}

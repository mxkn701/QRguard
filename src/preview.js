// „Bezpečný náhled“: otevře odkaz v izolovaném Chrome u Cloudflare (Browser Rendering)
// a vrátí snímek obrazovky + co stránka dělala. Případný útok proběhne tam, ne v telefonu.
//
// Soukromí: celou adresu vidí jen tento Worker, prohlížeč Cloudflare a cílový web.
// Nic se neukládá ani nezveřejňuje. Spouští se jen na výslovné kliknutí.

import puppeteer from '@cloudflare/puppeteer';

const MOBILE_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';

const RISKY_MIME = {
  'application/vnd.android.package-archive': 'apk',
  'application/x-msdownload': 'exe',
  'application/x-msdos-program': 'exe',
  'application/x-msi': 'msi',
  'application/x-apple-aspen-config': 'mobileconfig',
  'application/java-archive': 'jar',
  'application/x-sh': 'sh',
  'application/x-bat': 'bat',
  'application/zip': 'zip',
  'application/x-zip-compressed': 'zip',
  'application/x-rar-compressed': 'rar',
  'application/vnd.rar': 'rar',
  'application/x-7z-compressed': '7z',
  'application/x-iso9660-image': 'iso',
  'application/octet-stream': 'bin',
};

// Skript vložený do stránky ještě před jejím načtením — zaznamená, o co se stránka pokouší.
// Žádosti o oprávnění „naoko“ odmítne, takže stránka nic nezíská.
//
// Události se neukládají do stránky (tam by je stránka mohla smazat), ale hned se posílají
// ven přes CDP binding. Skript si binding schová do proměnné a z window ho smaže dřív,
// než se spustí jakýkoliv skript stránky, takže stránka nemůže nic podvrhnout ani zamést.
const probe = (binding) => `(() => {
  const send = window[${JSON.stringify(binding)}];
  try { delete window[${JSON.stringify(binding)}]; } catch {}
  if (typeof send !== 'function') return;
  let n = 0;
  const log = (type, detail) => { try { if (n++ < 50) send(JSON.stringify({ type, detail: String(detail || '').slice(0, 200) })); } catch {} };
  const deny = () => Promise.reject(new DOMException('denied', 'NotAllowedError'));
  try { if (window.Notification) { Notification.requestPermission = () => { log('notifications'); return Promise.resolve('denied'); }; } } catch {}
  try { if (window.PushManager) PushManager.prototype.subscribe = function () { log('push'); return deny(); }; } catch {}
  try { const g = navigator.geolocation; if (g) { g.getCurrentPosition = (s, e) => { log('geolocation'); e && e({ code: 1, message: 'denied' }); }; g.watchPosition = (s, e) => { log('geolocation'); e && e({ code: 1, message: 'denied' }); return 0; }; } } catch {}
  try { if (navigator.mediaDevices) navigator.mediaDevices.getUserMedia = (c) => { log(c && c.video ? 'camera' : 'microphone'); return deny(); }; } catch {}
  try { if (navigator.clipboard) { navigator.clipboard.writeText = (t) => { log('clipboard-write', t); return Promise.resolve(); }; navigator.clipboard.readText = () => { log('clipboard-read'); return deny(); }; } } catch {}
  try { const ec = document.execCommand.bind(document); document.execCommand = (c, ...a) => { if (/^(copy|cut)$/i.test(c)) log('clipboard-write', String(getSelection())); return ec(c, ...a); }; } catch {}
  try { const o = window.open; window.open = (u) => { log('popup', u); return null; }; } catch {}
  try { if (navigator.credentials) navigator.credentials.get = () => { log('credentials'); return deny(); }; } catch {}
  try { if (navigator.share) navigator.share = (d) => { log('share', d && d.url); return deny(); }; } catch {}
  try { const c = URL.createObjectURL; URL.createObjectURL = (b) => { if (b && b.size > 10000) log('blob', (b.type || '?') + ' ' + b.size + ' B'); return c(b); }; } catch {}
  try { const click = HTMLAnchorElement.prototype.click; HTMLAnchorElement.prototype.click = function () { if (this.hasAttribute('download')) log('download-link', (this.getAttribute('download') || '') + ' ' + this.href); return click.call(this); }; } catch {}
  try { if (window.PaymentRequest) window.PaymentRequest = function () { log('payment-request'); throw new DOMException('denied', 'NotAllowedError'); }; } catch {}
  try { window.addEventListener('beforeunload', () => log('beforeunload')); } catch {}
})();`;

export async function preview(env, targetUrl, isPrivateHost) {
  if (!env.BROWSER) return { error: 'not_configured', message: 'Na serveru chybí Browser Rendering.' };

  let browser;
  try {
    browser = await puppeteer.launch(env.BROWSER);
  } catch (e) {
    const msg = String(e?.message || e);
    if (/429|rate|limit/i.test(msg)) return { error: 'rate_limited', message: 'Limit izolovaného prohlížeče: nový náhled jde spustit nejdřív za 20 s, celkem cca 10 minut denně.' };
    return { error: 'browser_error', message: 'Prohlížeč se nepodařilo spustit.' };
  }

  const navigations = [];
  const downloads = [];
  const blocked = [];
  let mainStatus = null;

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 390, height: 780, deviceScaleFactor: 1, isMobile: true, hasTouch: true });
    await page.setUserAgent(MOBILE_UA);

    // Kanál pro události ze stránky (viz probe) — jméno je náhodné pro každý náhled.
    const events = [];
    const binding = '__qrg_' + crypto.getRandomValues(new Uint32Array(2)).join('');
    const cdp = await page.target().createCDPSession();
    await cdp.send('Runtime.enable'); // bez toho CDP nedoručuje události bindingCalled
    await cdp.send('Runtime.addBinding', { name: binding });
    cdp.on('Runtime.bindingCalled', (e) => {
      if (e.name !== binding || events.length >= 50) return;
      try {
        const d = JSON.parse(e.payload);
        events.push({ type: String(d.type).slice(0, 40), detail: String(d.detail || '').slice(0, 200) });
      } catch { /* ignore */ }
    });
    await page.evaluateOnNewDocument(probe(binding));

    // Zabránit přístupu do vnitřních sítí a zbytečným velkým přenosům.
    await page.setRequestInterception(true);
    page.on('request', async (req) => {
      try {
        if (['media', 'font'].includes(req.resourceType())) return req.abort('blockedbyclient');
        const u = new URL(req.url());
        // Kontrola i přes DNS: „interni.example.com → 10.0.0.5“ se taky zablokuje.
        if ((u.protocol === 'http:' || u.protocol === 'https:') && (await isPrivateHost(u.hostname))) {
          blocked.push(u.hostname);
          return req.abort('blockedbyclient');
        }
        return req.continue();
      } catch { /* data:, blob:, nebo už vyřízený požadavek */ }
      try { await req.continue(); } catch { /* ignore */ }
    });

    page.on('response', (res) => {
      try {
        const headers = res.headers();
        const ct = (headers['content-type'] || '').split(';')[0].trim().toLowerCase();
        const cd = headers['content-disposition'] || '';
        const url = res.url();
        const isAttachment = /attachment/i.test(cd);
        const fname = (cd.match(/filename\*?=(?:UTF-8'')?"?([^";]+)/i)?.[1] || '').slice(0, 120);
        const extFromName = fname.split('.').pop()?.toLowerCase();
        const ext = RISKY_MIME[ct] || (isAttachment ? extFromName : null);
        if ((isAttachment || (RISKY_MIME[ct] && res.request().resourceType() === 'document')) && downloads.length < 5) {
          downloads.push({ url: url.slice(0, 300), type: ct || '?', ext: ext || extFromName || '?', filename: decodeSafe(fname) });
        }
        if (res.request().isNavigationRequest() && res.request().frame() === page.mainFrame()) {
          navigations.push({ url: url.slice(0, 500), status: res.status() });
          mainStatus = res.status();
        }
      } catch { /* ignore */ }
    });

    let loadError = null;
    try {
      await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 15000 });
    } catch (e) {
      loadError = String(e?.message || e).slice(0, 160);
    }
    // Chvíli počkat na opožděné přesměrování / žádosti o oprávnění.
    await new Promise((r) => setTimeout(r, 2500));

    // Prohlídka stránky v izolovaném světě: sdílí DOM, ale ne JavaScript stránky,
    // takže stránka nemůže podvrhnout querySelectorAll, getBoundingClientRect apod.
    let info = {};
    try {
      const { frameTree } = await cdp.send('Page.getFrameTree');
      const { executionContextId } = await cdp.send('Page.createIsolatedWorld', { frameId: frameTree.frame.id, worldName: 'qrguard-inspect' });
      const r = await cdp.send('Runtime.evaluate', {
        expression: `(${INSPECT})()`, contextId: executionContextId, returnByValue: true, timeout: 3000,
      });
      info = sanitizeInfo(r.result?.value);
    } catch { /* stránka mohla mezitím odejít */ }

    let screenshot = null;
    try {
      const img = await page.screenshot({ type: 'jpeg', quality: 55, fullPage: false });
      screenshot = 'data:image/jpeg;base64,' + toBase64(img);
    } catch { /* např. když stránka okamžitě spustila stahování */ }

    return {
      finalUrl: page.url(),
      status: mainStatus,
      navigations: navigations.slice(0, 12),
      downloads,
      blocked: [...new Set(blocked)].slice(0, 5),
      loadError: downloads.length && loadError && /ERR_ABORTED/.test(loadError) ? null : loadError,
      screenshot,
      ...info,
      events: events.slice(0, 30),
    };
  } finally {
    try { await browser.close(); } catch { /* ignore */ }
  }
}

// Běží v izolovaném světě stránky. Je to text (ne funkce), aby do něj bundler nevložil
// pomocné volání (např. __name), které v prohlížeči neexistuje.
const INSPECT = String.raw`function () {
  const q = (s) => [...document.querySelectorAll(s)];
  const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
  const fieldText = (el) => [el.name, el.id, el.placeholder, el.autocomplete, el.getAttribute('aria-label')].join(' ').toLowerCase();
  const inputs = q('input').filter(visible);
  const formHosts = q('form[action]').map((f) => { try { return new URL(f.getAttribute('action') || '', location.href).hostname; } catch { return null; } }).filter(Boolean);
  return {
    title: String(document.title).slice(0, 200),
    passwordFields: inputs.filter((i) => i.type === 'password').length,
    cardFields: inputs.filter((i) => /cc-|card|karty|karta|cvv|cvc|expir|platnost/.test(fieldText(i))).length,
    otpFields: inputs.filter((i) => /otp|one-time|sms|kod|code|pin/.test(fieldText(i)) && i.type !== 'password').length,
    loginLike: inputs.some((i) => /email|login|user|jmeno|username|phone|telefon/.test(fieldText(i) + ' ' + i.type)),
    formHosts: [...new Set(formHosts)].slice(0, 5),
    iframes: q('iframe').length,
    textSample: (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').slice(0, 400),
  };
}`;

// Výsledek z prohlížeče je pořád „cizí“ — ověřit typy, než ho pošleme do appky.
function sanitizeInfo(v) {
  if (!v || typeof v !== 'object') return {};
  const num = (x) => (Number.isFinite(x) ? Math.max(0, Math.min(999, Math.floor(x))) : 0);
  const str = (x, n) => (typeof x === 'string' ? x.slice(0, n) : '');
  return {
    title: str(v.title, 200),
    passwordFields: num(v.passwordFields),
    cardFields: num(v.cardFields),
    otpFields: num(v.otpFields),
    loginLike: v.loginLike === true,
    formHosts: Array.isArray(v.formHosts) ? v.formHosts.filter((h) => typeof h === 'string').map((h) => h.slice(0, 253)).slice(0, 5) : [],
    iframes: num(v.iframes),
    textSample: str(v.textSample, 400),
  };
}

function decodeSafe(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function toBase64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) s += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(s);
}

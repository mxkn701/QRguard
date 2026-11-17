import { classify, analyzeUrl, verdict, registrableDomain, decodeHost } from './analyze.js';
import { sbHashes, vtUrlIds } from './hashing.js';
import { BRANDS, SHORT_BRANDS, DANGEROUS_EXTENSIONS } from './lists.js';

const $ = (s) => document.querySelector(s);

// ---------------- nastavení (jen lokálně v telefonu) ----------------

const DEFAULTS = { sb: true, vt: true, rdap: true, unroll: true };
function loadSettings() {
  try {
    const { sb, vt, rdap, unroll } = { ...DEFAULTS, ...JSON.parse(localStorage.getItem('qrguard.settings') || '{}') };
    localStorage.removeItem('qrh.settings'); // starý formát s tokenem
    return { sb, vt, rdap, unroll };
  } catch { return { ...DEFAULTS }; }
}
function saveSettings(s) {
  try { localStorage.setItem('qrguard.settings', JSON.stringify(s)); } catch { /* private mode */ }
}
let settings = loadSettings();
let serverConfig = null; // {vt, sb, rdap, unroll}

// ---------------- DOM helper (vždy textContent, nikdy innerHTML s daty) ----------------

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// ---------------- API ----------------

async function api(path, body) {
  const r = await fetch('/api/' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin', // přihlašovací cookie (HttpOnly — JavaScript ji nevidí)
    body: JSON.stringify(body || {}),
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  let data = null;
  try { data = await r.json(); } catch { /* ignore */ }
  if (!r.ok) {
    const err = new Error(data?.message || data?.error || 'HTTP ' + r.status);
    err.code = data?.error || 'http_' + r.status;
    throw err;
  }
  return data;
}

function showStatus(text, kind = 'info') {
  const s = $('#status');
  if (!text) { s.hidden = true; return; }
  s.hidden = false;
  s.className = 'status ' + kind;
  s.replaceChildren(text);
}

async function loadConfig() {
  try {
    serverConfig = await api('config');
    showLogin(false);
    const missing = [!serverConfig.vt && 'VirusTotal', !serverConfig.sb && 'Safe Browsing'].filter(Boolean);
    showStatus(missing.length ? `Na serveru není nastaven klíč pro: ${missing.join(', ')}. Ostatní kontroly fungují.` : '', 'info');
  } catch (e) {
    serverConfig = null;
    if (e.code === 'unauthorized') { showStatus(''); showLogin(true); }
    else if (e.code === 'not_configured') showStatus('Na serveru chybí heslo (APP_PASSWORD) — funguje jen offline kontrola. Nastav ho: npm run setup', 'warn');
    else showStatus('Server není dostupný — funguje jen offline kontrola.', 'warn');
  }
}

// ---------------- přihlášení ----------------

function showLogin(show) {
  $('#login').hidden = !show;
  $('#btn-logout').hidden = show;
  if (!show) { $('#login-error').hidden = true; $('#login-password').value = ''; }
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-submit');
  const err = $('#login-error');
  btn.disabled = true;
  btn.textContent = 'Ověřuji…';
  err.hidden = true;
  try {
    await api('login', { password: $('#login-password').value });
    await loadConfig();
  } catch (ex) {
    err.textContent = ex.code === 'bad_password' ? 'Špatné heslo.' : ex.message;
    err.hidden = false;
    $('#login-password').select();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Přihlásit';
  }
});

$('#btn-logout').addEventListener('click', async () => {
  if (!confirm('Odhlásit toto zařízení? Online kontroly pak nepoběží, dokud se znovu nepřihlásíš.')) return;
  try { await api('logout'); } catch { /* cookie i tak vyprší */ }
  $('#settings').close('cancel');
  serverConfig = null;
  showLogin(true);
});

// ---------------- skener ----------------

let stream = null;
let scanning = false;
let detector = null;

async function getDetector() {
  if (detector !== null) return detector;
  try {
    if ('BarcodeDetector' in window && (await BarcodeDetector.getSupportedFormats()).includes('qr_code')) {
      detector = new BarcodeDetector({ formats: ['qr_code'] });
      return detector;
    }
  } catch { /* fallback */ }
  detector = false;
  return detector;
}

async function decodeFrom(source, w, hgt) {
  const det = await getDetector();
  if (det) {
    try {
      const codes = await det.detect(source);
      if (codes.length) return codes[0].rawValue;
    } catch { /* fallback to jsQR */ }
  }
  if (!window.jsQR) return null;
  const canvas = $('#canvas');
  const scale = Math.min(1, 800 / Math.max(w, hgt));
  canvas.width = Math.round(w * scale);
  canvas.height = Math.round(hgt * scale);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
  return code ? code.data : null;
}

async function startScan() {
  if (!navigator.mediaDevices?.getUserMedia) {
    showStatus('Prohlížeč nepovoluje kameru. Appka musí běžet přes HTTPS (nebo localhost).', 'warn');
    return;
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
  } catch (e) {
    showStatus(e.name === 'NotAllowedError' ? 'Přístup ke kameře byl zamítnut. Povol ho v nastavení prohlížeče.' : 'Kameru se nepodařilo spustit.', 'warn');
    return;
  }
  const video = $('#video');
  video.srcObject = stream;
  await video.play().catch(() => {});
  $('#viewport').classList.add('live');
  $('#btn-scan').textContent = 'Zastavit';
  const track = stream.getVideoTracks()[0];
  $('#btn-torch').hidden = !track.getCapabilities?.().torch;
  scanning = true;
  loop();
}

function stopScan() {
  scanning = false;
  stream?.getTracks().forEach((t) => t.stop());
  stream = null;
  $('#video').srcObject = null;
  $('#viewport').classList.remove('live');
  $('#btn-scan').textContent = 'Spustit skener';
  $('#btn-torch').hidden = true;
}

let lastTick = 0;
async function loop() {
  if (!scanning) return;
  const video = $('#video');
  const now = performance.now();
  if (now - lastTick > 120 && video.readyState >= 2) {
    lastTick = now;
    const text = await decodeFrom(video, video.videoWidth, video.videoHeight);
    if (text != null && scanning) {
      stopScan();
      navigator.vibrate?.(60);
      handleContent(text);
      return;
    }
  }
  requestAnimationFrame(loop);
}

let torchOn = false;
async function toggleTorch() {
  const track = stream?.getVideoTracks()[0];
  if (!track) return;
  torchOn = !torchOn;
  try { await track.applyConstraints({ advanced: [{ torch: torchOn }] }); } catch { torchOn = false; }
}

async function scanFile(file) {
  if (!file) return;
  try {
    const bmp = await createImageBitmap(file);
    const text = await decodeFrom(bmp, bmp.width, bmp.height);
    bmp.close?.();
    if (text == null) showStatus('Na obrázku se nepodařilo najít QR kód.', 'warn');
    else { showStatus(''); handleContent(text); }
  } catch {
    showStatus('Obrázek nejde načíst.', 'warn');
  }
}

// ---------------- výsledek ----------------

const LEVEL_ICON = { danger: '⛔', warn: '⚠️', info: 'ℹ️', ok: '✓' };
const VERDICT = {
  danger: { title: 'Nebezpečné', text: 'Našly se vážné varovné signály. Doporučuji neotvírat.' },
  warn: { title: 'Opatrně', text: 'Něco tu nesedí. Pokračuj, jen pokud zdroji kódu věříš.' },
  ok: { title: 'Bez varovných signálů', text: 'Nic podezřelého jsem nenašel. To ale není záruka bezpečí.' },
  pending: { title: 'Kontroluji…', text: 'Probíhají online kontroly.' },
};

let runId = 0;

function handleContent(text) {
  const id = ++runId;
  const c = classify(text);
  const result = $('#result');
  result.hidden = false;

  const state = { findings: [...c.findings], pending: 0, sent: [], card: null };
  const verdictBox = h('div', { class: 'verdict' });
  const findingsList = h('ul', { class: 'findings' });
  const sentList = h('ul', { class: 'sent' });
  const extra = h('div', { class: 'extra' });

  const refresh = () => {
    if (id !== runId) return;
    const v = state.pending > 0 && verdict(state.findings) !== 'danger' ? 'pending' : verdict(state.findings);
    verdictBox.className = 'verdict v-' + v;
    verdictBox.replaceChildren(
      h('div', { class: 'v-title' }, v === 'pending' ? h('span', { class: 'spinner' }) : null, VERDICT[v].title),
      h('div', { class: 'v-text' }, VERDICT[v].text),
    );
    const order = { danger: 0, warn: 1, info: 2, ok: 3 };
    findingsList.replaceChildren(...[...state.findings].sort((a, b) => order[a.level] - order[b.level])
      .map((x) => h('li', { class: 'f-' + x.level }, h('span', { class: 'f-icon', 'aria-hidden': 'true' }, LEVEL_ICON[x.level]), h('span', {}, x.text))));
    sentList.replaceChildren(...(state.sent.length ? state.sent : ['Nic — kontrola proběhla jen v telefonu.']).map((s) => h('li', {}, s)));
    if (state.card) state.card.dataset.verdict = v;
  };
  const ctx = {
    add: (level, text) => { state.findings.push({ level, text }); refresh(); },
    sent: (s) => { state.sent.push(s); refresh(); },
    count: () => state.findings.length,
    task: async (fn) => { state.pending++; refresh(); try { await fn(); } finally { state.pending--; refresh(); } },
    isCurrent: () => id === runId,
    extra,
  };

  const details = c.details.length ? h('dl', { class: 'details' }, c.details.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])) : null;
  const rawBox = h('details', { class: 'raw' }, h('summary', {}, 'Celý obsah kódu'), h('pre', {}, c.raw));

  state.card = h('article', { class: 'card' },
    h('div', { class: 'kind' }, c.title),
    verdictBox,
    c.url ? h('div', { class: 'url' }, prettyUrl(c.url)) : null,
    details,
    findingsList,
    extra,
    buildActions(c, state),
    h('details', { class: 'privacy' }, h('summary', {}, 'Co se odeslalo mimo telefon'), sentList),
    rawBox,
  );
  result.replaceChildren(state.card);
  refresh();
  result.scrollIntoView({ behavior: 'smooth', block: 'start' });

  if (c.kind === 'url' && c.url) onlineChecks(c.url, ctx, { primary: true });
  if (c.links?.length) {
    extra.append(h('div', { class: 'links' }, h('div', { class: 'small muted' }, 'Odkazy v obsahu:'),
      c.links.map((l) => h('div', { class: 'link-row' }, h('span', { class: 'mono' }, prettyUrl(l)),
        h('button', { class: 'secondary small', onclick: () => handleContent(l) }, 'Zkontrolovat')))));
  }
}

function prettyUrl(href) {
  try {
    const u = new URL(href);
    const host = decodeHost(u.hostname);
    const reg = decodeHost(registrableDomain(u.hostname));
    const pre = host.slice(0, host.length - reg.length);
    const rest = (u.port ? ':' + u.port : '') + u.pathname + u.search + u.hash;
    return h('span', {}, h('span', { class: 'muted' }, u.protocol + '//'), pre,
      h('strong', { class: 'reg' }, reg), h('span', { class: 'muted' }, rest.length > 140 ? rest.slice(0, 140) + '…' : rest));
  } catch { return href; }
}

function buildActions(c, state) {
  const row = h('div', { class: 'actions' });
  const confirmRisky = () => {
    const v = verdict(state.findings);
    if (v === 'danger') return confirm('Kontrola našla vážné varovné signály. Opravdu otevřít?');
    if (v === 'warn' || state.pending) return confirm(state.pending ? 'Kontrola ještě neskončila. Přesto otevřít?' : 'Kontrola našla varování. Opravdu otevřít?');
    return true;
  };
  const openHref = (href) => {
    if (!confirmRisky()) return;
    const a = h('a', { href, target: '_blank', rel: 'noopener noreferrer' });
    document.body.append(a); a.click(); a.remove();
  };
  if (c.kind === 'url' && c.url) row.append(h('button', { class: 'primary', onclick: () => openHref(c.url) }, 'Otevřít odkaz'));
  if (['tel', 'sms', 'mail', 'geo'].includes(c.kind)) {
    row.append(h('button', { class: 'primary', onclick: () => openHref(c.raw.trim()) }, 'Otevřít v aplikaci'));
  }
  if (c.kind === 'wifi' && c.wifi?.P) row.append(copyBtn('Kopírovat heslo', c.wifi.P));
  row.append(copyBtn('Kopírovat', c.url || c.raw));
  row.append(h('button', { class: 'secondary', onclick: () => { $('#result').hidden = true; runId++; startScan(); } }, 'Skenovat další'));
  return row;
}

function copyBtn(label, text) {
  const b = h('button', { class: 'secondary' }, label);
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(text); b.textContent = 'Zkopírováno'; } catch { b.textContent = 'Nelze kopírovat'; }
    setTimeout(() => (b.textContent = label), 1500);
  });
  return b;
}

// ---------------- online kontroly ----------------

const SB_THREATS = {
  MALWARE: 'malware', SOCIAL_ENGINEERING: 'phishing / podvod', UNWANTED_SOFTWARE: 'nežádoucí software',
  POTENTIALLY_HARMFUL_APPLICATION: 'škodlivá aplikace',
};

function svcOn(name) {
  return serverConfig && settings[name] && (name === 'rdap' || name === 'unroll' || serverConfig[name]);
}

async function onlineChecks(href, ctx, { primary, label = '' }) {
  if (!serverConfig) {
    if (primary) ctx.add('info', 'Online kontroly neproběhly (server není nastaven). Výsledek vychází jen z offline analýzy.');
    return;
  }
  const u = new URL(href);
  const reg = registrableDomain(u.hostname);
  const regIsDomain = /[a-z]/i.test(reg) && reg.includes('.');
  const pfx = label ? `${label}: ` : '';
  const jobs = [];

  // 1) Zkracovače — rozbalit (server navštíví jen zkracovač, ne cíl)
  if (primary && settings.unroll && analyzeUrl(href).isShortener) {
    jobs.push(ctx.task(async () => {
      ctx.sent(`Vlastní server → ${u.hostname}: zkrácený odkaz (kvůli zjištění cíle)`);
      try {
        const r = await api('unroll', { url: href, mode: 'shorteners' });
        if (!ctx.isCurrent()) return;
        if (r.final && r.final !== href) {
          showChain(ctx, r);
          const a = analyzeUrl(r.final);
          for (const x of a.findings) ctx.add(x.level, 'Cíl: ' + x.text);
          await onlineChecks(r.final, ctx, { primary: false, label: 'Cíl' });
        } else if (r.stopped === 'network') {
          ctx.add('warn', 'Zkracovač neodpověděl — cíl se nepodařilo zjistit.');
        }
      } catch (e) { ctx.add('info', 'Rozbalení zkracovače selhalo: ' + e.message); }
    }));
  }

  // 2) Google Safe Browsing — jen prefixy hashů
  if (svcOn('sb')) {
    jobs.push(ctx.task(async () => {
      const { items, prefixesB64 } = await sbHashes(href);
      if (!prefixesB64.length) return;
      ctx.sent(`Google Safe Browsing: ${prefixesB64.length}× 4bajtový prefix hashe${label ? ' (' + label.toLowerCase() + ')' : ''}`);
      try {
        const r = await api('sb', { prefixes: prefixesB64 });
        const mine = new Map(items.map((i) => [i.fullHashB64, i.expr]));
        const threats = new Set();
        for (const fh of r.fullHashes || []) if (mine.has(fh.fullHash)) fh.threats.forEach((t) => threats.add(SB_THREATS[t] || t));
        if (threats.size) ctx.add('danger', `${pfx}Google Safe Browsing hlásí: ${[...threats].join(', ')}.`);
        else ctx.add('ok', `${pfx}Google Safe Browsing: bez záznamu.`);
      } catch (e) { ctx.add('info', `${pfx}Safe Browsing nedostupné (${e.message}).`); }
    }));
  }

  // 3) VirusTotal — hash URL + hlavní doména
  if (svcOn('vt')) {
    jobs.push(ctx.task(async () => {
      const ids = await vtUrlIds(href);
      ctx.sent(`VirusTotal: SHA‑256 hash adresy${label ? ' (' + label.toLowerCase() + ')' : ''}`);
      try {
        const r = await api('vt/url', { ids });
        if (!r.found) ctx.add('info', `${pfx}VirusTotal tuto přesnou adresu nezná. U osobních/tajných odkazů je to normální.`);
        else {
          const s = r.stats || {};
          const total = (s.malicious || 0) + (s.suspicious || 0) + (s.harmless || 0) + (s.undetected || 0);
          const when = r.lastAnalysis ? ` (sken ${new Date(r.lastAnalysis * 1000).toLocaleDateString('cs-CZ')})` : '';
          // Jednotlivé antiviry občas hlásí falešné poplachy — za "nebezpečné" bereme až shodu 3+.
          if ((s.malicious || 0) >= 3) ctx.add('danger', `${pfx}VirusTotal: ${s.malicious}/${total} antivirů hlásí škodlivou adresu${when}. ${r.engines.slice(0, 3).join(', ')}`);
          else if ((s.malicious || 0) >= 1 || (s.suspicious || 0) >= 2) ctx.add('warn', `${pfx}VirusTotal: ${s.malicious || 0} škodlivá, ${s.suspicious || 0} podezřelá detekce z ${total}${when}. ${r.engines.slice(0, 2).join(', ')}`);
          else if (s.suspicious) ctx.add('info', `${pfx}VirusTotal: 1 antivirus z ${total} adresu označil jako podezřelou, ostatní ne${when}.`);
          else ctx.add('ok', `${pfx}VirusTotal: 0/${total} detekcí${when}.`);
        }
      } catch (e) { ctx.add('info', `${pfx}VirusTotal (adresa) nedostupný: ${e.message}`); }

      if (!regIsDomain) return;
      ctx.sent(`VirusTotal: doména ${reg}`);
      try {
        const d = await api('vt/domain', { domain: reg });
        if (!d.found) { ctx.add('info', `${pfx}VirusTotal doménu ${reg} nezná.`); offerVtDomainScan(ctx, reg); return; }
        const s = d.stats || {};
        // Hodnocení celé domény je hrubší než u konkrétní adresy: velké portály (např. seznam.cz)
        // mívají 1–2 falešné detekce, protože někdo na jejich službách kdysi hostoval malware.
        const mal = s.malicious || 0;
        if (mal >= 5) ctx.add('danger', `${pfx}VirusTotal: doménu ${reg} označuje ${mal} antivirů jako škodlivou.`);
        else if (mal >= 3 || (d.reputation != null && d.reputation < -20)) ctx.add('warn', `${pfx}VirusTotal: doménu ${reg} označují ${mal} antiviry jako škodlivou${d.reputation < 0 ? `, komunitní hodnocení ${d.reputation}` : ''}.`);
        else if (mal >= 1) ctx.add('info', `${pfx}VirusTotal: doménu ${reg} označil${mal === 1 ? ' 1 antivirus' : 'y 2 antiviry'} z ${Object.values(s).reduce((a, b) => a + b, 0)} — u velkých webů bývají ojedinělé detekce falešný poplach.`);
        else ctx.add('ok', `${pfx}VirusTotal: doména ${reg} bez detekcí.`);
      } catch (e) { ctx.add('info', `${pfx}VirusTotal (doména) nedostupný: ${e.message}`); }
    }));
  }

  // 4) RDAP — stáří domény
  if (svcOn('rdap') && regIsDomain) {
    jobs.push(ctx.task(async () => {
      ctx.sent(`RDAP registr: doména ${reg}`);
      try {
        const r = await api('rdap', { domain: reg });
        if (!r.found) { ctx.add('warn', `${pfx}Doména ${reg} není v registru (neexistuje?).`); return; }
        if (!r.created) return;
        const days = Math.floor((Date.now() - Date.parse(r.created)) / 86400000);
        const date = new Date(r.created).toLocaleDateString('cs-CZ');
        if (days < 14) ctx.add('danger', `${pfx}Doména ${reg} je zaregistrovaná teprve před ${days} dny (${date}). Podvodné weby žijí typicky jen pár dní.`);
        else if (days < 90) ctx.add('warn', `${pfx}Doména ${reg} je mladá — zaregistrovaná ${date}.`);
        else ctx.add('ok', `${pfx}Doména ${reg} existuje od ${date}.`);
      } catch (e) { ctx.add('info', `${pfx}Stáří domény nezjištěno (${e.message}).`); }
    }));
  }

  if (primary) {
    ctx.extra.append(h('div', { class: 'more' },
      serverConfig.preview ? h('button', { class: 'secondary small preview-btn', onclick: (ev) => safePreview(href, ctx, ev.currentTarget) }, '🔍 Bezpečný náhled…') : null,
      h('button', { class: 'secondary small', onclick: (ev) => fullUnroll(href, ctx, ev.currentTarget) }, 'Projít všechna přesměrování…')));
  }
  await Promise.all(jobs);
}

function showChain(ctx, r) {
  ctx.extra.append(h('div', { class: 'chain' },
    h('div', { class: 'small muted' }, 'Řetěz přesměrování:'),
    h('ol', {}, [...r.chain.map((x) => h('li', {}, h('span', { class: 'mono' }, x.url), x.status ? ` (${x.status})` : '')),
      h('li', { class: 'final' }, h('strong', {}, 'Cíl: '), prettyUrl(r.final))])));
}

async function fullUnroll(href, ctx, btn) {
  const ok = confirm('Server teď skutečně navštíví cílový web a projde všechna přesměrování.\n\n' +
    '• Web uvidí IP adresu Cloudflare, ne tvoji.\n' +
    '• Jednorázové odkazy (přihlášení, reset hesla, vstupenky, potvrzení) se tím mohou SPOTŘEBOVAT.\n\nPokračovat?');
  if (!ok) return;
  btn.disabled = true;
  await ctx.task(async () => {
    ctx.sent(`Vlastní server → cílový web: celá adresa (ručně vyžádáno)`);
    try {
      const r = await api('unroll', { url: href, mode: 'all' });
      showChain(ctx, r);
      if (r.final !== href) {
        const a = analyzeUrl(r.final);
        for (const x of a.findings) ctx.add(x.level, 'Cíl: ' + x.text);
        await onlineChecks(r.final, ctx, { primary: false, label: 'Cíl' });
      } else ctx.add('ok', 'Odkaz nikam dál nepřesměrovává.');
    } catch (e) { ctx.add('info', 'Přesměrování se nepodařilo projít: ' + e.message); }
  });
  btn.remove();
}

// ---------------- Bezpečný náhled ----------------

const EVENT_TEXT = {
  notifications: ['warn', 'Stránka hned žádá o povolení notifikací. Na webech z QR kódů je nikdy nepovoluj — slouží k rozesílání podvodných zpráv.'],
  push: ['warn', 'Stránka se pokusila přihlásit k push notifikacím.'],
  geolocation: ['warn', 'Stránka chce znát tvoji polohu.'],
  camera: ['warn', 'Stránka chce přístup ke kameře.'],
  microphone: ['warn', 'Stránka chce přístup k mikrofonu.'],
  'clipboard-read': ['warn', 'Stránka se pokusila číst tvoji schránku.'],
  'payment-request': ['warn', 'Stránka se pokusila otevřít platební dialog.'],
  credentials: ['info', 'Stránka se ptá na uložená přihlášení.'],
  popup: ['info', 'Stránka se pokusila otevřít další okno'],
  'download-link': ['warn', 'Stránka skriptem spouští stahování souboru'],
  blob: ['warn', 'Stránka si v prohlížeči sama vygenerovala soubor ke stažení'],
};

function brandMentioned(text, registrable) {
  const compact = text.toLowerCase().normalize('NFKD').replace(/\p{M}/gu, '').replace(/[^a-z0-9]/g, '');
  for (const [brand, official] of Object.entries(BRANDS)) {
    if (brand.length >= 5 && compact.includes(brand) && !official.includes(registrable)) return { brand, official: official[0] };
  }
  return null;
}

function isOfficialDomain(registrable) {
  return [...Object.values(BRANDS), ...Object.values(SHORT_BRANDS)].some((list) => list.includes(registrable));
}

async function safePreview(href, ctx, btn) {
  const ok = confirm('Odkaz se otevře v izolovaném prohlížeči u Cloudflare — ne v tvém telefonu. Uvidíš snímek stránky a co se pokoušela dělat.\n\n' +
    '• Web uvidí IP adresu Cloudflare, ne tvoji.\n' +
    '• Jednorázové odkazy (přihlášení, reset hesla, vstupenky, potvrzení) se tím mohou SPOTŘEBOVAT.\n\nPokračovat?');
  if (!ok) return;
  btn.disabled = true;
  btn.textContent = 'Otevírám v izolovaném prohlížeči…';
  await ctx.task(async () => {
    ctx.sent('Izolovaný prohlížeč Cloudflare → cílový web: celá adresa (ručně vyžádáno)');
    let r;
    try {
      r = await api('preview', { url: href });
    } catch (e) {
      ctx.add('info', 'Bezpečný náhled se nepodařil: ' + e.message);
      btn.disabled = false;
      btn.textContent = '🔍 Bezpečný náhled…';
      return;
    }
    if (!ctx.isCurrent()) return;
    btn.remove();

    let finalReg = '';
    try { finalReg = registrableDomain(new URL(r.finalUrl).hostname); } catch { /* ignore */ }
    const startReg = registrableDomain(new URL(href).hostname);

    // --- snímek ---
    const shot = r.screenshot ? h('img', { class: 'shot', src: r.screenshot, alt: 'Snímek stránky z izolovaného prohlížeče' }) : null;
    shot?.addEventListener('click', () => shot.classList.toggle('expanded'));
    ctx.extra.prepend(h('div', { class: 'preview' },
      h('div', { class: 'small muted' }, 'Bezpečný náhled (izolovaný prohlížeč):'),
      shot || h('div', { class: 'small muted' }, 'Snímek není k dispozici.'),
      r.title ? h('div', { class: 'small' }, h('span', { class: 'muted' }, 'Titulek: '), r.title) : null,
      /^https?:/.test(r.finalUrl || '') ? h('div', { class: 'small' }, h('span', { class: 'muted' }, 'Skončil na: '), prettyUrl(r.finalUrl)) : null,
    ));

    const before = ctx.count();

    // --- stahování ---
    for (const d of r.downloads || []) {
      const ext = (d.ext || '').toLowerCase();
      const name = d.filename || d.url;
      if (DANGEROUS_EXTENSIONS.danger.includes(ext) || ['apk', 'exe', 'msi', 'mobileconfig', 'jar', 'sh', 'bat'].includes(ext)) {
        ctx.add('danger', `Náhled: stránka spustila stahování souboru .${ext} (${name}). ${ext === 'apk' ? 'Takovou aplikaci nikdy neinstaluj.' : 'Nespouštěj ho.'}`);
      } else if (['zip', 'rar', '7z', 'iso', 'bin'].includes(ext)) {
        ctx.add('warn', `Náhled: stránka stahuje soubor (${d.type}, ${name}).`);
      } else {
        ctx.add('info', `Náhled: stránka stahuje soubor ${name} (${d.type}).`);
      }
    }

    // --- pokusy o oprávnění, schránku… ---
    const seen = new Set();
    for (const e of r.events || []) {
      if (seen.has(e.type)) continue;
      seen.add(e.type);
      if (e.type === 'clipboard-write') {
        ctx.add('warn', `Náhled: stránka se pokusila vložit do schránky text „${e.detail.slice(0, 80)}${e.detail.length > 80 ? '…' : ''}“. Nic z toho nikam nevkládej (častý trik: podvržený příkaz nebo číslo účtu).`);
      } else if (EVENT_TEXT[e.type]) {
        const [lvl, text] = EVENT_TEXT[e.type];
        ctx.add(lvl, 'Náhled: ' + text + (e.detail && ['popup', 'download-link', 'blob'].includes(e.type) ? ` (${e.detail.slice(0, 80)}).` : ''));
      }
    }

    // --- formuláře: hesla, karty ---
    const official = isOfficialDomain(finalReg);
    const brand = brandMentioned((r.title || '') + ' ' + (r.textSample || ''), finalReg);
    const brandInTitle = brand && brandMentioned(r.title || '', finalReg);
    if (r.passwordFields || r.cardFields) {
      const what = [r.passwordFields && 'heslo', r.cardFields && 'údaje platební karty'].filter(Boolean).join(' a ');
      if (brand) {
        ctx.add(brandInTitle || r.cardFields ? 'danger' : 'warn',
          `Náhled: stránka se tváří jako „${brand.brand}“ a chce ${what}, ale běží na ${finalReg}, ne na ${brand.official}. Klasický phishing.`);
      } else if (official) {
        ctx.add('info', `Náhled: stránka chce ${what} — doména ${finalReg} patří známé službě.`);
      } else {
        ctx.add('warn', `Náhled: stránka chce ${what}. Zadávej je jen pokud ${finalReg} opravdu patří službě, ke které se přihlašuješ.`);
      }
    }
    if (r.otpFields && (r.passwordFields || r.cardFields) && !official) {
      ctx.add('warn', 'Náhled: stránka chce i ověřovací kód (SMS/PIN). Banky ani dopravci ho přes odkazy nikdy nechtějí.');
    }
    const foreignForms = (r.formHosts || []).map((x) => registrableDomain(x)).filter((x) => x && x !== finalReg);
    if (foreignForms.length && (r.passwordFields || r.cardFields)) {
      ctx.add('warn', `Náhled: formulář odesílá data na jinou doménu: ${[...new Set(foreignForms)].join(', ')}.`);
    }

    if (r.blocked?.length) ctx.add('danger', `Náhled: stránka se pokusila přistoupit do lokální sítě (${r.blocked.join(', ')}) — např. na router.`);
    if (r.status >= 400) ctx.add('info', `Náhled: server odpověděl chybou ${r.status}.`);
    if (r.loadError && !r.screenshot) ctx.add('info', 'Náhled: stránka se nenačetla celá (' + r.loadError + ').');

    // --- kam to skončilo ---
    const navs = r.navigations || [];
    if (navs.length > 1) showChain(ctx, { chain: navs.slice(0, -1), final: r.finalUrl });
    if (finalReg && finalReg !== startReg && /^https?:/.test(r.finalUrl)) {
      ctx.add('warn', `Náhled: stránka tě přesměrovala na jinou doménu: ${decodeHost(finalReg)}.`);
      for (const x of analyzeUrl(r.finalUrl).findings) ctx.add(x.level, 'Cíl: ' + x.text);
      await onlineChecks(r.finalUrl, ctx, { primary: false, label: 'Cíl' });
    }

    if (ctx.count() === before) ctx.add('ok', 'Náhled: stránka nic podezřelého nezkoušela (stahování, oprávnění, schránka, přihlašovací formuláře).');
  });
}

function offerVtDomainScan(ctx, domain) {
  const btn = h('button', { class: 'secondary small' }, `Nechat VirusTotal naskenovat ${domain}…`);
  btn.addEventListener('click', async () => {
    if (!confirm(`VirusTotal naskenuje jen hlavní stránku https://${domain}/ (bez cesty a parametrů z QR kódu).\n\nDoména se tím ve VirusTotalu stane veřejně dohledatelnou. Pokračovat?`)) return;
    btn.disabled = true;
    await ctx.task(async () => {
      ctx.sent(`VirusTotal: ke skenu odeslána jen https://${domain}/`);
      try {
        const { analysisId } = await api('vt/submit-domain', { domain });
        for (let i = 0; i < 8; i++) {
          await new Promise((r) => setTimeout(r, 8000));
          const a = await api('vt/analysis', { id: analysisId });
          if (a.status === 'completed') {
            const s = a.stats || {};
            if ((s.malicious || 0) >= 2) ctx.add('danger', `VirusTotal sken: ${s.malicious} antivirů hlásí doménu jako škodlivou.`);
            else if (s.malicious || s.suspicious) ctx.add('warn', `VirusTotal sken: ${s.malicious || 0} škodlivá / ${s.suspicious || 0} podezřelá detekce.`);
            else ctx.add('ok', 'VirusTotal sken hlavní stránky: bez detekcí.');
            return;
          }
        }
        ctx.add('info', 'VirusTotal sken zatím neskončil, zkus to později.');
      } catch (e) { ctx.add('info', 'Sken se nepodařilo spustit: ' + e.message); }
    });
    btn.remove();
  });
  ctx.extra.append(h('div', { class: 'more' }, btn));
}

// ---------------- nastavení UI ----------------

function openSettings() {
  for (const k of ['sb', 'vt', 'rdap', 'unroll']) $('#set-' + k).checked = !!settings[k];
  $('#settings').showModal();
}

$('#settings').addEventListener('close', () => {
  if ($('#settings').returnValue !== 'save') return;
  settings = {};
  for (const k of ['sb', 'vt', 'rdap', 'unroll']) settings[k] = $('#set-' + k).checked;
  saveSettings(settings);
  loadConfig();
});

// ---------------- události ----------------

$('#btn-settings').addEventListener('click', openSettings);
$('#btn-scan').addEventListener('click', () => (scanning ? stopScan() : startScan()));
$('#btn-torch').addEventListener('click', toggleTorch);
$('#file').addEventListener('change', (e) => { stopScan(); scanFile(e.target.files[0]); e.target.value = ''; });
$('#btn-manual').addEventListener('click', () => { const m = $('#manual'); m.hidden = !m.hidden; if (!m.hidden) $('#manual-text').focus(); });
$('#manual').addEventListener('submit', (e) => {
  e.preventDefault();
  const t = $('#manual-text').value;
  if (t.trim()) { stopScan(); handleContent(t); $('#manual-text').value = ''; $('#manual').hidden = true; }
});
document.addEventListener('visibilitychange', () => { if (document.hidden && scanning) stopScan(); });

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
loadConfig();

#!/usr/bin/env node
// Průvodce instalací QRguard: přihlášení ke Cloudflare, heslo, API klíče, nasazení.
//
// Spuštění: npm run setup   (nebo ./install.sh, který navíc zkontroluje Node.js)
//
// Bezpečnost:
// - Klíče a heslo se nikam neukládají na disk. Jdou přes stdin rovnou do
//   `wrangler secret bulk` (šifrované secrets u Cloudflare).
// - Při opakovaném spuštění lze nechat stávající hodnoty (prázdný vstup = beze změny).

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, copyFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const WRANGLER = join(ROOT, 'node_modules', 'wrangler', 'bin', 'wrangler.js');

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

function fail(msg) {
  console.error('\n' + c.red('✗ ' + msg));
  process.exit(1);
}

/** Spustí wrangler. capture=true vrátí výstup (a zároveň ho ukáže, pokud show=true). */
function wrangler(args, { input, capture = false, show = true } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [WRANGLER, ...args], {
      cwd: ROOT,
      stdio: [input !== undefined ? 'pipe' : 'inherit', capture ? 'pipe' : 'inherit', capture ? 'pipe' : 'inherit'],
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    });
    let out = '';
    if (capture) {
      const collect = (stream, target) => stream.on('data', (d) => { out += d; if (show) target.write(d); });
      collect(child.stdout, process.stdout);
      collect(child.stderr, process.stderr);
    }
    if (input !== undefined) { child.stdin.write(input); child.stdin.end(); }
    child.on('close', (code) => resolve({ code, out }));
  });
}

// ---------- vstup z terminálu ----------

const stdin = process.stdin;
let buffered = '';
const lineWaiters = [];
let stdinEnded = false;

function readLine({ hidden = false } = {}) {
  return new Promise((resolve) => {
    if (stdin.isTTY) {
      stdin.setRawMode(true);
      stdin.resume();
      let value = '';
      const onData = (chunk) => {
        for (const ch of chunk.toString('utf8')) {
          if (ch === '\r' || ch === '\n') {
            stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData);
            process.stdout.write('\n');
            return resolve(value);
          } else if (ch === '\u0003') { // Ctrl+C
            stdin.setRawMode(false);
            process.stdout.write('\n');
            process.exit(130);
          } else if (ch === '\u007f' || ch === '\b') {
            if (value) { value = value.slice(0, -1); if (!hidden) process.stdout.write('\b \b'); }
          } else if (ch >= ' ') {
            value += ch;
            process.stdout.write(hidden ? '' : ch);
          }
        }
      };
      stdin.on('data', onData);
    } else {
      // neinteraktivní vstup (roura) — čte po řádcích
      const tryTake = () => {
        const i = buffered.indexOf('\n');
        if (i >= 0) { const l = buffered.slice(0, i).replace(/\r$/, ''); buffered = buffered.slice(i + 1); resolve(l); return true; }
        if (stdinEnded) { const l = buffered; buffered = ''; resolve(l); return true; }
        return false;
      };
      if (!tryTake()) lineWaiters.push(tryTake);
    }
  });
}
if (!stdin.isTTY) {
  stdin.setEncoding('utf8');
  stdin.on('data', (d) => { buffered += d; while (lineWaiters.length && lineWaiters[0]()) lineWaiters.shift(); });
  stdin.on('end', () => { stdinEnded = true; while (lineWaiters.length && lineWaiters[0]()) lineWaiters.shift(); });
}

async function ask(question, opts = {}) {
  process.stdout.write(question + ' ');
  return (await readLine(opts)).trim();
}

async function yesNo(question, def = true) {
  const a = (await ask(`${question} ${c.dim(def ? '[A/n]' : '[a/N]')}`)).toLowerCase();
  if (!a) return def;
  return a.startsWith('a') || a.startsWith('y');
}

function generatePassword() {
  // 4 skupiny po 5 znacích bez zaměnitelných znaků (~98 bitů), dobře se píše i na telefonu
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  const bytes = randomBytes(40);
  const groups = [];
  let g = '', i = 0;
  while (groups.length < 4) {
    const b = bytes[i++ % bytes.length];
    if (b >= 248) continue; // 248 = 8 * 31, rovnoměrné rozložení
    g += alphabet[b % alphabet.length];
    if (g.length === 5) { groups.push(g); g = ''; }
  }
  return groups.join('-');
}

// ---------- průvodce ----------

console.log(c.bold('\n🛡️  QRguard – instalace\n'));
console.log('Appka poběží na tvém vlastním Cloudflare účtu (zdarma). Nikdo jiný nevidí, co skenuješ.\n');

const [major] = process.versions.node.split('.').map(Number);
if (major < 20) fail(`Potřebuješ Node.js 20 nebo novější (máš ${process.versions.node}). Stáhni ho z https://nodejs.org`);

// 1) závislosti
if (!existsSync(WRANGLER)) {
  console.log(c.cyan('→ Instaluji závislosti (npm ci)…'));
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const code = await new Promise((r) => spawn(npm, ['ci'], { cwd: ROOT, stdio: 'inherit', shell: process.platform === 'win32' }).on('close', r));
  if (code !== 0 || !existsSync(WRANGLER)) fail('Instalace závislostí selhala.');
}
const jsqrTarget = join(ROOT, 'public', 'vendor', 'jsQR.js');
if (!existsSync(jsqrTarget)) {
  mkdirSync(dirname(jsqrTarget), { recursive: true });
  copyFileSync(join(ROOT, 'node_modules', 'jsqr', 'dist', 'jsQR.js'), jsqrTarget);
}

// 2) přihlášení ke Cloudflare
console.log(c.bold('\n1/4  Cloudflare účet'));
let who = await wrangler(['whoami'], { capture: true, show: false });
if (who.code !== 0 || /not authenticated|You are not logged in/i.test(who.out)) {
  console.log('Teď se otevře prohlížeč s přihlášením ke Cloudflare. Pokud účet nemáš, můžeš si ho tam zdarma založit.');
  await ask(c.dim('Stiskni Enter…'));
  const login = await wrangler(['login']);
  if (login.code !== 0) fail('Přihlášení se nepovedlo. Zkus to znovu: npm run setup');
  who = await wrangler(['whoami'], { capture: true, show: false });
}
const email = who.out.match(/associated with the email\s+(\S+?)\.?\s*$/m)?.[1];
console.log(c.green('✓ Přihlášeno' + (email ? ` (${email})` : '')));

// existující secrets (při opakovaném spuštění)
let existing = new Set();
const list = await wrangler(['secret', 'list', '--format', 'json'], { capture: true, show: false });
if (list.code === 0) {
  try { existing = new Set(JSON.parse(list.out.slice(list.out.indexOf('['))).map((s) => s.name)); } catch { /* první instalace */ }
}

const secrets = {};

// 3) heslo
console.log(c.bold('\n2/4  Heslo do appky'));
console.log('Chrání tvůj server, aby tvoje API kvóty nemohl používat kdokoliv, kdo zná adresu.');
let keepPassword = false;
if (existing.has('APP_PASSWORD')) keepPassword = await yesNo('Heslo už je nastavené. Ponechat ho?', true);
if (!keepPassword) {
  if (await yesNo('Vygenerovat silné heslo automaticky?', true)) {
    secrets.APP_PASSWORD = generatePassword();
  } else {
    for (;;) {
      const p1 = await ask('Heslo (aspoň 12 znaků, nezobrazuje se):', { hidden: true });
      if (p1.length < 12) { console.log(c.yellow('  Příliš krátké.')); continue; }
      const p2 = await ask('Zopakuj heslo:', { hidden: true });
      if (p1 !== p2) { console.log(c.yellow('  Hesla se neshodují.')); continue; }
      secrets.APP_PASSWORD = p1;
      break;
    }
  }
}

// 4) API klíče
console.log(c.bold('\n3/4  API klíče') + c.dim('  (obojí je volitelné; Enter = přeskočit / ponechat)'));

console.log(`\n${c.bold('VirusTotal')} – výrazně zlepšuje detekci. Zdarma: 500 dotazů denně.
  Klíč: zaregistruj se na ${c.cyan('https://www.virustotal.com/gui/join-us')}
        → vpravo nahoře profil → ${c.bold('API key')}`);
const vt = await ask(existing.has('VT_API_KEY') ? 'VirusTotal klíč (Enter = ponechat stávající):' : 'VirusTotal klíč:', { hidden: true });
if (vt) {
  if (!/^[a-f0-9]{64}$/i.test(vt)) console.log(c.yellow('  Klíč nevypadá jako VirusTotal klíč (64 hex znaků), ukládám ho i tak.'));
  secrets.VT_API_KEY = vt;
}

console.log(`\n${c.bold('Google Safe Browsing')} – databáze phishingu a malwaru od Googlu. Zdarma pro nekomerční použití.
  Klíč: ${c.cyan('https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com')}
        → Povolit (Enable) → APIs & Services → Credentials → Create credentials → API key
        → doporučeno: Restrict key → jen „Safe Browsing API“`);
const sb = await ask(existing.has('SB_API_KEY') ? 'Safe Browsing klíč (Enter = ponechat stávající):' : 'Safe Browsing klíč:', { hidden: true });
if (sb) {
  if (!/^AIza[0-9A-Za-z_-]{35}$/.test(sb)) console.log(c.yellow('  Klíč nevypadá jako Google API klíč (AIza…), ukládám ho i tak.'));
  secrets.SB_API_KEY = sb;
}

// 5) nasazení
console.log(c.bold('\n4/4  Nasazení'));
const deploy = await wrangler(['deploy'], { capture: true });
if (deploy.code !== 0) fail('Nasazení selhalo (výpis výše).');
const url = deploy.out.match(/https:\/\/[^\s]+\.workers\.dev/)?.[0];

if (Object.keys(secrets).length) {
  console.log(c.cyan('→ Ukládám heslo a klíče jako šifrované secrets u Cloudflare…'));
  const put = await wrangler(['secret', 'bulk'], { input: JSON.stringify(secrets), capture: true, show: false });
  if (put.code !== 0) {
    console.error(put.out.replace(/[\s\S]*?(✘|ERROR)/, '$1'));
    fail('Uložení secrets selhalo. Spusť průvodce znovu: npm run setup');
  }
  console.log(c.green('✓ Uloženo'));
}

// hotovo
console.log(c.green(c.bold('\n✓ Hotovo!\n')));
if (url) {
  console.log('Adresa tvého QRguardu: ' + c.bold(url));
  try {
    const qrcode = require('qrcode-terminal');
    console.log('\nNaskenuj telefonem (fotoaparátem) a otevři:\n');
    qrcode.generate(url, { small: true }, (q) => console.log(q));
  } catch { /* bez QR v terminálu */ }
} else {
  console.log('Adresu najdeš ve výpisu výše (…workers.dev).');
}
if (secrets.APP_PASSWORD) {
  console.log(`\nTvoje heslo: ${c.bold(secrets.APP_PASSWORD)}`);
  console.log(c.yellow('Ulož si ho (např. do správce hesel). Nikde jinde uložené není.'));
}
console.log(`
V telefonu: otevři adresu → zadej heslo → v menu prohlížeče ${c.bold('Přidat na plochu')}.
Heslo se zadává jednou, přihlášení vydrží 90 dní.
Změna hesla nebo klíčů později: znovu ${c.bold('npm run setup')}.
`);
process.exit(0);

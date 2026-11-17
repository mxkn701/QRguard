# QRguard

Skener QR kódů do telefonu (PWA), který **před otevřením** zkontroluje, co v kódu je.
Důraz na soukromí: celá naskenovaná adresa se nikam nezveřejní.

## Co kontroluje

**Offline v telefonu** (okamžitě, nic se neodesílá):
- napodobeniny značek (`paypa1.com`, `paypal.com.evil.top`, cyrilice v doméně, `kb.overeni-uctu.cz`)
- `@` triky, IP adresy místo domény, nestandardní porty, nešifrované `http`
- zkracovače a „dynamické QR“, free hostingy (`*.pages.dev`, `*.github.io`…), zneužívané koncovky
- stahování `.apk`/`.exe`/iOS profilů, `javascript:`/`data:`/Android `intent:` odkazy
- **QR Platba** (SPD) a SEPA: ukáže účet, banku, částku, ověří kontrolní součet IBAN
- Wi‑Fi (otevřené/WEP sítě), prémiová čísla a SMS, 2FA klíče, kryptoměnové platby

**Online přes vlastní server** (Cloudflare Worker):

| Kontrola | Co opustí telefon |
|---|---|
| Google Safe Browsing v5 | jen 4bajtové prefixy SHA‑256 hashů (k‑anonymita) |
| VirusTotal – adresa | jen SHA‑256 hash URL (vyhledání, **ne** odeslání ke skenu) |
| VirusTotal – doména | jen hlavní doména (`example.com`, bez subdomén a cesty) |
| Stáří domény (RDAP) | jen hlavní doména, přímo registru dané koncovky |
| Rozbalení zkracovače | zkrácený odkaz jde přes tvůj server **jen na zkracovač**; cílový web se nenavštíví |

### Bezpečný náhled (proti neznámým útokům)

Databáze chrání jen před **známými** hrozbami. Tlačítko **🔍 Bezpečný náhled** otevře odkaz v izolovaném Chrome
u Cloudflare (Browser Rendering), ne v telefonu. Případný exploit tak proběhne tam. Výsledek obsahuje:
- **snímek obrazovky** stránky,
- **stažené soubory** podle skutečného typu (např. `.apk` bez přípony v adrese),
- **žádosti o oprávnění**: notifikace, poloha, kamera, mikrofon (náhled je naoko odmítne),
- **zápis do schránky** (podvržené příkazy typu „ClickFix“ nebo čísla účtů),
- **přihlašovací a platební formuláře**: heslo nebo karta na doméně, která nepatří značce, za kterou se stránka vydává; formuláře odesílané na cizí doménu; žádosti o SMS kód,
- **přesměrování**, včetně těch v JavaScriptu, a pokusy o přístup do lokální sítě.

Free plán: 10 minut prohlížeče denně a jeden nový náhled za 20 s. Jeden náhled trvá 5–10 s.
Náhled cílový web skutečně navštíví, proto se spouští jen na kliknutí (jednorázové odkazy by se spotřebovaly).

Na výslovné kliknutí (s varováním) navíc:
- **Projít všechna přesměrování:** server skutečně navštíví cíl. Jednorázové odkazy (přihlášení, reset hesla) se tím mohou spotřebovat.
- **Nechat VirusTotal naskenovat doménu:** odešle se jen `https://domena/`, nikdy cesta z QR kódu. Server jinou URL ani neumí odeslat.

V každém výsledku je rozbalovací sekce **„Co se odeslalo mimo telefon“**.
Appka nemá historii a Worker nic neloguje (observability vypnutá, data jen v těle POST požadavků).

## Instalace (zdarma, ~5 minut)

Každý si QRguard provozuje na **vlastním** Cloudflare účtu, takže nikdo jiný nevidí, co skenuješ.
Potřebuješ jen účet na [cloudflare.com](https://dash.cloudflare.com/sign-up) (zdarma).
API klíče jsou volitelné a dají se doplnit později. Bez nich fungují offline kontroly, stáří domény a bezpečný náhled.

### Možnost A: jedním kliknutím (bez instalace čehokoliv)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mxkn701/QRguard)

Cloudflare si vyžádá přihlášení, zkopíruje repozitář do tvého GitHubu a zeptá se na **heslo** a **klíče**
(u každého pole je návod, kde ho získat). Formulář vyžaduje vyplnit všechna pole: když klíč nemáš, napiš `-`.
Pak appku sám nasadí a ukáže adresu.

### Možnost B: průvodce v terminálu

Potřebuješ [Node.js](https://nodejs.org) 20+ a [Git](https://git-scm.com).

```bash
git clone https://github.com/mxkn701/QRguard.git
```
```bash
cd QRguard && ./install.sh
```
(Na Windows místo `./install.sh` spusť `npm install` a pak `npm run setup`.)

Průvodce tě přihlásí ke Cloudflare, vygeneruje heslo, zeptá se na klíče, appku nasadí a nakonec
**vypíše adresu jako QR kód**, který stačí naskenovat telefonem. Klíče a heslo se neukládají na disk,
jdou rovnou do šifrovaných secrets u Cloudflare. Změna hesla nebo klíčů později: znovu `npm run setup`.

### Pak v telefonu

Otevři adresu `https://qrguard.<účet>.workers.dev` → zadej heslo → v menu prohlížeče **Přidat na plochu**.

### Kde získat klíče

- **VirusTotal** (doporučeno): zaregistruj se na [virustotal.com](https://www.virustotal.com/gui/join-us) → profil → **API key**.
  Zdarma 4 dotazy/min, 500/den.
- **Google Safe Browsing**: v [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)
  povol *Safe Browsing API* → APIs & Services → Credentials → Create credentials → API key
  (doporučeno omezit klíč jen na Safe Browsing API). Zdarma pro nekomerční použití.

### Ruční nastavení (pro pokročilé)

```bash
npx wrangler login
```
```bash
npx wrangler deploy
```
```bash
npx wrangler secret put APP_PASSWORD
```
(a stejně `VT_API_KEY`, `SB_API_KEY`). Heslo musí mít aspoň 8 znaků, doporučeno 12+.

### Přihlášení

- Heslo se zadává jednou na zařízení. Server pak uloží podepsanou cookie platnou **90 dní**
  (`HttpOnly`, `Secure`, `SameSite=Strict` — JavaScript ani cizí weby k ní nemají přístup).
- **Odhlášení jednoho zařízení:** ⚙️ → Odhlásit.
- **Odhlášení všech zařízení:** změň heslo (`npx wrangler secret put APP_PASSWORD`). Všechny cookie jsou
  podepsané klíčem odvozeným z hesla, takže okamžitě přestanou platit.
- Volitelně `APP_TOKEN`: token pro skripty a testy (hlavička `Authorization: Bearer …`). Appka ho nepotřebuje.

### Vlastní doména (později)

Až bude `qrguard.dev` (nebo jiná doména) v tvém Cloudflare účtu, přidej do `wrangler.jsonc`:

```jsonc
"routes": [{ "pattern": "qrguard.dev", "custom_domain": true }]
```

a spusť `npm run deploy`. Cloudflare sám vytvoří DNS záznam i HTTPS certifikát.
Na nové adrese se v telefonu přihlásíš znovu (přihlášení platí zvlášť pro každou adresu).

## Lokální vývoj

```bash
npm install
```
```bash
cp .dev.vars.example .dev.vars
```
```bash
npm run dev
```
Testy:
```bash
npm test
```

Kamera v prohlížeči funguje jen přes HTTPS nebo `localhost`. Pro test z telefonu v síti spusť `npm run dev:phone` (self‑signed certifikát → v telefonu potvrdit výjimku).

## Struktura

- `public/analyze.js`: offline heuristiky a rozpoznání typu obsahu
- `public/hashing.js`: kanonizace a hashování URL (Safe Browsing / VirusTotal)
- `public/lists.js`: seznamy zkracovačů, značek, TLD…
- `public/app.js`: UI, kamera (BarcodeDetector, fallback jsQR)
- `src/worker.js`: API proxy s klíči, RDAP, rozbalování přesměrování
- `src/preview.js`: bezpečný náhled v izolovaném prohlížeči
- `src/auth.js`: přihlášení heslem a session cookie
- `scripts/setup.mjs`, `install.sh`: průvodce instalací
- `wrangler.jsonc`: konfigurace Workeru. `browser` = izolovaný Chrome pro bezpečný náhled,
  `ratelimits` = omezení pokusů o přihlášení, `run_worker_first` = bezpečnostní hlavičky (CSP…) u všech souborů,
  `observability` vypnutá = žádné logy toho, co se skenovalo

## Omezení

- „Bez varovných signálů“ není záruka. Nový phishing nemusí být ještě v žádné databázi, proto appka hlídá i stáří domény a vzhled adresy.
- VirusTotal hash adresy najde jen URL, které už někdo dřív nahlásil. U osobních odkazů je „neznámá“ normální a bezpečnostně správné.
- Detekce napodobenin značek pokrývá jen značky v `lists.js` (hlavně české banky, dopravce a velké služby).

## Licence

[MIT](LICENSE). Přibalená knihovna [jsQR](https://github.com/cozmo/jsQR) (`public/vendor/jsQR.js`) je pod licencí
Apache-2.0, viz [`public/vendor/jsQR.LICENSE.txt`](public/vendor/jsQR.LICENSE.txt).

// Sdílené seznamy pro klienta i Worker. Žádná data se odsud nikam neposílají.

// Zkracovače a "dynamické QR" služby — skrývají skutečný cíl.
export const SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 't.ly', 's.id', 'bit.do',
  'qrco.de', 'q-r.to', 'l.ead.me', 'bl.ink', 'lnkd.in', 'url.cz', 'v.gd', 'shorte.st',
  'adf.ly', 'clck.ru', 'cli.re', 'tr.ee', 'me-qr.com', 'qr.link', 'qrfy.io', 'scan.page',
  'qr1.be', 'qr.io', 'uqr.me', 'lc.chat', 'surl.li', 'gg.gg', 'short.gy', 'shorturl.com',
  // zkracovače velkých firem — samy o sobě nejsou podezřelé, ale cíl skrývají
  'youtu.be', 'amzn.to', 'amzn.eu', 'a.co', 'spoti.fi', 'fb.me', 'forms.gle', 'g.co',
  'maps.app.goo.gl', 'aka.ms', 'apple.co', 'wa.me', 't.me', 'ift.tt', 'trib.al', 'dlvr.it',
]);

export const TRUSTED_SHORTENERS = new Set([
  'youtu.be', 'amzn.to', 'amzn.eu', 'a.co', 'spoti.fi', 'fb.me', 'forms.gle', 'g.co',
  'maps.app.goo.gl', 'aka.ms', 'apple.co', 'wa.me', 't.me',
]);

// Víceúrovňové veřejné přípony (zjednodušený Public Suffix List).
export const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz',
  'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.cn', 'com.tr', 'co.in', 'co.za', 'com.mx',
  'com.pl', 'com.ua', 'co.il', 'com.sg', 'com.hk', 'com.tw', 'co.kr', 'com.ar', 'com.ru',
  'eu.org', 'gov.cz',
]);

// Platformy, kde si subdoménu může založit kdokoliv zdarma.
export const FREE_HOSTING = new Set([
  'github.io', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'web.app',
  'firebaseapp.com', 'herokuapp.com', 'blogspot.com', 'ngrok-free.app', 'ngrok.io',
  'ngrok.app', 'trycloudflare.com', 'glitch.me', 'repl.co', 'replit.app', 'replit.dev',
  'duckdns.org', 'no-ip.org', 'ddns.net', 'azurewebsites.net', 'appspot.com',
  'wixsite.com', 'weebly.com', 'square.site', 'webflow.io', 'framer.website',
  'onrender.com', 'fly.dev', 'surge.sh', '000webhostapp.com', 'r2.dev', 'ipfs.io',
  'cloudfront.net', 'amazonaws.com', 'blob.core.windows.net', 'storage.googleapis.com',
  'mybluehost.me', 'myshopify.com', 'carrd.co', 'godaddysites.com', 'webnode.cz',
  'webnode.page', 'estranky.cz', 'mozello.cz', 'sites.google.com',
]);

// TLD, které se nadprůměrně zneužívají k phishingu/malwaru.
export const ABUSED_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'gq', 'tk', 'ml', 'cf', 'ga', 'buzz',
  'rest', 'cam', 'icu', 'monster', 'sbs', 'cfd', 'quest', 'bond', 'cyou', 'lol', 'mom',
  'support', 'country', 'work', 'fit', 'loan', 'win', 'bid', 'kim', 'men', 'date',
  'review', 'party', 'racing', 'download', 'stream', 'gdn', 'su', 'vip', 'shop', 'online',
  'site', 'live', 'cc', 'ws', 'pw', 'cn', 'ru',
]);

// Značky, které phishing nejčastěji napodobuje. Klíč = podoba v doméně,
// hodnota = oficiální registrovatelné domény.
export const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'],
  apple: ['apple.com', 'icloud.com', 'apple.co'],
  icloud: ['icloud.com', 'apple.com'],
  google: ['google.com', 'google.cz', 'youtube.com', 'goo.gl', 'g.co', 'forms.gle'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'aka.ms'],
  outlook: ['outlook.com', 'live.com', 'microsoft.com', 'office.com'],
  office365: ['office.com', 'microsoft.com'],
  facebook: ['facebook.com', 'fb.me', 'fb.com', 'meta.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  netflix: ['netflix.com'],
  amazon: ['amazon.com', 'amazon.de', 'amazon.co.uk', 'amzn.to', 'amzn.eu', 'a.co'],
  seznam: ['seznam.cz', 'email.cz', 'mapy.cz', 'sbazar.cz', 'firmy.cz', 'novinky.cz'],
  alza: ['alza.cz', 'alza.sk'],
  csob: ['csob.cz', 'csob.sk'],
  airbank: ['airbank.cz'],
  moneta: ['moneta.cz'],
  raiffeisen: ['rb.cz', 'raiffeisen.cz'],
  unicredit: ['unicreditbank.cz', 'unicredit.eu'],
  mbank: ['mbank.cz'],
  ceskasporitelna: ['csas.cz', 'ceskasporitelna.cz'],
  revolut: ['revolut.com', 'revolut.me'],
  ceskaposta: ['postaonline.cz', 'cpost.cz', 'ceskaposta.cz'],
  postaonline: ['postaonline.cz'],
  zasilkovna: ['zasilkovna.cz', 'packeta.com'],
  packeta: ['packeta.com', 'zasilkovna.cz'],
  dhl: ['dhl.com', 'dhl.cz', 'dhl.de'],
  fedex: ['fedex.com'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  steamcommunity: ['steamcommunity.com'],
  discord: ['discord.com', 'discord.gg'],
  roblox: ['roblox.com'],
  telegram: ['telegram.org', 't.me'],
  linkedin: ['linkedin.com', 'lnkd.in'],
  booking: ['booking.com'],
  airbnb: ['airbnb.com', 'airbnb.cz'],
  vinted: ['vinted.cz', 'vinted.com'],
  bazos: ['bazos.cz'],
  vodafone: ['vodafone.cz', 'vodafone.com'],
  tmobile: ['t-mobile.cz'],
  aliexpress: ['aliexpress.com'],
  regiojet: ['regiojet.cz'],
  rohlik: ['rohlik.cz'],
  identitaobcana: ['identitaobcana.cz'],
  mojedatovaschranka: ['mojedatovaschranka.cz'],
};

// Krátké značky — hlídáme jen přesnou shodu labelu v subdoméně (kb.evil.com).
export const SHORT_BRANDS = {
  kb: ['kb.cz', 'mojebanka.cz'],
  fio: ['fio.cz'],
  rb: ['rb.cz'],
  cez: ['cez.cz'],
  ppl: ['ppl.cz'],
  dpd: ['dpd.cz', 'dpd.com'],
  gls: ['gls-czech.com', 'gls-group.eu', 'gls-group.com'],
  ups: ['ups.com'],
  o2: ['o2.cz'],
  cd: ['cd.cz'],
  posta: ['postaonline.cz', 'cpost.cz'],
  ebay: ['ebay.com'],
  uber: ['uber.com'],
  bolt: ['bolt.eu'],
  wolt: ['wolt.com'],
  temu: ['temu.com'],
  ikea: ['ikea.com'],
  mall: ['mall.cz'],
  gov: ['gov.cz'],
};

export const PHISHY_WORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'validate', 'update', 'secure',
  'account', 'wallet', 'confirm', 'password', 'banking', 'unlock', 'suspend', 'billing',
  'refund', 'platba', 'overeni', 'prihlaseni', 'prihlasit', 'doplatek', 'doplatit',
  'zasilka', 'pokuta', 'vratka', 'vraceni', 'odmena', 'vyhra', 'darek', 'clo',
];

export const DANGEROUS_EXTENSIONS = {
  danger: ['apk', 'xapk', 'apks', 'exe', 'msi', 'scr', 'bat', 'cmd', 'com', 'ps1', 'vbs',
    'vbe', 'js', 'jse', 'wsf', 'hta', 'jar', 'dmg', 'pkg', 'ipa', 'mobileconfig', 'lnk', 'reg'],
  warn: ['zip', 'rar', '7z', 'iso', 'img', 'docm', 'xlsm', 'pptm', 'svg', 'html', 'htm'],
};

// Kódy českých bank (pro zobrazení u QR Platby).
export const CZ_BANKS = {
  '0100': 'Komerční banka', '0300': 'ČSOB', '0600': 'MONETA Money Bank', '0710': 'ČNB',
  '0800': 'Česká spořitelna', '2010': 'Fio banka', '2250': 'Banka CREDITAS',
  '2700': 'UniCredit Bank', '3030': 'Air Bank', '3500': 'ING Bank', '5500': 'Raiffeisenbank',
  '5800': 'J&T Banka', '6210': 'mBank',
};

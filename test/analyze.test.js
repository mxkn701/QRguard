import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, verdict, registrableDomain, decodeHost, validIban, czAccountFromIban } from '../public/analyze.js';

const v = (text) => verdict(classify(text).findings);
const has = (text, re) => classify(text).findings.some((f) => re.test(f.text));

test('registrovatelná doména', () => {
  assert.equal(registrableDomain('www.seznam.cz'), 'seznam.cz');
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('evil.github.io'), 'evil.github.io');
  assert.equal(registrableDomain('192.168.1.1'), '192.168.1.1');
});

test('punycode dekódování', () => {
  assert.equal(decodeHost('xn--pypal-4ve.com'), 'pаypal.com'); // cyrilské "а"
  assert.equal(decodeHost('xn--esk-eqa.cz'), 'česk.cz');
});

test('běžné legitimní odkazy jsou OK', () => {
  for (const u of ['https://www.seznam.cz/', 'https://www.paypal.com/cz/home', 'https://www.alza.cz/iphone',
    'https://pineapple.com/', 'https://www.idnes.cz/zpravy/domaci/apple-predstavil-novy-iphone.A251110',
    'https://steakhouse.cz/menu', 'https://www.csob.cz/portal/lide']) {
    assert.equal(v(u), 'ok', u + ' → ' + JSON.stringify(classify(u).findings));
  }
});

test('napodobeniny značek jsou nebezpečné', () => {
  for (const u of ['https://paypa1.com/login', 'https://paypal.com.secure-login.net/', 'https://paypal-secure.com/',
    'https://xn--pypal-4ve.com/', 'https://rnicrosoft.com/', 'https://kb.overeni-uctu.cz/', 'https://alza-vratka.cz/']) {
    assert.equal(v(u), 'danger', u + ' → ' + JSON.stringify(classify(u).findings));
  }
});

test('technické triky', () => {
  assert.equal(v('https://www.google.com@evil.example/'), 'danger');
  assert.equal(v('http://192.168.1.1/admin'), 'danger');
  assert.equal(v('http://3279880203/x'), 'danger'); // desítková IP
  assert.equal(v('https://example.com/app.apk'), 'danger');
  assert.equal(v('javascript:alert(1)'), 'danger');
  assert.equal(v('intent://scan/#Intent;scheme=zxing;package=com.evil;end'), 'danger');
  assert.equal(v('http://example.com/'), 'warn');
  assert.equal(v('https://bit.ly/abc'), 'warn');
  assert.equal(v('https://evil.pages.dev/'), 'warn');
});

test('detekce tajných tokenů', () => {
  assert.ok(has('https://example.com/reset?token=8f7a6b5c4d3e2f1a', /tajný token/));
  assert.ok(has('https://example.com/i/Xk29dkqLm2Pz8sYtQ1vB4nRwE7u', /tajný token/));
  assert.ok(!has('https://example.com/clanek/jak-na-to', /tajný token/));
});

test('IBAN', () => {
  assert.ok(validIban('CZ6508000000192000145399'));
  assert.ok(!validIban('CZ6508000000192000145398'));
  assert.equal(czAccountFromIban('CZ6508000000192000145399').text, '19-2000145399/0800');
});

test('QR Platba', () => {
  const c = classify('SPD*1.0*ACC:CZ5855000000001265098001*AM:480.50*CC:CZK*MSG:PLATBA ZA ZBOZI*X-VS:1234567890');
  assert.equal(c.kind, 'payment');
  assert.ok(c.details.some(([k, val]) => k === 'Číslo účtu' && val.includes('1265098001/5500')));
  assert.equal(verdict(c.findings), 'warn');
  const bad = classify('SPD*1.0*ACC:CZ5855000000001265098002*AM:100');
  assert.equal(verdict(bad.findings), 'danger');
});

test('Wi-Fi', () => {
  const c = classify('WIFI:T:WPA;S:Moje\\;Sit;P:tajneheslo;;');
  assert.equal(c.kind, 'wifi');
  assert.equal(c.wifi.S, 'Moje;Sit');
  assert.ok(!c.details.some(([, val]) => String(val).includes('tajneheslo')), 'heslo se nesmí zobrazit');
  assert.equal(verdict(classify('WIFI:S:Free;T:nopass;;').findings), 'warn');
});

test('telefon a SMS', () => {
  assert.equal(v('tel:+420900123456'), 'danger');
  assert.equal(v('SMSTO:90333:DMS POMOC'), 'danger');
  assert.equal(v('tel:+420777123456'), 'ok');
});

test('text s odkazem', () => {
  const c = classify('Navštivte nás na https://example.cz/akce, díky!');
  assert.equal(c.kind, 'text');
  assert.deepEqual(c.links, ['https://example.cz/akce']);
});

test('doména bez schématu', () => {
  const c = classify('www.seznam.cz');
  assert.equal(c.kind, 'url');
  assert.equal(c.url, 'https://www.seznam.cz/');
});

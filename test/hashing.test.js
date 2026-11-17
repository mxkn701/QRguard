import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sbCanonicalize, sbExpressions, sbHashes, vtUrlIds } from '../public/hashing.js';

const canon = (u) => {
  const c = sbCanonicalize(u);
  return 'http://' + c.host + c.path + (c.query !== null ? '?' + c.query : '');
};

// Příklady z dokumentace Google Safe Browsing ("URLs and Hashing")
const CASES = [
  ['http://host/%25%32%35', 'http://host/%25'],
  ['http://host/%25%32%35%25%32%35', 'http://host/%25%25'],
  ['http://host/%2525252525252525', 'http://host/%25'],
  ['http://host/asdf%25%32%35asd', 'http://host/asdf%25asd'],
  ['http://host/%%%25%32%35asd%%', 'http://host/%25%25%25asd%25%25'],
  ['http://www.google.com/', 'http://www.google.com/'],
  ['http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/', 'http://168.188.99.26/.secure/www.ebay.com/'],
  ['http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/', 'http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/'],
  ['http://www.GOOgle.com/', 'http://www.google.com/'],
  ['http://www.google.com.../', 'http://www.google.com/'],
  ['http://www.google.com/foo\tbar\rbaz\n2', 'http://www.google.com/foobarbaz2'],
  ['http://www.google.com/q?', 'http://www.google.com/q?'],
  ['http://www.google.com/q?r?', 'http://www.google.com/q?r?'],
  ['http://www.google.com/q?r?s', 'http://www.google.com/q?r?s'],
  ['http://evil.com/foo#bar#baz', 'http://evil.com/foo'],
  ['http://evil.com/foo;', 'http://evil.com/foo;'],
  ['http://evil.com/foo?bar;', 'http://evil.com/foo?bar;'],
  ['http://notrailingslash.com', 'http://notrailingslash.com/'],
  ['http://www.gotaport.com:1234/', 'http://www.gotaport.com/'],
  ['  http://www.google.com/  ', 'http://www.google.com/'],
  ['http://host.com/ab%23cd', 'http://host.com/ab%23cd'],
  ['http://host.com//twoslashes?more//slashes', 'http://host.com/twoslashes?more//slashes'],
  ['http://3279880203/blah', 'http://195.127.0.11/blah'],
  ['http://www.google.com/blah/..', 'http://www.google.com/'],
  ['www.google.com/', 'http://www.google.com/'],
  ['www.google.com', 'http://www.google.com/'],
  ['http://www.evil.com/blah#frag', 'http://www.evil.com/blah'],
  ['http://www.google.com/foo/./bar/../baz', 'http://www.google.com/foo/baz'],
];

for (const [input, expected] of CASES) {
  test(`SB kanonizace: ${JSON.stringify(input)}`, () => assert.equal(canon(input), expected));
}

test('SB výrazy: a.b.c/1/2.html?param=1', () => {
  assert.deepEqual(sbExpressions('http://a.b.c/1/2.html?param=1').sort(), [
    'a.b.c/1/2.html?param=1', 'a.b.c/1/2.html', 'a.b.c/', 'a.b.c/1/',
    'b.c/1/2.html?param=1', 'b.c/1/2.html', 'b.c/', 'b.c/1/',
  ].sort());
});

test('SB výrazy: dlouhý host', () => {
  assert.deepEqual(sbExpressions('http://a.b.c.d.e.f.g/1.html').sort(), [
    'a.b.c.d.e.f.g/1.html', 'a.b.c.d.e.f.g/', 'c.d.e.f.g/1.html', 'c.d.e.f.g/',
    'd.e.f.g/1.html', 'd.e.f.g/', 'e.f.g/1.html', 'e.f.g/', 'f.g/1.html', 'f.g/',
  ].sort());
});

test('SB výrazy: IP adresa', () => {
  assert.deepEqual(sbExpressions('http://1.2.3.4/1/').sort(), ['1.2.3.4/1/', '1.2.3.4/'].sort());
});

test('SB výrazy: max 30 a prefixy 4 bajty', async () => {
  const { items, prefixesB64 } = await sbHashes('http://a.b.c.d.e.f.g/1/2/3/4/5/6.html?x=1');
  assert.ok(items.length <= 30);
  for (const p of prefixesB64) assert.equal(Buffer.from(p, 'base64').length, 4);
});

test('SB hash odpovídá SHA-256 výrazu', async () => {
  const { items } = await sbHashes('http://example.com/');
  const e = items.find((i) => i.expr === 'example.com/');
  const { createHash } = await import('node:crypto');
  assert.equal(e.fullHashB64, createHash('sha256').update('example.com/').digest('base64'));
});

test('VT identifikátory jsou jen hex hashe (žádná URL)', async () => {
  const ids = await vtUrlIds('https://example.com/secret?token=abc123');
  assert.ok(ids.length >= 1 && ids.length <= 3);
  for (const id of ids) {
    assert.match(id, /^[0-9a-f]{64}$/);
    assert.ok(!id.includes('example'));
  }
});

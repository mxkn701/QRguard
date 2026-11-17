import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateHost, isPrivateIp, expandV6, clientKey, readBodyLimited } from '../src/net.js';

test('soukromé IPv4 a rezervované rozsahy', () => {
  for (const ip of ['10.1.2.3', '127.0.0.1', '0.0.0.0', '169.254.169.254', '172.16.0.1', '172.31.255.255',
    '192.168.1.1', '100.64.0.1', '192.0.0.1', '192.0.2.5', '198.18.0.1', '198.51.100.1', '203.0.113.9', '224.0.0.1', '255.255.255.255']) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
  for (const ip of ['1.1.1.1', '8.8.8.8', '172.32.0.1', '192.169.0.1', '100.128.0.1']) assert.equal(isPrivateIp(ip), false, ip);
});

test('soukromé IPv6 včetně vložených IPv4', () => {
  for (const ip of ['::1', '::', 'fe80::1', 'fd00::1', 'fc12:3456::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:7f00:1',
    '::ffff:10.0.0.1', '64:ff9b::a00:1', '2002:c0a8:0101::1', '2001:db8::1', '[::1]']) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
  for (const ip of ['2606:4700:4700::1111', '2a00:1450:4001::200e', '::ffff:8.8.8.8', '2002:0808:0808::1']) {
    assert.equal(isPrivateIp(ip), false, ip);
  }
});

test('rozbalení IPv6', () => {
  assert.deepEqual(expandV6('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(expandV6('2001:db8::8:800:200c:417a'), [0x2001, 0xdb8, 0, 0, 8, 0x800, 0x200c, 0x417a]);
  assert.deepEqual(expandV6('::ffff:1.2.3.4'), [0, 0, 0, 0, 0, 0xffff, 0x102, 0x304]);
  assert.equal(expandV6('1:2:3'), null);
  assert.equal(expandV6('1::2::3'), null);
  assert.equal(expandV6('1.2.3.4'), null);
});

test('soukromé názvy hostitelů', () => {
  for (const h of ['localhost', 'printer', 'nas.local', 'x.internal', 'router.lan', 'a.home.arpa', 'db.corp', 'LOCALHOST.', '']) {
    assert.equal(isPrivateHost(h), true, h);
  }
  for (const h of ['example.com', 'seznam.cz', 'localhost.example.com', 'my-home.cz']) assert.equal(isPrivateHost(h), false, h);
});

test('klíč pro omezení pokusů: IPv6 po sítích /64', () => {
  assert.equal(clientKey('2a00:1028:1:2:aaaa::1'), clientKey('2a00:1028:1:2:bbbb:cccc:dddd:eeee'));
  assert.notEqual(clientKey('2a00:1028:1:2::1'), clientKey('2a00:1028:1:3::1'));
  assert.equal(clientKey('1.2.3.4'), 'v4:1.2.3.4');
  assert.notEqual(clientKey('1.2.3.4'), clientKey('1.2.3.5'));
});

test('omezení velikosti těla požadavku', async () => {
  const req = (body) => new Request('https://x/api', { method: 'POST', body });
  assert.equal(await readBodyLimited(req('{"a":1}'), 100), '{"a":1}');
  assert.equal(await readBodyLimited(req('x'.repeat(101)), 100), null);
  const chunked = new Request('https://x/api', {
    method: 'POST', duplex: 'half',
    body: new ReadableStream({ start(c) { for (let i = 0; i < 5; i++) c.enqueue(new Uint8Array(50)); c.close(); } }),
  });
  assert.equal(await readBodyLimited(chunked, 100), null);
});

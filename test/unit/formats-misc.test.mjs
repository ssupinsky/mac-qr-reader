import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { analyze, assertWarning, assertNoWarning, field, action, fuzz } from './_formats-helper.mjs';
import { base45Decode } from '../../src/renderer/parsers/formats/codecs.js';

const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
function base45Encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 2) {
    if (i + 1 < bytes.length) {
      const n = bytes[i] * 256 + bytes[i + 1];
      out += B45[n % 45] + B45[Math.floor(n / 45) % 45] + B45[Math.floor(n / 2025)];
    } else {
      out += B45[bytes[i] % 45] + B45[Math.floor(bytes[i] / 45)];
    }
  }
  return out;
}

test('magnet link', () => {
  const a = analyze('magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=Example%20File&tr=udp%3A%2F%2Ftracker.example.org%3A1337');
  assert.equal(a.type, 'text');
  assert.equal(a.data.format, 'magnet');
  assert.equal(a.data.infoHash, 'c12fe1c06bba254a9dc9f519b335aa7c1367a88a');
  assert.equal(a.data.name, 'Example File');
  assert.deepEqual(a.data.trackers, ['udp://tracker.example.org:1337']);
  assert.equal(field(a, 'Tracker').value, 'tracker.example.org:1337');
  assertWarning(a, 'info', /peer-to-peer/);
  assert.ok(!a.actions.some((x) => x.kind === 'open'));
  const v2 = analyze(`magnet:?xt=urn:btmh:1220${'ab'.repeat(32)}&xl=1048576&dn=a+b`);
  assert.equal(v2.data.infoHashV2, 'ab'.repeat(32));
  assert.equal(v2.data.size, 1048576);
  assert.equal(v2.data.name, 'a b');
  assertWarning(analyze('magnet:?dn=x'), 'caution', /info-hash/);
});

test('ssh / smb / vnc links', () => {
  const a = analyze('ssh://user@host.example:2222');
  assert.equal(a.data.format, 'ssh');
  assert.equal(a.data.host, 'host.example');
  assert.equal(a.data.port, '2222');
  assert.equal(a.data.user, 'user');
  assert.equal(action(a, /ssh command/).value, 'ssh -p 2222 user@host.example');
  assert.ok(!a.actions.some((x) => x.kind === 'open'));
  const fp = analyze('ssh://bob;fingerprint=SHA256-abc@h.example');
  assert.equal(fp.data.user, 'bob');
  assert.equal(fp.data.fingerprint, 'SHA256-abc');
  const smb = analyze('smb://guest:secret@nas.local/share');
  assertWarning(smb, 'caution', /credentials/);
  assertWarning(smb, 'caution', /password/);
  assert.equal(field(smb, 'Password').sensitive, true);
  assert.equal(analyze('vnc://10.0.0.5').title, 'Screen sharing (VNC)');
  assertWarning(analyze('ssh://a b@h'), 'danger', /spaces/);
});

test('HC1 (EU DCC): base45 + zlib header identified, never verified', () => {
  assert.equal(new TextDecoder().decode(base45Decode('%69 VD92EX0')), 'Hello!!');
  assert.equal(new TextDecoder().decode(base45Decode('BB8')), 'AB');
  assert.equal(new TextDecoder().decode(base45Decode('QED8WEX0')), 'ietf!');
  assert.equal(base45Decode('GGW'), null, 'value > 65535');
  assert.equal(base45Decode('A'), null);

  const cose = new Uint8Array([0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x40]);
  const hc1 = `HC1:${base45Encode(deflateSync(cose))}`;
  const a = analyze(hc1);
  assert.equal(a.type, 'text');
  assert.equal(a.data.format, 'hc1');
  assert.equal(a.data.compression, 'zlib');
  assertWarning(a, 'info', /Signature not verified/);
  assert.ok(!JSON.stringify(a).includes('verified"'), 'never claims verified');
  assert.ok(a.actions.every((x) => x.sensitive));
  assert.equal(analyze(`HC1:${base45Encode(cose)}`).data.coseTagged, true);
  assertWarning(analyze('HC1:not base45!'), 'caution', /Base45/);
});

test('SMART Health Card and NZ COVID Pass', () => {
  const a = analyze('shc:/56762909524320603460292437404460');
  assert.equal(a.data.format, 'shc');
  assert.equal(a.data.jws, 'eyJ6aXAiOiJERUYi');
  assertWarning(a, 'info', /incomplete/);
  const chunk = analyze('shc:/1/3/5676');
  assert.deepEqual(chunk.data.chunk, { index: 1, total: 3 });
  assertWarning(chunk, 'info', /Part 1 of 3/);
  assertWarning(analyze('shc:/999'), 'caution', /Malformed/);
  const nz = analyze('NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX');
  assert.equal(nz.data.format, 'nzcp');
  assert.equal(nz.data.version, 1);
});

test('JWT preview (never verified)', () => {
  const a = analyze('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
  assert.equal(a.data.format, 'jwt');
  assert.deepEqual(a.data.header, { alg: 'HS256', typ: 'JWT' });
  assert.deepEqual(a.data.payload, { sub: '1234567890', name: 'John Doe', iat: 1516239022 });
  assert.equal(a.data.iat, '2018-01-18T01:30:22Z');
  assertWarning(a, 'caution', /access token/);
  assertWarning(a, 'info', /Signature not verified/);
  assert.equal(field(a, 'Token').sensitive, true);
  assert.equal(action(a, /Copy token/).sensitive, true);

  const none = analyze('eyJhbGciOiJub25lIn0.eyJleHAiOjF9.');
  assertWarning(none, 'info', /alg: none/);
  assertWarning(none, 'info', /Expired/);
  const jwe = analyze('eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d');
  assert.equal(jwe.data.format, 'jwe');
  assertWarning(jwe, 'info', /Encrypted token/);
  assertWarning(analyze('eyJ.eyJ.x'), 'caution', /not valid JSON/);
});

test('PEM blocks and other keys', () => {
  const priv = analyze('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----');
  assert.equal(priv.data.format, 'pem');
  assert.equal(priv.data.private, true);
  assertWarning(priv, 'danger', /private key/);
  assert.equal(field(priv, 'Private key').sensitive, true);
  const pgp = analyze('-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxx\n-----END PGP PRIVATE KEY BLOCK-----');
  assertWarning(pgp, 'danger', /private key/);
  const cert = analyze('-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUA\n-----END CERTIFICATE-----');
  assertNoWarning(cert, 'danger');
  assertWarning(cert, 'info', /certificate/);
  assert.equal(action(cert, /Save/).saveAs.kind, 'txt');
  assertWarning(analyze('-----BEGIN RSA PRIVATE KEY-----\nMIIE'), 'info', /truncated/);

  const ssh = analyze('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtMzAdtM8AkGXCmGC6vsfdYZTxSlFVQhhEnEA2E8XrX alice@laptop');
  assert.equal(ssh.data.format, 'ssh-public-key');
  assert.equal(ssh.data.comment, 'alice@laptop');
  assert.match(ssh.data.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);

  assertWarning(analyze(`AGE-SECRET-KEY-1${'Q'.repeat(58)}`), 'danger', /age secret key/);
  assertNoWarning(analyze(`age1${'q'.repeat(58)}`), 'danger');
  assertWarning(analyze('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'), 'danger', /WIF/);
  assertWarning(analyze(`0x${'ab'.repeat(32)}`), 'caution', /private key/);
});

test('wallet recovery phrase detection', () => {
  const phrase = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  const a = analyze(phrase);
  assert.equal(a.data.format, 'seed-phrase');
  assert.equal(a.data.wordCount, 12);
  assertWarning(a, 'danger', /recovery phrase/);
  assert.equal(field(a, 'Phrase').sensitive, true);
  assert.ok(a.actions.every((x) => x.sensitive));
  assert.equal(analyze('legal winner thank year wave sausage worth useful legal winner thank'), null, '11 words');
  assert.equal(analyze('Legal winner thank year wave sausage worth useful legal winner thank yellow'), null, 'uppercase');
  assert.equal(analyze(`${phrase} extra`), null, '13 words');
});

test('base64 blobs: text, JSON, binary with magic bytes', () => {
  const t = analyze(Buffer.from('Hello, this is a secret note!').toString('base64'));
  assert.equal(t.data.format, 'base64');
  assert.equal(t.data.decodedKind, 'text');
  assert.equal(t.data.decodedText, 'Hello, this is a secret note!');
  assert.ok(action(t, /decoded text/));
  const j = analyze(Buffer.from('{"a":1,"url":"https://x"}').toString('base64url'));
  assert.equal(j.data.decodedKind, 'json');
  assert.equal(analyze(Buffer.from([0xfb, 0xef, 0xff, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]).toString('base64url')).data.variant, 'url');
  assertWarning(j, 'info', /link/);
  const png = analyze(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 1, 2, 3]).toString('base64'));
  assert.equal(png.data.decodedKind, 'png');
  const save = action(png, /Save/);
  assert.equal(save.saveAs.kind, 'bin');
  assert.equal(save.saveAs.suggestedName, 'decoded.png');
  assert.equal(Buffer.from(save.value, 'base64')[0], 0x89, 'bin save value is base64 of the bytes');
  const gz = analyze(Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6]).toString('base64'));
  assert.equal(gz.data.decodedKind, 'gzip');
  assert.equal(analyze('deadbeefdeadbeefdeadbeefdeadbeef'), null, 'hex is not base64');
  assert.equal(analyze('abcdefghijklmnopqrstuvwxyz'), null, 'one character class');
});

test('misc parsers never throw on malformed input', () => {
  fuzz('magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=Example%20File&tr=udp%3A%2F%2Ft%3A1&xl=12');
  fuzz('ssh://user;fingerprint=x:pw@[::1]:22/path');
  fuzz('shc:/1/2/56762909524320603460292437404460');
  fuzz('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxfQ.sig');
  fuzz('-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----', { step: 4 });
  fuzz('SGVsbG8sIHRoaXMgaXMgYSBzZWNyZXQgbm90ZSE=');
});

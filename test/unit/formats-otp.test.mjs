import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, field, fuzz } from './_formats-helper.mjs';
import { generateOtp } from '../../src/renderer/parsers/totp.js';
import { base64ToBytes, bytesToBase64 } from '../../src/renderer/parsers/formats/codecs.js';
import { decodeMigrationPayload } from '../../src/renderer/parsers/formats/otp-migration.js';

const SECRET_RE = /2FA secret/;

test('otpauth TOTP basic', async () => {
  const a = analyze('otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example');
  assert.equal(a.type, 'otp');
  const { type, issuer, account, secretB32, algorithm, digits, period } = a.data;
  assert.deepEqual({ type, issuer, account, secretB32, algorithm, digits, period },
    { type: 'totp', issuer: 'Example', account: 'alice@google.com', secretB32: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 });
  assertWarning(a, 'caution', SECRET_RE);
  assert.equal(field(a, 'Secret').sensitive, true);
  assert.equal(field(a, 'Secret').value, 'JBSW Y3DP EHPK 3PXP');
  assert.ok(a.actions.filter((x) => x.kind === 'copy').every((x) => x.sensitive));
  assert.equal(a.data.codeComputable, true);
  assert.equal(await generateOtp(a.data.otpParams, 59000), '996554');
});

test('otpauth issuer with encoded space', () => {
  const a = analyze('otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30');
  assert.equal(a.data.issuer, 'ACME Co');
  assert.equal(a.data.account, 'john.doe@email.com');
  assertNoWarning(a, 'caution', /mismatch|Weak|Invalid/);
});

test('otpauth %3A separator, leading spaces, lenient secret', () => {
  const a = analyze('otpauth://totp/Big%20Corporation%3A%20alice%40bigco.com?secret=jbsw y3dp ehpk 3pxp====&issuer=Big%20Corporation');
  assert.equal(a.data.issuer, 'Big Corporation');
  assert.equal(a.data.account, 'alice@bigco.com');
  assert.equal(a.data.secretB32, 'JBSWY3DPEHPK3PXP');
  assertWarning(a, 'info', /normalised/);
});

test('otpauth HOTP with counter computes RFC 4226 code', async () => {
  const a = analyze('otpauth://hotp/Svc:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=5');
  assert.equal(a.data.type, 'hotp');
  assert.equal(a.data.counter, 5);
  assert.equal(await generateOtp(a.data.otpParams), '254676');
  const missing = analyze('otpauth://hotp/Svc:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assertWarning(missing, 'caution', /counter is missing/);
  assert.equal(missing.data.codeComputable, false);
});

test('otpauth issuer mismatch, invalid base32, weak secret, odd params', () => {
  assertWarning(analyze('otpauth://totp/PayPal:me?secret=JBSWY3DPEHPK3PXP&issuer=Evil'), 'caution', /Issuer mismatch.*PayPal.*Evil/);
  const bad = analyze('otpauth://totp/X?secret=ABC1');
  assertWarning(bad, 'caution', /Invalid secret.*"1"/);
  assert.equal(bad.data.codeComputable, false);
  assertWarning(analyze('otpauth://totp/X?secret=ABCDEFGH'), 'caution', /Weak secret \(40 bits/);
  assertWarning(analyze('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=10'), 'caution', /digits/);
  assertWarning(analyze('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&period=60'), 'info', /Non-standard period 60/);
  assertWarning(analyze('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256'), 'info', /ignore/);
  assertWarning(analyze('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=MD5'), 'caution', /Unsupported algorithm/);
  assertWarning(analyze('otpauth://steam/X?secret=JBSWY3DPEHPK3PXP'), 'caution', /Unknown OTP type/);
  assertWarning(analyze('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&image=https://x.example/i.png'), 'caution', /remote image/);
  assertWarning(analyze('otpauth://totp/X'), 'caution', /secret is missing/);
  assertWarning(analyze('otpauth://totp/A:b:c?secret=JBSWY3DPEHPK3PXP'), 'caution', /more than one ":"/);
  assert.equal(analyze('OTPAUTH://TOTP/X?secret=JBSWY3DPEHPK3PXP').data.type, 'totp');
});

const MIGRATION = 'otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUuY29tGgdFeGFtcGxlIAEoATACCjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgtBQ01FIENvOmJvYhoHQUNNRSBDbyACKAIwATisAhABGAEgACj50rT%2F%2F%2F%2F%2F%2F%2F8B';

test('otpauth-migration constructed vector', async () => {
  const a = analyze(MIGRATION);
  assert.equal(a.type, 'otp-migration');
  assert.equal(a.title, 'Authenticator export (2 accounts)');
  assertWarning(a, 'danger', /2 two-factor secrets/);
  assert.equal(a.data.version, 1);
  assert.deepEqual(a.data.batch, { size: 1, index: 0, id: -1234567 });
  const [e1, e2] = a.data.accounts;
  assert.equal(e1.secretB32, 'JBSWY3DPEHPK3PXP');
  assert.equal(e1.name, 'alice@example.com');
  assert.equal(e1.issuer, 'Example');
  assert.deepEqual([e1.type, e1.algorithm, e1.digits], ['totp', 'SHA1', 6]);
  assert.equal(await generateOtp(e1.otpParams, 59000), '996554');
  assert.equal(e2.secretB32, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(e2.name, 'ACME Co:bob');
  assert.equal(e2.account, 'bob');
  assert.deepEqual([e2.type, e2.algorithm, e2.digits, e2.counter], ['hotp', 'SHA256', 8, 300]);
  assert.equal(e2.uri, 'otpauth://hotp/ACME%20Co:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA256&digits=8&counter=300');
  // The generated URI round-trips through the otpauth parser.
  const back = analyze(e2.uri);
  assert.equal(back.data.issuer, 'ACME Co');
  assert.equal(back.data.account, 'bob');
  assert.equal(back.data.counter, 300);
  assert.ok(a.actions.every((x) => x.sensitive));
  assert.ok(field(a, '1. Secret').sensitive);
});

test('otpauth-migration negative cases', () => {
  const m = /data=([^&]+)/.exec(MIGRATION);
  const bytes = base64ToBytes(decodeURIComponent(m[1]));
  const truncated = `otpauth-migration://offline?data=${encodeURIComponent(bytesToBase64(bytes.subarray(0, bytes.length - 3)))}`;
  assertWarning(analyze(truncated), 'caution', /truncated/);
  const wire3 = `otpauth-migration://offline?data=${encodeURIComponent(bytesToBase64(new Uint8Array([0x0b, 0x00])))}`;
  assertWarning(analyze(wire3), 'caution', /wire type 3/);
  assertWarning(analyze('otpauth-migration://offline?foo=1'), 'caution', /data parameter is missing/);
  assertWarning(analyze('otpauth-migration://offline?data=!!!'), 'caution', /not base64/);
  assertWarning(analyze('otpauth-migration://offline?data='), 'caution', /missing/);
  // Unpadded, base64url and space-for-plus variants decode the same.
  const raw = decodeURIComponent(m[1]);
  const variants = [raw.replace(/=+$/, ''), raw.replace(/\+/g, '-').replace(/\//g, '_'), encodeURIComponent(raw).replace(/%2B/g, '+')];
  for (const v of variants) assert.equal(analyze(`otpauth-migration://offline?data=${v}`).data.accounts.length, 2, v);
  // Varint longer than 10 bytes.
  assert.throws(() => decodeMigrationPayload(new Uint8Array([0x10, ...new Array(11).fill(0xff)])), /varint/);
});

test('otpauth-migration batch info and unspecified enums', () => {
  // One entry with only a secret (all enums unspecified), batch 2 of 3.
  const entry = [0x0a, 0x02, 0x48, 0x69];
  const bytes = new Uint8Array([0x0a, entry.length, ...entry, 0x18, 0x03, 0x20, 0x01]);
  const a = analyze(`otpauth-migration://offline?data=${encodeURIComponent(bytesToBase64(bytes))}`);
  assertWarning(a, 'info', /Part 2 of 3/);
  assertWarning(a, 'info', /unspecified/);
  assertWarning(a, 'caution', /weak secret/);
  assert.equal(a.data.accounts[0].type, 'totp');
  const md5 = new Uint8Array([0x0a, 0x06, 0x0a, 0x02, 0x48, 0x69, 0x20, 0x04]);
  assertWarning(analyze(`otpauth-migration://offline?data=${encodeURIComponent(bytesToBase64(md5))}`), 'caution', /MD5/);
});

test('OTP parsers never throw on malformed input', () => {
  fuzz('otpauth://totp/ACME%20Co:john?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60');
  fuzz('otpauth://hotp/S:b?secret=GEZDGNBV&counter=5');
  fuzz(MIGRATION, { step: 3 });
});


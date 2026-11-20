// Payload strings used as object keys must never hit Object.prototype
// ("constructor", "__proto__", "toString", …): no false duplicates, no functions
// leaking into labels, no dropped values.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzePayload } from '../../src/renderer/parsers/index.js';

const KEYS = ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf'];

/** No function source / prototype values anywhere in the analysis. */
function assertClean(a) {
  const json = JSON.stringify(a);
  assert.doesNotMatch(json, /function |\[native code\]|\[object Object\]/, json);
}

test('vCard group / TYPE named like prototype keys', () => {
  for (const k of KEYS) {
    const a = analyzePayload({
      text: ['BEGIN:VCARD', 'VERSION:3.0', 'FN:Jane', `${k}.TEL:+15550100`, `TEL;TYPE=${k}:+15550101`, 'END:VCARD'].join('\r\n'),
    });
    assert.equal(a.type, 'contact');
    assertClean(a);
    const phones = a.fields.filter((f) => /^Phone/.test(f.label));
    assert.equal(phones.length, 2, k);
    assert.ok(!phones.some((f) => /function/.test(f.label)), phones.map((f) => f.label).join());
  }
});

test('vCard Apple label on a "constructor" group is still used', () => {
  const a = analyzePayload({
    text: ['BEGIN:VCARD', 'VERSION:3.0', 'FN:Jane', 'constructor.TEL:+15550100', 'constructor.X-ABLABEL:Office', 'END:VCARD'].join('\r\n'),
  });
  assert.ok(a.fields.some((f) => /^Phone/.test(f.label) && /Office/.test(f.label)), a.fields.map((f) => f.label).join());
});

test('otpauth parameters named like prototype keys are not duplicates', () => {
  const a = analyzePayload({ text: 'otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP&issuer=X&constructor=1&__proto__=2&toString=3' });
  assert.equal(a.type, 'otp');
  assertClean(a);
  assert.ok(!a.warnings.some((w) => /Duplicate/.test(w.message)), a.warnings.map((w) => w.message).join('\n'));
  assert.ok(Object.hasOwn(a.data.extra, '__proto__'));
  assert.equal(a.data.extra.__proto__, '2');
  assert.equal(a.data.extra.constructor, '1');
});

test('otpauth: a real duplicate is still reported', () => {
  const a = analyzePayload({ text: 'otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&constructor=1&constructor=2' });
  assert.ok(a.warnings.some((w) => /Duplicate parameter "constructor"/.test(w.message)));
});

test('BIP21 / EIP-681 parameters named like prototype keys', () => {
  const b = analyzePayload({ text: 'bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.1&constructor=1&__proto__=x' });
  assert.equal(b.type, 'crypto');
  assertClean(b);
  assert.ok(!b.warnings.some((w) => /Duplicate/.test(w.message)), b.warnings.map((w) => w.message).join('\n'));
  assert.ok(Object.hasOwn(b.data.params, '__proto__'));
  assert.equal(b.data.params.constructor, '1');

  const e = analyzePayload({ text: 'ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed?value=1&__proto__=1&constructor=2' });
  assert.equal(e.type, 'crypto');
  assertClean(e);
  assert.ok(Object.hasOwn(e.data.params, '__proto__'));
});

test('lightning / segwit prefixes named like prototype keys', () => {
  for (const text of ['lnconstructor1qqqqqqqqqqqqqq', 'lightning:lnconstructor1qqqqqqqqqqqqqq', 'bitcoin:constructor1qqqqqqqqqqqqqq']) {
    const a = analyzePayload({ text });
    assertClean(a);
  }
});

test('geo / tel / mailto parameters named like prototype keys', () => {
  const g = analyzePayload({ text: 'geo:1,2;__proto__=x;constructor=y' });
  assert.equal(g.type, 'geo');
  assertClean(g);
  const t = analyzePayload({ text: 'tel:+15550100;constructor=1;__proto__=2' });
  assertClean(t);
  const m = analyzePayload({ text: 'mailto:a@example.com?__proto__=x&constructor=y' });
  assert.equal(m.type, 'email');
  assertClean(m);
});

test('currency / country codes named like prototype keys', () => {
  const a = analyzePayload({ text: 'SPD*1.0*ACC:CZ5855000000001265098001*AM:100*CC:constructor' });
  assertClean(a);
  const b = analyzePayload({ text: 'BCD\n002\n1\nSCT\n\nJane\nconstructor12345\nEURconstructor' });
  assertClean(b);
});

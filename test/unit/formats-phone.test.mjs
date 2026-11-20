import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, assertClean, field, action, fuzz } from './_formats-helper.mjs';
import { analyzePhoneNumber } from '../../src/renderer/parsers/formats/phone.js';

test('tel: global number', () => {
  const a = analyze('tel:+1-201-555-0123');
  assert.equal(a.type, 'phone');
  assert.equal(a.data.format, 'tel');
  assert.equal(a.data.number, '+12015550123');
  assert.equal(a.data.display, '+1-201-555-0123');
  assert.equal(action(a, /Call/).value, 'tel:+12015550123');
  assert.equal(field(a, 'Region').value, 'USA / Canada / Caribbean');
  assertClean(a);
});

test('tel: local number with phone-context', () => {
  const a = analyze('tel:7042;phone-context=example.com');
  assert.equal(a.data.global, false);
  assert.equal(a.data.phoneContext, 'example.com');
  assertNoWarning(a, 'info', /country code/);
  assertWarning(analyze('tel:02079460958'), 'info', /No country code/);
});

test('tel: spaces accepted with caution, ext parameter', () => {
  const a = analyze('TEL:+44 20 7946 0958;ext=12');
  assertWarning(a, 'caution', /Spaces/);
  assert.equal(a.data.ext, '12');
  assert.equal(a.data.number, '+442079460958');
  assert.equal(action(a, /Call/).value, 'tel:+442079460958;ext=12');
});

test('tel: USSD / MMI codes are danger and not openable', () => {
  for (const t of ['tel:*21*+15550100%23', 'tel:*2767*3855#', 'tel:**21*1%23', 'tel:%2A%2306%23']) {
    const a = analyze(t);
    assertWarning(a, 'danger', /USSD/);
    assert.equal(a.data.ussd, true, t);
    assert.ok(!a.actions.some((x) => x.kind === 'open'), t);
  }
});

test('tel: other checks', () => {
  assertWarning(analyze('tel:+1234567890123456'), 'caution', /16 digits/);
  assertWarning(analyze('tel:1-800-FLOWERS'), 'info', /vanity/);
  assertWarning(analyze('tel:112'), 'info', /short code/);
  assertWarning(analyze('tel:'), 'caution', /empty/);
  assert.deepEqual(analyzePhoneNumber('+49 (30) 123-45').normalized, '+493012345');
});

test('sms: body, + literal, multiple recipients', () => {
  const a = analyze('sms:+15105550101?body=hello%20there');
  assert.equal(a.type, 'sms');
  assert.deepEqual(a.data.recipients, ['+15105550101']);
  assert.equal(a.data.body, 'hello there');
  assert.equal(action(a, /Messages/).value, 'sms:+15105550101?body=hello%20there');
  assertClean(a);

  const b = analyze('sms:+15105550101,+15105550102?body=a+b');
  assert.equal(b.data.body, 'a+b');
  assert.equal(b.data.recipients.length, 2);
  assertWarning(b, 'info', /2 recipients/);
});

test('SMSTO / MMSTO', () => {
  const a = analyze('SMSTO:+15105550101:Code: 1234');
  assert.equal(a.data.format, 'smsto');
  assert.equal(a.data.body, 'Code: 1234');
  assert.equal(action(a, /Messages/).value, 'sms:+15105550101?body=Code%3A%201234');

  const s = analyze('smsto:12345:STOP');
  assertWarning(s, 'caution', /short code.*premium/);
  assert.equal(analyze('MMSTO:+1555:hi').data.format, 'mmsto');
});

test('sms: iOS-style &body= without ?', () => {
  const a = analyze('sms:+15105550101&body=hi');
  assert.equal(a.data.body, 'hi');
  assert.deepEqual(a.data.recipients, ['+15105550101']);
  assertWarning(a, 'info', /Non-standard/);
});

test('sms: danger/caution checks', () => {
  assertWarning(analyze('sms:*21*1#'), 'danger', /USSD/);
  assertWarning(analyze('sms:+15550100?body=pay%20at%20http://evil.example'), 'caution', /Message link/);
  const z = analyze('sms:+15550100?body=hi%E2%80%8Bthere');
  assertWarning(z, 'caution', /Message/);
  assert.equal(analyze('mms:+15550100?subject=S&body=B').data.subject, 'S');
});

test('FaceTime', () => {
  const a = analyze('facetime:user@example.com');
  assert.equal(a.type, 'phone');
  assert.equal(a.data.service, 'facetime');
  assert.equal(a.data.targetKind, 'email');
  assert.equal(action(a, /FaceTime/).value, 'facetime:user@example.com');

  const b = analyze('facetime-audio://+14085551234');
  assert.equal(b.data.service, 'facetime-audio');
  assert.equal(b.data.target, '+14085551234');
  assert.equal(action(b, /FaceTime Audio/).value, 'facetime-audio:+14085551234');
  assertWarning(analyze('facetime:*21#'), 'danger', /USSD/);
});

test('phone parsers never throw on malformed input', () => {
  fuzz('tel:+1-201-555-0123;ext=5;isub=x;phone-context=+1');
  fuzz('sms:+15105550101,+1?body=hello%20there&subject=x');
  fuzz('SMSTO:+15105550101:Code: 1234');
  fuzz('facetime-audio://+14085551234');
});

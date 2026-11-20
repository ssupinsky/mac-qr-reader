import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, assertClean, action, fuzz } from './_formats-helper.mjs';

test('mailto: single recipient', () => {
  const a = analyze('mailto:alice@example.com');
  assert.equal(a.type, 'email');
  assert.equal(a.data.format, 'mailto');
  assert.deepEqual(a.data.to, ['alice@example.com']);
  assert.equal(action(a, /Compose/).value, 'mailto:alice@example.com');
  assertClean(a);
});

test('mailto: multiple recipients, subject, CRLF body, cc', () => {
  const a = analyze('mailto:a@example.com,b@example.com?subject=Hi%20there&body=Line1%0D%0ALine2&cc=c@example.com');
  assert.deepEqual(a.data.to, ['a@example.com', 'b@example.com']);
  assert.deepEqual(a.data.cc, ['c@example.com']);
  assert.equal(a.data.subject, 'Hi there');
  assert.equal(a.data.body, 'Line1\r\nLine2');
  assert.equal(a.summary, 'Email to a@example.com, b@example.com — “Hi there”');
});

test('mailto: "+" is a literal plus (RFC 6068)', () => {
  const a = analyze('MAILTO:x+tag@example.com?subject=1+1');
  assert.deepEqual(a.data.to, ['x+tag@example.com']);
  assert.equal(a.data.subject, '1+1');
  assert.match(action(a, /Compose/).value, /^mailto:x%2Btag@example\.com\?subject=1%2B1$/);
});

test('mailto: ?to=, bcc caution, attach danger (no Open)', () => {
  const a = analyze('mailto:?to=a@example.com&bcc=spy@example.net&attach=/etc/passwd');
  assert.deepEqual(a.data.to, ['a@example.com']);
  assertWarning(a, 'caution', /Hidden recipients/);
  assertWarning(a, 'danger', /attach a local file "\/etc\/passwd"/);
  assert.ok(!a.actions.some((x) => x.kind === 'open'));
});

test('mailto: homograph domain is danger', () => {
  const a = analyze('mailto:support@pаypal.com');
  assertWarning(a, 'danger', /mixes Latin and Cyrillic/);
  const whole = analyze('mailto:x@аррӏе.com');
  assertWarning(whole, 'danger', /looks like the Latin word "apple"/);
  const ace = analyze('mailto:x@xn--80ak6aa92e.com');
  assertWarning(ace, 'danger', /apple/);
});

test('mailto: other checks', () => {
  assertWarning(analyze('mailto:'), 'info', /No recipient/);
  assertWarning(analyze('mailto:a@x.com,b@x.com,c@x.com,d@x.com,e@x.com,f@x.com'), 'caution', /6 recipients/);
  assertWarning(analyze(`mailto:a@x.com?body=${'x'.repeat(1001)}`), 'info', /Long message/);
  assertWarning(analyze('mailto:not-an-address'), 'caution', /not a valid email/);
  assertWarning(analyze('mailto:a@x.com?body=see%20http://bit.ly/abc'), 'caution', /Message link.*(http|shortened)/);
  assertWarning(analyze('mailto:a@x.com?body=%E0%A4'), 'info', /percent-encoding/);
  assertWarning(analyze('mailto:a@x.com?x-mailer=1'), 'info', /Unusual header/);
});

test('MATMSG vector', () => {
  const a = analyze('MATMSG:TO:a@example.com;SUB:Hello\\; world;BODY:See https://example.com;;');
  assert.equal(a.data.format, 'matmsg');
  assert.deepEqual(a.data.to, ['a@example.com']);
  assert.equal(a.data.subject, 'Hello; world');
  assert.equal(a.data.body, 'See https://example.com');
  assert.equal(action(a, /Compose/).value, 'mailto:a@example.com?subject=Hello%3B%20world&body=See%20https%3A%2F%2Fexample.com');
  assertClean(a);
});

test('SMTP vectors', () => {
  const a = analyze('SMTP:a@example.com:Hello:See you at 10:30');
  assert.equal(a.data.format, 'smtp');
  assert.deepEqual(a.data.to, ['a@example.com']);
  assert.equal(a.data.subject, 'Hello');
  assert.equal(a.data.body, 'See you at 10:30');
  const b = analyze('SMTP:a@example.com:Re: hi:x');
  assert.equal(b.data.subject, 'Re');
  assert.equal(b.data.body, ' hi:x');
  assert.deepEqual(analyze('SMTP:a@example.com').data.to, ['a@example.com']);
});

test('email parsers never throw on malformed input', () => {
  fuzz('mailto:a@example.com,b@x.org?subject=Hi%20there&body=Line1%0D%0ALine2&cc=c@example.com&attach=x');
  fuzz('MATMSG:TO:a@example.com;SUB:Hello\\; world;BODY:x;;');
  fuzz('SMTP:a@example.com:Hello:See you');
  assertNoWarning(analyze('mailto:%'), 'danger');
});

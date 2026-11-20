import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, field, action, fuzz } from './_formats-helper.mjs';
import { buildVcard, foldLine } from '../../src/renderer/parsers/formats/contact.js';

const V30 = 'BEGIN:VCARD\nVERSION:3.0\nN:Doe;John;Q.;Dr.;Jr.\nFN:Dr. John Q. Doe Jr.\nORG:Example\\, Inc.;R&D\nTEL;TYPE=CELL:+1 555 0100\nEMAIL;TYPE=WORK:john@example.com\nADR;TYPE=WORK:;;1 Main St\\nSuite 2;Springfield;IL;62701;USA\nURL:https://example.com\nEND:VCARD';

test('vCard 3.0 structured values and escaping', () => {
  const a = analyze(V30);
  assert.equal(a.type, 'contact');
  assert.equal(a.data.format, 'vcard-3.0');
  assert.equal(a.data.version, '3.0');
  assert.equal(a.data.fn, 'Dr. John Q. Doe Jr.');
  assert.deepEqual(a.data.n, { family: 'Doe', given: 'John', additional: 'Q.', prefix: 'Dr.', suffix: 'Jr.' });
  assert.deepEqual(a.data.org, ['Example, Inc.', 'R&D']);
  assert.deepEqual(a.data.tel, [{ value: '+1 555 0100', types: ['cell'] }]);
  assert.equal(a.data.email[0].value, 'john@example.com');
  assert.equal(a.data.adr[0].street, '1 Main St\nSuite 2');
  assert.deepEqual(a.data.url, ['https://example.com']);
  assert.equal(a.summary, 'Contact: Dr. John Q. Doe Jr. — Example, Inc.');
  const save = action(a, /Save contact/);
  assert.equal(save.kind, 'save');
  assert.deepEqual(save.saveAs, { suggestedName: 'Dr. John Q. Doe Jr.vcf', kind: 'vcf' });
  assert.ok(save.value.startsWith('BEGIN:VCARD\r\nVERSION:3.0\r\n') && save.value.endsWith('END:VCARD\r\n'));
  assert.ok(!/[^\r]\n/.test(save.value), 'CRLF only');
  assertNoWarning(a, 'caution');
  assertNoWarning(a, 'danger');
});

test('vCard 2.1 QUOTED-PRINTABLE with charset and soft line breaks', () => {
  const a = analyze('BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:M=C3=BCller;J=C3=BCrgen\r\nTEL;CELL;PREF:+49301234567\r\nNOTE;ENCODING=QUOTED-PRINTABLE:Line one=0D=0ALine=\r\n two\r\nEND:VCARD');
  assert.equal(a.data.version, '2.1');
  assert.equal(a.data.n.family, 'Müller');
  assert.equal(a.data.n.given, 'Jürgen');
  assert.deepEqual(a.data.tel[0].types, ['cell', 'pref']);
  assert.equal(a.data.note, 'Line one\r\nLine two');
  assert.equal(a.data.fn, 'Jürgen Müller');
});

test('vCard 2.1 ISO-8859-1 charset', () => {
  const a = analyze('BEGIN:VCARD\nVERSION:2.1\nFN;CHARSET=ISO-8859-1;ENCODING=QUOTED-PRINTABLE:Fran=E7ois\nEND:VCARD');
  assert.equal(a.data.fn, 'François');
  const bad = analyze('BEGIN:VCARD\nVERSION:2.1\nFN;CHARSET=X-NOPE;ENCODING=QUOTED-PRINTABLE:A=42\nEND:VCARD');
  assert.equal(bad.data.fn, 'AB');
  assertWarning(bad, 'info', /unknown character set/);
});

test('vCard 4.0 folding, VALUE=uri TEL with quoted TYPE list, remote PHOTO', () => {
  const a = analyze('BEGIN:VCARD\nVERSION:4.0\nFN:Jane\n  Roe\nTEL;VALUE=uri;TYPE="voice,home":tel:+1-555-555-5555;ext=5555\nPHOTO:https://tracker.example/p.png\nEND:VCARD');
  assert.equal(a.data.format, 'vcard-4.0');
  assert.equal(a.data.fn, 'Jane Roe');
  assert.deepEqual(a.data.tel[0], { value: 'tel:+1-555-555-5555;ext=5555', types: ['voice', 'home'] });
  assertWarning(a, 'caution', /remote image/);
  assertNoWarning(a, 'danger');
});

test('vCard TEL with USSD code is danger', () => {
  const a = analyze('BEGIN:VCARD\nVERSION:3.0\nFN:Bank Support\nTEL:*21*+15550100#\nEND:VCARD');
  assertWarning(a, 'danger', /USSD/);
});

test('vCard: multiple cards, truncation, missing version, Apple groups, propagated URL warnings', () => {
  const multi = analyze('BEGIN:VCARD\nVERSION:3.0\nFN:A\nEND:VCARD\nBEGIN:VCARD\nVERSION:3.0\nFN:B\nEND:VCARD');
  assertWarning(multi, 'info', /2 contacts/);
  assert.equal(multi.data.cards.length, 2);
  assert.ok(field(multi, 'Contact 2 · Name'));

  const trunc = analyze('BEGIN:VCARD\nFN:Cut');
  assertWarning(trunc, 'info', /truncated/);
  assertWarning(trunc, 'info', /no VERSION/);
  assert.ok(action(trunc, /Save/).value.endsWith('END:VCARD\r\n'));

  const g = analyze('BEGIN:VCARD\nVERSION:3.0\nFN:G\nitem1.EMAIL:g@example.com\nitem1.X-ABLabel:_$!<Other>!$_\nEND:VCARD');
  assert.equal(g.data.email[0].label, 'Other');
  assert.ok(field(g, 'Email (Other)'));

  const http = analyze('BEGIN:VCARD\nVERSION:3.0\nFN:H\nURL:http://example.com\nEND:VCARD');
  assertWarning(http, 'caution', /^Website: .*http/);

  const inv = analyze('BEGIN:VCARD\nVERSION:3.0\nFN:Pay‮pal\nEND:VCARD');
  assertWarning(inv, 'danger', /^Name: /);
  const mixed = analyze('BEGIN:VCARD\nVERSION:3.0\nFN:Аlice Smith\nEND:VCARD');
  assertWarning(mixed, 'caution', /mixes/);
});

test('vCard inline photo size and lowercase prefix', () => {
  const big = 'A'.repeat(50000);
  const a = analyze(`begin:vcard\nversion:3.0\nfn:P\nPHOTO;ENCODING=b;TYPE=JPEG:${big}\nend:vcard`);
  assert.equal(a.data.photo.kind, 'inline');
  assertWarning(a, 'info', /large embedded photo/);
});

test('MECARD vectors', () => {
  const a = analyze('MECARD:N:Owen,Sean;ADR:76 9th Avenue\\, 4th Floor\\, New York\\, NY 10011;TEL:12125551212;EMAIL:srowen@example.com;;');
  assert.equal(a.type, 'contact');
  assert.equal(a.data.format, 'mecard');
  assert.deepEqual(a.data.name, { last: 'Owen', first: 'Sean' });
  assert.equal(a.data.adr, '76 9th Avenue, 4th Floor, New York, NY 10011');
  assert.deepEqual(a.data.tel, ['12125551212']);
  assert.match(a.data.vcf, /^BEGIN:VCARD\r\nVERSION:3.0\r\nN:Owen;Sean;;;\r\nFN:Sean Owen\r\n/);
  assert.match(a.data.vcf, /ADR:;;76 9th Avenue\\, 4th Floor\\, New York\\, NY 10011;;;;\r\n/);
  assert.equal(action(a, /Save/).saveAs.suggestedName, 'Sean Owen.vcf');

  const b = analyze('MECARD:N:Doe,John;TEL:+15550100;TEL:+15550101;NOTE:a\\;b\\:c;BDAY:19900131;URL:http://example.com;;');
  assert.equal(b.data.tel.length, 2);
  assert.equal(b.data.note, 'a;b:c');
  assert.equal(b.data.bday, '1990-01-31');
  assertWarning(b, 'caution', /Website.*http/);

  const c = analyze('MECARD:N:山田,太郎;SOUND:ヤマダ,タロウ;TEL:0312345678;;');
  assert.deepEqual(c.data.name, { last: '山田', first: '太郎' });
  assert.equal(c.data.sound, 'ヤマダ,タロウ');
  assert.match(c.data.vcf, /X-PHONETIC-LAST-NAME:ヤマダ\r\nX-PHONETIC-FIRST-NAME:タロウ/);

  const d = analyze('MECARD:N:Smith,Ann;ADR:76 9th Avenue, 4th Floor, New York;;');
  assert.equal(d.data.adr, '76 9th Avenue, 4th Floor, New York');
  assertWarning(analyze('MECARD:N:X;TEL:*#06#;;'), 'danger', /USSD/);
});

test('BIZCARD vector', () => {
  const a = analyze('BIZCARD:N:Sean;X:Owen;T:Software Engineer;C:Google;A:76 9th Avenue, New York, NY 10011;B:+12125551212;E:srowen@google.com;;');
  assert.equal(a.data.format, 'bizcard');
  for (const [k, v] of Object.entries({ first: 'Sean', last: 'Owen', title: 'Software Engineer', company: 'Google' })) assert.equal(a.data[k], v);
  assert.deepEqual(a.data.phones, [{ value: '+12125551212', kind: 'work' }]);
  assert.deepEqual(a.data.emails, ['srowen@google.com']);
  assert.match(a.data.vcf, /TEL;TYPE=WORK:\+12125551212/);
  assert.equal(a.summary, 'Contact: Sean Owen — Google');
});

test('vCard generation escapes and folds at 75 octets', () => {
  const vcf = buildVcard({ family: 'O;Brien', given: 'A,B', note: `${'x'.repeat(70)}é\nend`, tel: [{ value: '+1', type: 'CELL' }] });
  assert.match(vcf, /N:O\\;Brien;A\\,B;;;\r\n/);
  for (const line of vcf.split('\r\n')) assert.ok(new TextEncoder().encode(line).length <= 75, line);
  const unfolded = vcf.replace(/\r\n /g, '');
  assert.match(unfolded, new RegExp(`NOTE:${'x'.repeat(70)}é\\\\nend`));
  assert.equal(foldLine('short'), 'short');
  // Never splits a multi-byte code point.
  const f = foldLine('€'.repeat(40));
  assert.ok(!f.includes('�'));
  assert.equal(f.replace(/\r\n /g, ''), '€'.repeat(40));
});

test('contact parsers never throw on malformed input', () => {
  fuzz(V30, { step: 7 });
  fuzz('BEGIN:VCARD\r\nVERSION:2.1\r\nN;ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:M=C3=BC=\r\nller\r\nEND:VCARD', { step: 3 });
  fuzz('MECARD:N:Owen,Sean;TEL:1;EMAIL:a@b.c;BDAY:2000;;');
  fuzz('BIZCARD:N:A;X:B;B:1;E:x;;');
});

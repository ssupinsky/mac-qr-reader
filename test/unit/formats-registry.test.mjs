import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyze, structuredParsers, makeCtx } from './_formats-helper.mjs';

test('registry order follows the dispatcher table (PAYLOADS.md §0.3)', () => {
  const ids = structuredParsers.map((p) => p.id);
  const order = ['vcard', 'ical', 'mecard', 'bizcard', 'wifi', 'dpp', 'otpauth', 'otp-migration', 'epc', 'swiss-qr-bill',
    'spd', 'emv', 'upi', 'bezahlcode', 'crypto', 'mailto', 'matmsg', 'smtp', 'tel', 'facetime', 'sms', 'geo', 'healthcert',
    'magnet', 'remote-access', 'jwt', 'keys', 'seed-phrase', 'api-secret', 'base64'];
  assert.deepEqual(ids, order);
  assert.deepEqual(structuredParsers.filter((p) => p.phase === 'late').map((p) => p.id), ['jwt', 'keys', 'seed-phrase', 'api-secret', 'base64']);
  for (const p of structuredParsers) {
    assert.equal(typeof p.detect, 'function');
    assert.equal(typeof p.parse, 'function');
  }
});

test('leaves plain URLs, JSON, text and unknown schemes to the dispatcher', () => {
  for (const t of ['https://example.com/', 'HTTP://EXAMPLE.COM', 'www.example.com', '{"a":1}', '[1,2]', 'Hello, QR world!',
    'Note: 12:30', 'foo:bar', 'javascript:alert(1)', 'MEBKM:TITLE:x;URL:https://x;;', 'ftp://x.example/', '',
    'CODE128-ABC-12345', '9780306406157', 'sgnl://linkdevice?uuid=abc&pub_key=xyz', 'bitcoinx:abc', 'telnetx://x']) {
    assert.equal(analyze(t), null, `should not claim ${JSON.stringify(t)}`);
  }
});

test('first match wins: containing formats are routed to the outer parser', () => {
  assert.equal(analyze('BEGIN:VCARD\nVERSION:3.0\nURL:https://x.example\nEND:VCARD').parser, 'vcard');
  assert.equal(analyze('SPC\n0200\n1\nCH4431999123000889012').parser, 'swiss-qr-bill');
  assert.equal(analyze('bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?lightning=lnbc1x').parser, 'crypto');
  assert.equal(analyze('otpauth-migration://offline?data=').parser, 'otp-migration');
  assert.equal(analyze('SMSTO:+1:hi').parser, 'sms');
  assert.equal(analyze('facetime-audio:+1').parser, 'facetime');
});

test('detection tolerates surrounding whitespace / BOM and is ASCII case-insensitive', () => {
  assert.equal(analyze('﻿WIFI:S:x;T:nopass;;\n').data.ssid, 'x');
  assert.equal(analyze('  TEL:+15550100 ').data.number, '+15550100');
  assert.equal(analyze('Mailto:a@example.com').parser, 'mailto');
});

test('guard: detect() never throws and parse() returns a caution analysis on internal errors', () => {
  const ctx = makeCtx({ textSafety: () => { throw new Error('boom'); } });
  for (const p of structuredParsers) {
    assert.doesNotThrow(() => p.detect(null, ctx));
    assert.doesNotThrow(() => p.detect(undefined, ctx));
  }
  // A throwing textSafety must not break parsing (report.check swallows it).
  const a = structuredParsers.find((p) => p.id === 'wifi').parse('WIFI:S:x;T:nopass;;', ctx);
  assert.equal(a.type, 'wifi');
  // Stub textSafety without opts support works too.
  const stub = makeCtx({ textSafety: (s) => ({ escaped: s, hasInvisible: false, warnings: [] }) });
  assert.equal(structuredParsers.find((p) => p.id === 'vcard').parse('BEGIN:VCARD\nFN:A\nEND:VCARD', stub).data.fn, 'A');
});

test('ctx.analyzeUrl (optional) is used for embedded links', () => {
  const calls = [];
  const a = analyze('MECARD:N:A;URL:https://evil.example;;', {
    analyzeUrl: (u) => { calls.push(u); return { warnings: [{ level: 'danger', message: 'Imitates paypal' }] }; },
  });
  assert.deepEqual(calls, ['https://evil.example']);
  assert.ok(a.warnings.some((w) => w.level === 'danger' && w.message === 'Website: Imitates paypal'));
});

test('fixture manifest payloads parse sanely', () => {
  const manifest = JSON.parse(readFileSync(new URL('../fixtures/manifest.json', import.meta.url), 'utf8'));
  const expected = {
    'Wi-Fi WPA with escaped chars': ['wifi', (a) => assert.equal(a.data.ssid, 'My;Net,work') || assert.equal(a.data.password, 'p:a\\ss"word')],
    'vCard 3.0': ['contact', (a) => assert.equal(a.data.fn, 'Dr. John Doe')],
    'MECARD contact': ['contact', (a) => assert.deepEqual(a.data.name, { last: 'Doe', first: 'John' })],
    'otpauth TOTP': ['otp', (a) => assert.equal(a.data.issuer, 'Example')],
    // NOTE: the fixture literal in native/gen-fixtures.swift is malformed protobuf (the name
    // "Example:alice@example.com" is 25 bytes but its length prefix says 0x18 = 24), so the
    // parser must report it instead of inventing accounts.
    'Google Authenticator migration': ['otp-migration', (a) => { assert.ok(!a.warnings.some((w) => /truncated/.test(w.message))); assert.ok(a.warnings.some((w) => w.level === 'danger')); }],
    'SEPA EPC (BCD) payment': ['epc-payment', (a) => assert.equal(a.data.amount, '12.50') || assert.equal(a.data.ibanValid, true)],
    'geo URI': ['geo', (a) => assert.equal(a.data.label, 'San Francisco')],
    'mailto URI': ['email', (a) => assert.equal(a.data.subject, 'Hello')],
    'tel URI': ['phone', (a) => assert.equal(a.data.number, '+15551234567')],
    SMSTO: ['sms', (a) => assert.equal(a.data.body, 'Hello there')],
    'iCalendar VEVENT': ['event', (a) => assert.equal(a.data.summary, 'Team meeting')],
    'bitcoin URI': ['crypto', (a) => assert.equal(a.data.addressValid, true)],
  };
  let checked = 0;
  for (const fx of manifest.fixtures) {
    for (const code of fx.expect?.codes ?? []) {
      const a = analyze(code.text, { symbology: code.symbology });
      const exp = expected[fx.description];
      if (exp) {
        assert.ok(a, `${fx.description} detected`);
        assert.equal(a.type, exp[0], fx.description);
        exp[1](a);
        // A valid authenticator export carries secrets, so it is expected to raise a danger warning.
        if (exp[0] !== 'otp-migration') assert.ok(!a.warnings.some((w) => w.level === 'danger'), `${fx.description}: no danger`);
        checked++;
      } else if (a) {
        // Anything else the structured parsers claim must at least be well-formed (analyze asserts shape).
        assert.notEqual(a.type, undefined);
      }
    }
  }
  assert.equal(checked, Object.keys(expected).length);
});

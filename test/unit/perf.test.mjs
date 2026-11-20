// Performance regression tests: no parser may backtrack super-linearly on hostile
// payloads (a QR code is attacker-controlled input and parsing runs on the renderer's
// main thread). Every generator is run through analyzePayload and through each
// format parser's detect + parse at 4 KB, 16 KB and 64 KB.
//
// Set PERF_REPORT=1 to print the slowest cases.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzePayload } from '../../src/renderer/parsers/index.js';
import { structuredParsers } from '../../src/renderer/parsers/formats/registry.js';
import { urlParser } from '../../src/renderer/parsers/url.js';
import { jsonParser } from '../../src/renderer/parsers/json.js';
import { textParser } from '../../src/renderer/parsers/text.js';
import { textSafety } from '../../src/renderer/parsers/text-safety.js';
import { analyzeUrl } from '../../src/renderer/parsers/url.js';
import { BODIES, PREFIXES, gens } from './_perf-generators.mjs';

const KB = 1024;
const SIZES = [4 * KB, 16 * KB, 64 * KB];
const LIMIT_16K_MS = 50;

function time(fn) {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

const ctx = { bytes: null, bytesKind: null, symbology: 'QR', encoding: null, textSafety, analyzeUrl };
const parsers = [...structuredParsers, urlParser, jsonParser, textParser];

// Prefixes for the dispatcher battery and for the catch-all parsers (URL, text); the
// other parsers get every prefix that routes to them.
const SAMPLE = new Set(['', 'BEGIN:VCARD\r\nVERSION:3.0\r\nFN:', 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:',
  'MECARD:N:', 'WIFI:S:', 'otpauth://totp/', '000201', 'bitcoin:', 'lnbc', 'mailto:', 'sms:', 'geo:', 'https://',
  'https://a.com/?', '{"a":"', 'Visit ']);

/** Prefixes that route into `parser` (plus '' for every parser). */
function prefixesFor(parser) {
  const routed = PREFIXES.filter((p) => {
    if (p === '') return true;
    try { return !!parser.detect(`${p}a`, ctx); } catch { return false; }
  });
  return routed.length > 6 ? routed.filter((p) => SAMPLE.has(p)) : routed;
}

/** detect + parse (parse runs even when detect declines: it must be safe on any input). */
function runParser(parser, text) {
  try { parser.detect(text, ctx); } catch { /* guarded by the dispatcher */ }
  try { parser.parse(text, ctx); } catch { /* handled by the dispatcher */ }
}

/**
 * Times `run` over each case at 4, 16 and 64 KB. A measurement over budget is retried
 * (best of 3) so GC pauses and JIT warm-up do not cause false alarms. The 64 KB run is
 * skipped for cases under 1 ms at 16 KB (even quadratic growth stays < 20 ms there).
 * @returns {Map<string, number[]>} name → ms per size
 */
function measure(cases, run) {
  const timeOf = (text, budget) => {
    let ms = time(() => run(text));
    for (let i = 0; i < 2 && ms > budget; i++) ms = Math.min(ms, time(() => run(text)));
    return ms;
  };
  const [small, medium, large] = SIZES.map((n) => cases(n));
  const results = new Map();
  medium.forEach((c, i) => {
    const t4 = timeOf(small[i].text, Infinity);
    const t16 = timeOf(c.text, LIMIT_16K_MS);
    const t64 = t16 >= 1 && t16 <= LIMIT_16K_MS ? timeOf(large[i].text, 6 * t16 + 25) : 0;
    results.set(c.name, [t4, t16, t64]);
  });
  return results;
}

/** Fails on > 50 ms at 16 KB or clearly super-linear growth from 16 KB to 64 KB. */
function check(results, label) {
  const rows = [...results].sort((a, b) => b[1][2] - a[1][2]);
  if (process.env.PERF_REPORT) {
    console.log(`--- ${label}: slowest (4 KB / 16 KB / 64 KB, ms)`);
    for (const [name, ms] of rows.slice(0, 10)) console.log(`${name.padEnd(60)} ${ms.map((x) => x.toFixed(1)).join(' / ')}`);
  }
  const failures = [];
  for (const [name, [, t16, t64]] of rows) {
    if (t16 > LIMIT_16K_MS) failures.push(`${name}: ${t16.toFixed(1)} ms at 16 KB`);
    else if (t64 > 6 * t16 + 25) failures.push(`${name}: super-linear (${t16.toFixed(1)} → ${t64.toFixed(1)} ms)`);
  }
  assert.deepEqual(failures, [], `${label} too slow`);
}

test('analyzePayload is fast and linear on pathological payloads', () => {
  analyzePayload({ text: 'warm up https://example.com' });
  const cases = (n) => gens(n).filter((g) => SAMPLE.has(g.prefix));
  check(measure(cases, (text) => analyzePayload({ text })), 'analyzePayload');
});

test('every parser detect + parse is fast and linear on pathological payloads', () => {
  for (const parser of parsers) {
    const prefixes = prefixesFor(parser);
    const cases = (n) => Object.entries(BODIES).flatMap(([bname, body]) => prefixes.map((p) => (
      { name: `${parser.id} ${JSON.stringify(p)}+${bname}`, text: p + body(Math.max(4, n - p.length)) })));
    check(measure(cases, (text) => runParser(parser, text)), parser.id);
  }
});

test('analyzePayload caps very large payloads', () => {
  const big = `WIFI:S:${'x'.repeat(200 * KB)};;`;
  const a = analyzePayload({ text: big });
  assert.equal(a.type, 'text');
  assert.equal(a.raw.text, big);
  assert.equal(a.raw.length, big.length);
  assert.ok(a.warnings.some((w) => /Very large payload/.test(w.message)));
  assert.ok(a.fields[0].value.length <= 64 * KB + 1);
  const bytes = Buffer.from(big).toString('base64');
  const b = analyzePayload({ text: big, bytesBase64: bytes, bytesKind: 'payload' });
  assert.equal(b.raw.byteLength, Buffer.byteLength(big));
  const t = time(() => analyzePayload({ text: `https://a.com/${'a1.'.repeat(400 * KB)}` }));
  assert.ok(t < 1000, `1.2 MB payload took ${t} ms`);
});

test('fields per analysis are capped', () => {
  const lines = ['BEGIN:VCARD', 'VERSION:3.0', 'FN:X'];
  for (let i = 0; i < 1000; i++) lines.push(`TEL:+1555000${String(i).padStart(4, '0')}`);
  lines.push('END:VCARD');
  const a = analyzePayload({ text: lines.join('\r\n') });
  assert.equal(a.type, 'contact');
  assert.ok(a.fields.length <= 201, `fields: ${a.fields.length}`);
  assert.match(a.fields.at(-1).label, /more/i);
  assert.match(a.fields.at(-1).value, /^…\d+ more/);
});

test('detected links / e-mails / phones in text are capped', () => {
  const text = Array.from({ length: 500 }, (_, i) => `https://a${i}.com x${i}@b.com +1 555 000 ${String(i).padStart(4, '0')}`).join(' ');
  const a = analyzePayload({ text: `note ${text}` });
  assert.equal(a.type, 'text');
  assert.ok(a.data.detected.length <= 20);
});

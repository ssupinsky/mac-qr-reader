// Display truncation (strings.js truncateDisplay) and every site that uses it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { truncateDisplay } from '../../src/renderer/parsers/strings.js';
import { truncate, oneLine, sanitizeFileName } from '../../src/renderer/parsers/formats/util.js';
import { escapeForDisplay } from '../../src/renderer/parsers/text-safety.js';
import { analyzePayload, MAX_ANALYZED_CHARS } from '../../src/renderer/parsers/index.js';

const TOKEN = /\\(?:[\\nrt]|u\{[0-9A-F]+\})/g;
/** The escaped string with complete tokens removed must not contain a stray `\`. */
function assertNoBrokenEscape(s) {
  const body = s.endsWith('…') ? s.slice(0, -1) : s;
  assert.ok(!body.replace(TOKEN, '').includes('\\'), `broken escape in ${JSON.stringify(s)}`);
}
const noLoneSurrogate = (s) => !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);

test('fits: returned unchanged (counted in code points by default)', () => {
  assert.equal(truncateDisplay('abc', 3), 'abc');
  assert.equal(truncateDisplay('😀😀😀', 3), '😀😀😀', '3 code points, 6 UTF-16 units');
  assert.equal(truncateDisplay('x'.repeat(11), 10), `${'x'.repeat(9)}…`);
  assert.equal(truncateDisplay('', 5), '');
  assert.equal(truncateDisplay('abcdef', 4, { ellipsis: '' }), 'abcd');
  assert.equal(truncateDisplay('abcdef', 4, { units: 'utf16', ellipsis: '' }), 'abcd');
});

test('never splits an escapeForDisplay token', () => {
  const esc = escapeForDisplay('LRI x⁦y\\z\n'.repeat(20));
  for (let max = 1; max < 60; max++) {
    const out = truncateDisplay(esc, max);
    assert.ok(Array.from(out).length <= max, `max ${max}: ${out}`);
    assertNoBrokenEscape(out);
  }
  assert.equal(truncateDisplay('LRI x\\u{2066}rest of the line', 9), 'LRI x…');
  assert.equal(truncateDisplay('ab\\\\u{41}cdefgh', 6), 'ab\\\\u…', 'escaped backslash + literal "u{41}"');
  assert.equal(truncateDisplay('ab\\ncdef', 4), 'ab…');
});

test('never splits a surrogate pair; backs off to a grapheme boundary', () => {
  for (let max = 1; max < 12; max++) {
    assert.ok(noLoneSurrogate(truncateDisplay('a😀b😀c😀d😀e😀f😀', max)));
    assert.ok(noLoneSurrogate(truncateDisplay('a😀b😀c😀d😀e😀f😀', max, { units: 'utf16' })));
  }
  const family = '👨‍👩‍👧‍👦'; // 7 code points
  assert.equal(truncateDisplay(family + family, 9), `${family}…`);
  assert.equal(truncateDisplay('ab🇩🇪🇫🇷', 4), 'ab…', 'flag (two regional indicators) kept whole');
  assert.equal(truncateDisplay('abé́́xyz', 5), 'ab…', 'base + combining marks kept whole');
  // A cluster longer than the budget falls back to a code point cut (never empty).
  assert.equal(truncateDisplay(`a${'́'.repeat(100)}`, 5), `a${'́'.repeat(3)}…`);
  assert.equal(truncateDisplay(`a${'́'.repeat(100)}`, 5).length, 5);
});

test('linear in max: a huge string is not scanned to the end', () => {
  const big = 'x'.repeat(5_000_000);
  const t0 = performance.now();
  for (let i = 0; i < 100; i++) truncateDisplay(big, 80);
  assert.ok(performance.now() - t0 < 500);
});

test('util truncate / oneLine / sanitizeFileName use the helper', () => {
  assert.equal(truncate('👨‍👩‍👧‍👦👨‍👩‍👧‍👦', 9), '👨‍👩‍👧‍👦…');
  assert.equal(oneLine('a\nb  c', 140), 'a b c');
  assert.equal(sanitizeFileName('x'.repeat(100)).length, 60);
  assert.ok(!sanitizeFileName('x'.repeat(100)).includes('…'));
  assert.equal(sanitizeFileName(`${'n'.repeat(59)}🇩🇪`), 'n'.repeat(59), 'no half flag in a file name');
});

test('text summary: cut on an escape token boundary (bidi controls)', () => {
  const a = analyzePayload({ text: 'LRI x⁦'.repeat(30) });
  assert.equal(a.type, 'text');
  assert.ok(a.summary.endsWith('…'));
  assert.ok(Array.from(a.summary).length <= 80);
  assertNoBrokenEscape(a.summary);
  for (let n = 70; n < 90; n++) {
    const s = analyzePayload({ text: `${'a'.repeat(n)}‮${'b'.repeat(20)}` }).summary;
    assertNoBrokenEscape(s);
  }
});

test('very large payloads: the analysed head ends on a grapheme boundary', () => {
  const text = `${'a'.repeat(MAX_ANALYZED_CHARS - 1)}🇩🇪 tail`;
  const a = analyzePayload({ text });
  assert.equal(a.data.truncated, true);
  assert.equal(a.data.analyzedLength, MAX_ANALYZED_CHARS - 1);
  assert.ok(noLoneSurrogate(a.fields.find((f) => f.label === 'Text').value));
});

test('data: URL preview: no split surrogate, size of the whole content, UTF-8 cut safe', () => {
  const u = analyzePayload({ text: `data:text/plain,${'a'.repeat(4095)}%F0%9F%98%80tail` });
  const dataUrl = u.data.dataUrl;
  assert.ok(noLoneSurrogate(dataUrl.preview));
  assert.ok(dataUrl.preview.endsWith('…'));
  assert.equal(dataUrl.size, 4095 + 4 + 4);
  const bytes = Buffer.concat([Buffer.alloc(4095, 0x61), Buffer.from('😀 more')]);
  const b = analyzePayload({ text: `data:text/plain;base64,${bytes.toString('base64')}` });
  assert.equal(b.data.dataUrl.preview, `${'a'.repeat(4095)}…`, 'incomplete UTF-8 sequence at the cut is dropped, not a decode failure');
});

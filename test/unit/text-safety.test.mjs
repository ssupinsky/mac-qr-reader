// Text safety (PAYLOADS.md §1): spec vectors, every flagged class, escaping,
// scripts / mixed-script / confusables.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  textSafety, escapeForDisplay, codePointName, scriptProfile, mixedScriptWarnings,
  wholeScriptConfusable, skeleton, detectScripts,
} from '../../src/renderer/parsers/text-safety.js';

const levels = (r) => r.warnings.map((w) => w.level);
const has = (r, level, re) => r.warnings.some((w) => w.level === level && re.test(w.message));

// ---- spec vectors (§1.3 table)
test('vector: RLO in file name → danger, escaped form', () => {
  const r = textSafety('Invoice\u202Etxt.exe');
  assert.ok(has(r, 'danger', /bidirectional/));
  assert.equal(r.escaped, 'Invoice\\u{202E}txt.exe');
  assert.equal(r.hasInvisible, true);
});

test('vector: tag characters → danger with hidden text', () => {
  const r = textSafety('hello\u{E0069}\u{E0067}\u{E006E}\u{E006F}\u{E0072}\u{E0065}');
  assert.ok(has(r, 'danger', /tag/));
  assert.equal(r.hiddenText, 'ignore');
  assert.ok(r.warnings.some((w) => w.message.includes('"ignore"')));
  assert.equal(r.escaped, 'hello\\u{E0069}\\u{E0067}\\u{E006E}\\u{E006F}\\u{E0072}\\u{E0065}');
});

test('vector: Café menu → no warnings', () => {
  const r = textSafety('Café menu');
  assert.deepEqual(r.warnings, []);
  assert.equal(r.hasInvisible, false);
  assert.equal(r.escaped, 'Café menu');
});

test('vector: ZWSP → caution at index 2', () => {
  const r = textSafety('pa\u200Bypal');
  assert.deepEqual(levels(r), ['caution']);
  assert.match(r.warnings[0].message, /ZWSP at position 2/);
  assert.equal(r.findings[0].index, 2);
});

test('vector: ZWJ emoji sequence → no warning', () => {
  const r = textSafety('👩\u200D💻');
  assert.deepEqual(r.warnings, []);
  assert.equal(r.hasInvisible, false);
  assert.equal(r.escaped, '👩\u200D💻');
  assert.deepEqual(textSafety('❤️\u200D🔥').warnings, []);
});

// ---- classes of §1.1
const CASES = [
  ['LRE..PDI bidi controls', ['\u202A', '\u202B', '\u202C', '\u202D', '\u2066', '\u2067', '\u2068', '\u2069'], 'danger'],
  ['bidi marks', ['\u200E', '\u200F', '\u061C'], 'caution'],
  ['zero-width', ['\u200C', '\u2060', 'x\uFEFF'], 'caution'],
  ['lone ZWJ', ['a\u200Db'], 'caution'],
  ['invisible operators / fillers', ['\u2061', '\u2064', '\u00AD', '͏', '᠎', 'ᅟ', 'ᅠ', 'ㅤ', 'ﾠ', '឴', '឵'], 'caution'],
  ['deprecated format', ['\u206A', '\u206F', '￹', '￻'], 'caution'],
  ['variation selector supplement', ['a\u{E0100}', 'a\u{E01EF}'], 'caution'],
  ['C0 controls', ['\u0000', '\u001B[31m', '\u0007', '\u000B', '\u001F'], 'danger'],
  ['DEL / C1', ['\u007F', '\u0080', '\u009F'], 'caution'],
  ['line separators', ['\u2028', '\u2029', '\u0085'], 'caution'],
  ['private use', ['', '', '\u{F0000}', '\u{10FFFD}'], 'caution'],
  ['noncharacters', ['﷐', '﷯', '￾', '\u{1FFFF}'], 'caution'],
  ['lone surrogates', ['\uD800', 'a\uDC00b'], 'danger'],
  ['unusual spaces', ['a b', 'a b', 'a b', 'a b', 'a b', 'a b', 'a　b'], 'info'],
  ['replacement char', ['bad �'], 'info'],
  ['variation selector after plain letter', ['a︁'], 'info'],
  ['other Cf (catch-all)', ['؀', '\u{110BD}'], 'caution'],
  ['unassigned (catch-all)', ['\u{E0080}', '͸'], 'caution'],
];
for (const [name, inputs, level] of CASES) {
  test(`class: ${name} → ${level}`, () => {
    for (const s of inputs) {
      const r = textSafety(s);
      assert.equal(r.warnings.length, 1, `${JSON.stringify(s)}: ${JSON.stringify(r.warnings)}`);
      assert.equal(r.warnings[0].level, level, JSON.stringify(s));
      assert.match(r.escaped, /\\u\{[0-9A-F]{4,}\}/, JSON.stringify(s));
    }
  });
}

test('TAB/LF/CR are fine in multi-line text, flagged in single-line / url contexts', () => {
  assert.deepEqual(textSafety('a\tb\nc\r\nd').warnings, []);
  assert.equal(textSafety('a\tb\nc').hasInvisible, false);
  assert.deepEqual(levels(textSafety('My\nNet', { context: 'single-line' })), ['caution']);
  assert.deepEqual(levels(textSafety('exa\nmple.com', { context: 'url' })), ['danger']);
});

test('context raises levels: spaces caution in single-line, bidi marks danger in url', () => {
  assert.deepEqual(levels(textSafety('a b', { context: 'single-line' })), ['caution']);
  assert.deepEqual(levels(textSafety('a\u200Fb', { context: 'url' })), ['danger']);
});

test('leading BOM is info, non-leading BOM caution', () => {
  assert.deepEqual(levels(textSafety('\uFEFFhello')), ['info']);
  assert.deepEqual(levels(textSafety('hel\uFEFFlo')), ['caution']);
});

test('variation selectors after emoji / CJK are normal', () => {
  assert.deepEqual(textSafety('☺️').warnings, []);
  assert.deepEqual(textSafety('葛︀').warnings, []);
  assert.deepEqual(textSafety('1️⃣').warnings, []);
});

test('label prefixes messages; warnings sorted by severity; grouped per class', () => {
  const r = textSafety('\u200Bx\u202Ey\u200B', { label: 'Network name' });
  assert.deepEqual(levels(r), ['danger', 'caution']);
  assert.ok(r.warnings.every((w) => w.message.startsWith('Network name: ')));
  assert.match(r.warnings[1].message, /positions 0, 4/);
});

test('length counts code points', () => {
  assert.equal(textSafety('a😀b').length, 3);
  assert.equal(textSafety('').length, 0);
});

// ---- escaping (§1.2)
test('escapeForDisplay', () => {
  assert.equal(escapeForDisplay('a\\b'), 'a\\\\b');
  assert.equal(escapeForDisplay('l1\nl2\r\tx'), 'l1\\nl2\\r\\tx');
  assert.equal(escapeForDisplay('l1\nl2', { multiline: true }), 'l1\\n\nl2');
  assert.equal(escapeForDisplay('\u0000\u001B'), '\\u{0000}\\u{001B}');
  assert.equal(escapeForDisplay('x\u{E0041}'), 'x\\u{E0041}');
  assert.equal(escapeForDisplay('Grüße 日本'), 'Grüße 日本');
  assert.equal(escapeForDisplay(null), '');
});

test('escaped form never contains the flagged characters themselves', () => {
  const nasty = '\u202E\u2066\u200B\u0000\u007F\u2028\u{E0061}\uD800\uFEFF';
  const e = escapeForDisplay(`x${nasty}`);
  assert.doesNotMatch(e, /[\u202E\u2066\u200B\u0000\u007F\u2028\uFEFF]|[\uD800-\uDFFF]/u);
});

test('codePointName', () => {
  assert.equal(codePointName(0x202e), 'RLO');
  assert.equal(codePointName(0xe0041), "TAG 'A'");
  assert.equal(codePointName(0xa0), 'NBSP');
  assert.equal(codePointName(0x1b), 'ESC');
  assert.equal(codePointName(0x12345), 'U+12345');
  assert.equal(codePointName(0xe000), 'U+E000');
});

// ---- scripts (§1.3)
test('scriptProfile: single, mixed, allowed CJK combos', () => {
  assert.equal(scriptProfile('paypal').mixed, false);
  assert.equal(scriptProfile('pаypal').mixed, true);
  assert.deepEqual(scriptProfile('pаypal').scripts.sort(), ['Cyrillic', 'Latin']);
  assert.equal(scriptProfile('аррӏе').mixed, false);
  assert.equal(scriptProfile('日本語ひらがなカタカナabc').mixed, false);
  assert.equal(scriptProfile('中文注音ㄅㄆ').mixed, false);
  assert.equal(scriptProfile('한국어漢字abc').mixed, false);
  assert.equal(scriptProfile('한국어ひらがな').mixed, true);
  assert.equal(scriptProfile('αβγ-123').mixed, false);
  assert.equal(scriptProfile('abcαβγ').mixed, true);
  assert.equal(scriptProfile('café-123').mixed, false);
});

test('detectScripts ignores Common / Inherited', () => {
  assert.deepEqual(detectScripts('Hello 123 !'), ['Latin']);
  assert.deepEqual(detectScripts('Привет world'), ['Cyrillic', 'Latin']);
  assert.deepEqual(detectScripts('123 -- ...'), []);
});

test('mixedScriptWarnings per word / per label', () => {
  assert.deepEqual(mixedScriptWarnings('Привет world'), []);
  const w = mixedScriptWarnings('Free pаypal WiFi', { label: 'Network name' });
  assert.equal(w.length, 1);
  assert.equal(w[0].level, 'caution');
  assert.match(w[0].message, /Network name "pаypal" mixes/);
  assert.equal(mixedScriptWarnings('xn.pаypal.com', { labels: true, level: 'danger' })[0].level, 'danger');
});

test('wholeScriptConfusable', () => {
  assert.equal(wholeScriptConfusable('аррӏе'), 'apple');
  assert.equal(wholeScriptConfusable('раураӏ'), 'paypal');
  assert.equal(wholeScriptConfusable('ορο'), 'opo'); // Greek
  assert.equal(wholeScriptConfusable('привет'), null); // в, т, п not strong lookalikes
  assert.equal(wholeScriptConfusable('apple'), null); // Latin
  assert.equal(wholeScriptConfusable('аpple'), null); // mixed, handled by mixed-script
});

test('skeleton', () => {
  assert.equal(skeleton('PаyPal'), 'paypal');
  assert.equal(skeleton('paypa1', { brand: true }), 'paypal');
  assert.equal(skeleton('rnicrosoft', { brand: true }), 'microsoft');
  assert.equal(skeleton('g00gle', { brand: true }), 'google');
  assert.equal(skeleton('ébay'), 'ebay');
  assert.equal(skeleton('paypa1'), 'paypa1'); // digit map only for brand checks
});

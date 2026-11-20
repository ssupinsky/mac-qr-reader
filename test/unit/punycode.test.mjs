// RFC 3492 §7.1 sample strings + domain conversion and malformed-input handling.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decode, encode, domainToUnicode } from '../../src/renderer/parsers/punycode.js';

const cp = (...xs) => String.fromCodePoint(...xs);

// [name, unicode, punycode]
const RFC3492 = [
  ['A Arabic (Egyptian)', cp(0x0644, 0x064A, 0x0647, 0x0645, 0x0627, 0x0628, 0x062A, 0x0643, 0x0644, 0x0645, 0x0648, 0x0634, 0x0639, 0x0631, 0x0628, 0x064A, 0x061F), 'egbpdaj6bu4bxfgehfvwxn'],
  ['B Chinese (simplified)', cp(0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587), 'ihqwcrb4cv8a8dqg056pqjye'],
  ['C Chinese (traditional)', cp(0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD, 0x4E0D, 0x8AAA, 0x4E2D, 0x6587), 'ihqwctvzc91f659drss3x8bo0yb'],
  ['D Czech', 'Pročprostěnemluvíčesky', 'Proprostnemluvesky-uyb24dma41a'],
  ['E Hebrew', cp(0x05DC, 0x05DE, 0x05D4, 0x05D4, 0x05DD, 0x05E4, 0x05E9, 0x05D5, 0x05D8, 0x05DC, 0x05D0, 0x05DE, 0x05D3, 0x05D1, 0x05E8, 0x05D9, 0x05DD, 0x05E2, 0x05D1, 0x05E8, 0x05D9, 0x05EA), '4dbcagdahymbxekheh6e0a7fei0b'],
  ['F Hindi (Devanagari)', cp(0x092F, 0x0939, 0x0932, 0x094B, 0x0917, 0x0939, 0x093F, 0x0928, 0x094D, 0x0926, 0x0940, 0x0915, 0x094D, 0x092F, 0x094B, 0x0902, 0x0928, 0x0939, 0x0940, 0x0902, 0x092C, 0x094B, 0x0932, 0x0938, 0x0915, 0x0924, 0x0947, 0x0939, 0x0948, 0x0902), 'i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd'],
  ['G Japanese', cp(0x306A, 0x305C, 0x307F, 0x3093, 0x306A, 0x65E5, 0x672C, 0x8A9E, 0x3092, 0x8A71, 0x3057, 0x3066, 0x304F, 0x308C, 0x306A, 0x3044, 0x306E, 0x304B), 'n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa'],
  ['H Korean', cp(0xC138, 0xACC4, 0xC758, 0xBAA8, 0xB4E0, 0xC0AC, 0xB78C, 0xB4E4, 0xC774, 0xD55C, 0xAD6D, 0xC5B4, 0xB97C, 0xC774, 0xD574, 0xD55C, 0xB2E4, 0xBA74, 0xC5BC, 0xB9C8, 0xB098, 0xC88B, 0xC744, 0xAE4C), '989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c'],
  ['I Russian', cp(0x043F, 0x043E, 0x0447, 0x0435, 0x043C, 0x0443, 0x0436, 0x0435, 0x043E, 0x043D, 0x0438, 0x043D, 0x0435, 0x0433, 0x043E, 0x0432, 0x043E, 0x0440, 0x044F, 0x0442, 0x043F, 0x043E, 0x0440, 0x0443, 0x0441, 0x0441, 0x043A, 0x0438), 'b1abfaaepdrnnbgefbadotcwatmq2g4l'],
  ['J Spanish', 'PorquénopuedensimplementehablarenEspañol', 'PorqunopuedensimplementehablarenEspaol-fmd56a'],
  ['K Vietnamese', 'TạisaohọkhôngthểchỉnóitiếngViệt', 'TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g'],
  ['L', '3年B組金八先生', '3B-ww4c5e180e575a65lsy2b'],
  ['M', '安室奈美恵-with-SUPER-MONKEYS', '-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n'],
  ['N', 'Hello-Another-Way-それぞれの場所', 'Hello-Another-Way--fc4qua05auwb3674vfr0b'],
  ['O', 'ひとつ屋根の下2', '2-u9tlzr9756bt3uc0v'],
  ['P', 'MajiでKoiする5秒前', 'MajiKoi5-783gue6qz075azm5e'],
  ['Q', 'パフィーdeルンバ', 'de-jg4avhby1noc0d'],
  ['R', 'そのスピードで', 'd9juau41awczczp'],
  ['S', '-> $1.00 <-', '-> $1.00 <--'],
];

for (const [name, unicode, puny] of RFC3492) {
  test(`RFC 3492 sample ${name}: decode`, () => assert.equal(decode(puny), unicode));
  test(`RFC 3492 sample ${name}: encode`, () => assert.equal(encode(unicode), puny));
}

test('decode is case-insensitive for digits (RFC sample I with mixed-case annotation)', () => {
  assert.equal(decode('b1abfaaepdrnnbgefbaDotcwatmq2g4l'), RFC3492[8][1]);
});

test('round-trips astral code points', () => {
  const s = 'a\u{1F600}b\u{10FFFD}';
  assert.equal(decode(encode(s)), s);
});

test('rejects invalid digits', () => {
  assert.throws(() => decode('ab!'), RangeError);
  assert.throws(() => decode('abc-d\u00E9'), RangeError);
});

test('rejects truncated and overflowing input', () => {
  assert.throws(() => decode('99999999999999'), RangeError);
  assert.throws(() => decode('é-abc'), RangeError); // non-basic before delimiter
  assert.throws(() => decode('zz'), RangeError); // truncated variable-length integer
});

test('domainToUnicode decodes xn-- labels and reports invalid ones', () => {
  assert.deepEqual(domainToUnicode('xn--80ak6aa92e.com'), { unicode: 'аррӏе.com', errors: [] });
  assert.deepEqual(domainToUnicode('xn--pypal-4ve.com'), { unicode: 'pаypal.com', errors: [] });
  assert.deepEqual(domainToUnicode('www.example.com'), { unicode: 'www.example.com', errors: [] });
  assert.deepEqual(domainToUnicode('XN--FA-HIA.de'), { unicode: 'faß.de', errors: [] });
  const bad = domainToUnicode('xn--zz.com');
  assert.deepEqual(bad.errors, ['xn--zz']);
  assert.equal(bad.unicode, 'xn--zz.com');
  // An A-label that decodes to pure ASCII is not a valid IDN label.
  assert.deepEqual(domainToUnicode('xn--abc-.com').errors, ['xn--abc-']);
});

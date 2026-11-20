// Dispatcher (PAYLOADS.md §0, §11.9): text decoding from bytes, normalisation,
// ordering against the format registry, error containment, raw + safety.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePayload, analyzeWithRegistry } from '../../src/renderer/parsers/index.js';
import * as registry from '../../src/renderer/parsers/formats/registry.js';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const has = (a, level, re) => a.warnings.some((w) => w.level === level && re.test(w.message));

function assertShape(a) {
  assert.equal(typeof a.type, 'string');
  assert.equal(typeof a.title, 'string');
  assert.equal(typeof a.summary, 'string');
  assert.ok(Array.isArray(a.fields) && Array.isArray(a.warnings) && Array.isArray(a.actions));
  assert.equal(typeof a.data.format, 'string');
  assert.equal(typeof a.raw.text, 'string');
  assert.equal(typeof a.raw.escaped, 'string');
  assert.equal(typeof a.raw.hasInvisible, 'boolean');
  assert.equal(typeof a.raw.length, 'number');
  for (const w of a.warnings) assert.ok(['info', 'caution', 'danger'].includes(w.level));
  const ranks = a.warnings.map((w) => ({ info: 0, caution: 1, danger: 2 })[w.level]);
  assert.deepEqual(ranks, [...ranks].sort((x, y) => y - x), 'warnings sorted by severity');
}

// ---- bytes → text (§11.9 vectors)
test('bytes "Hello" → text', () => {
  const a = analyzePayload({ text: 'Hello', bytesBase64: b64([0x48, 0x65, 0x6c, 0x6c, 0x6f]), bytesKind: 'payload', symbology: 'QR' });
  assertShape(a);
  assert.equal(a.type, 'text');
  assert.equal(a.raw.text, 'Hello');
  assert.equal(a.raw.bytesHex, '48656c6c6f');
  assert.equal(a.raw.encoding, 'utf-8');
  assert.deepEqual(a.warnings, []);
});

test('bytes UTF-8 Café', () => {
  const a = analyzePayload({ text: 'Café', bytesBase64: b64([0x43, 0x61, 0x66, 0xc3, 0xa9]), bytesKind: 'payload' });
  assert.equal(a.raw.text, 'Café');
  assert.equal(a.raw.encoding, 'utf-8');
  assert.equal(a.raw.systemText, undefined);
});

test('bytes not UTF-8 → Latin-1 Café + info', () => {
  const a = analyzePayload({ text: null, bytesBase64: b64([0x43, 0x61, 0x66, 0xe9]), bytesKind: 'payload' });
  assert.equal(a.type, 'text');
  assert.equal(a.raw.text, 'Café');
  assert.equal(a.raw.encoding, 'iso-8859-1');
  assert.ok(has(a, 'info', /ISO-8859-1/));
});

test('system decoder disagreement → info + systemText', () => {
  const a = analyzePayload({ text: 'Caf\uFFFD', bytesBase64: b64([0x43, 0x61, 0x66, 0xe9]), bytesKind: 'payload' });
  assert.equal(a.raw.text, 'Café');
  assert.equal(a.raw.systemText, 'Caf\uFFFD');
  assert.ok(has(a, 'info', /system decoder/));
});

test('binary bytes → binary analysis', () => {
  const a = analyzePayload({ text: null, bytesBase64: b64([0x00, 0x01, 0x02, 0xff, 0xfe]), bytesKind: 'payload' });
  assertShape(a);
  assert.equal(a.type, 'binary');
  assert.equal(a.data.size, 5);
  assert.equal(a.raw.bytesHex, '000102fffe');
  assert.match(a.data.hexDump, /^00000000  00 01 02 ff fe/);
  assert.ok(a.actions.some((x) => x.kind === 'save' && x.saveAs.kind === 'bin'));
  assert.ok(a.actions.some((x) => x.label === 'Copy hex' && x.value === '000102fffe'));
});

test('Shift_JIS bytes → こんにちは', () => {
  const a = analyzePayload({ bytesBase64: b64([0x82, 0xb1, 0x82, 0xf1, 0x82, 0xc9, 0x82, 0xbf, 0x82, 0xcd]), bytesKind: 'payload' });
  assert.equal(a.raw.text, 'こんにちは');
  assert.equal(a.raw.encoding, 'shift_jis');
});

test('many C0 controls → binary; magic bytes guessed', () => {
  const png = analyzePayload({ bytesBase64: b64([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]), bytesKind: 'payload' });
  assert.equal(png.type, 'binary');
  assert.equal(png.data.magic, 'PNG image');
  const gz = analyzePayload({ bytesBase64: b64([0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03]), bytesKind: 'payload' });
  assert.equal(gz.type, 'binary');
});

test('raw codewords are not decoded; Vision text is used', () => {
  const a = analyzePayload({ text: 'https://example.com/', bytesBase64: b64([0x41, 0x14, 0x10]), bytesKind: 'raw', symbology: 'Aztec' });
  assert.equal(a.type, 'url');
  assert.equal(a.raw.bytesKind, 'raw');
  assert.equal(a.raw.bytesHex, '411410');
  const b = analyzePayload({ text: null, bytesBase64: b64([0x41, 0x14, 0x10]), bytesKind: 'raw' });
  assert.equal(b.type, 'binary');
  assert.equal(b.data.format, 'binary-codewords');
});

test('mojibake hint', () => {
  assert.ok(has(analyzePayload({ text: 'CafÃ© menu' }), 'info', /UTF-8 text shown as Latin-1/));
});

test('invalid base64 bytes do not crash', () => {
  const a = analyzePayload({ text: 'hi', bytesBase64: '***', bytesKind: 'payload' });
  assert.equal(a.type, 'text');
  assert.equal(a.raw.text, 'hi');
});

// ---- normalisation (§0.2)
test('trailing whitespace: detected on trimmed copy, raw untouched, info', () => {
  const a = analyzePayload({ text: 'https://example.com/\n' });
  assert.equal(a.type, 'url');
  assert.equal(a.raw.text, 'https://example.com/\n');
  assert.ok(has(a, 'info', /whitespace/));
  assert.equal(a.data.href, 'https://example.com/');
});

test('leading BOM stripped for detection and flagged info', () => {
  const a = analyzePayload({ text: '\uFEFFhttps://example.com/' });
  assert.equal(a.type, 'url');
  assert.ok(has(a, 'info', /byte order mark/));
  assert.equal(a.raw.escaped, '\\u{FEFF}https://example.com/');
});

test('UTF-8 BOM in bytes is preserved in raw text', () => {
  const a = analyzePayload({ bytesBase64: b64([0xef, 0xbb, 0xbf, 0x68, 0x69]), bytesKind: 'payload' });
  assert.equal(a.raw.text, '\uFEFFhi');
});

// ---- dispatch & fallbacks
test('URL vs text: unknown scheme with colon is text', () => {
  assert.equal(analyzePayload({ text: 'Note: 12:30' }).type, 'text');
  assert.equal(analyzePayload({ text: 'foo:bar' }).type, 'text');
  assert.equal(analyzePayload({ text: 'foo://bar' }).type, 'url');
  assert.equal(analyzePayload({ text: 'HTTPS://EXAMPLE.COM' }).type, 'url');
  assert.equal(analyzePayload({ text: 'www.example.com' }).type, 'url');
  assert.equal(analyzePayload({ text: 'MEBKM:TITLE:x;URL:https://example.com;;' }).type, 'url');
});

test('JSON fallback', () => {
  const a = analyzePayload({ text: '{"name":"x","token":"abc","link":"javascript:alert(1)"}' });
  assertShape(a);
  assert.equal(a.type, 'json');
  assert.ok(a.data.sensitivePaths.includes('$.token'));
  assert.ok(a.fields.some((f) => f.label === '$.token' && f.sensitive));
  assert.ok(has(a, 'danger', /Link at \$\.link/));
  assert.equal(analyzePayload({ text: '{not json' }).type, 'text');
  assert.equal(analyzePayload({ text: '[1,2,3]' }).summary, 'JSON array of 3');
  const deep = analyzePayload({ text: `${'['.repeat(100)}${']'.repeat(100)}` });
  assert.equal(deep.type, 'json');
  assert.ok(deep.data.tooDeep);
});

test('text fallback lists embedded links / e-mails / phones', () => {
  const a = analyzePayload({ text: 'Call +1 555 010 0199 or mail bob@example.com, see https://p\u0430ypal.com/x.' });
  assert.equal(a.type, 'text');
  const kinds = a.data.detected.map((d) => d.kind);
  assert.deepEqual(kinds.sort(), ['email', 'phone', 'url']);
  const url = a.data.detected.find((d) => d.kind === 'url');
  assert.equal(url.value, 'https://p\u0430ypal.com/x');
  assert.equal(url.level, 'danger');
  assert.ok(has(a, 'caution', /suspicious link/));
  assert.ok(a.actions.some((x) => x.kind === 'copy'));
});

test('empty input', () => {
  const a = analyzePayload({ text: '' });
  assertShape(a);
  assert.equal(a.type, 'text');
  assert.equal(a.summary, 'Empty');
  assertShape(analyzePayload({}));
  assertShape(analyzePayload());
  assertShape(analyzePayload(null));
});

test('text-safety warnings of raw text are attached to every type', () => {
  const a = analyzePayload({ text: 'https://example.com/?q=\u202Egnp.exe' });
  assert.equal(a.type, 'url');
  assert.ok(has(a, 'danger', /bidirectional/));
  assert.equal(a.raw.hasInvisible, true);
  const t = analyzePayload({ text: 'Invoice\u202Etxt.exe' });
  assert.equal(t.raw.escaped, 'Invoice\\u{202E}txt.exe');
  const h = analyzePayload({ text: 'hi\u{E0069}\u{E0067}' });
  assert.equal(h.raw.hiddenText, 'ig');
});

test('summary of text never carries raw bidi controls', () => {
  const a = analyzePayload({ text: 'Invoice\u202Etxt.exe' });
  assert.doesNotMatch(a.summary, /\u202E/);
});

// ---- ordering against the registry (§0.3)
const fake = (id, prefix, type, extra = {}) => ({
  id,
  detect: (t) => t.slice(0, prefix.length).toUpperCase() === prefix.toUpperCase(),
  parse: () => ({ type, title: id, summary: id, fields: [], warnings: [], actions: [], data: { format: id } }),
  ...extra,
});

test('structured parsers run before URL (otpauth://, bitcoin:, mailto:)', () => {
  const reg = { structuredParsers: [fake('otp', 'otpauth://', 'otp'), fake('crypto', 'bitcoin:', 'crypto'), fake('email', 'mailto:', 'email')] };
  assert.equal(analyzeWithRegistry({ text: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' }, reg).type, 'otp');
  assert.equal(analyzeWithRegistry({ text: 'BITCOIN:BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ' }, reg).type, 'crypto');
  assert.equal(analyzeWithRegistry({ text: 'mailto:a@example.com' }, reg).type, 'email');
  assert.equal(analyzeWithRegistry({ text: 'https://example.com/' }, reg).type, 'url');
});

test('late parsers run after URL and JSON', () => {
  const grabAll = { id: 'grab', detect: () => true, parse: () => ({ type: 'text', title: 'g', summary: 'g', fields: [], warnings: [], actions: [], data: { format: 'grab' } }) };
  const reg1 = { structuredParsers: [{ ...grabAll, phase: 'late' }] };
  const reg2 = { structuredParsers: [], lateParsers: [grabAll] };
  for (const reg of [reg1, reg2]) {
    assert.equal(analyzeWithRegistry({ text: 'https://example.com/' }, reg).type, 'url');
    assert.equal(analyzeWithRegistry({ text: '{"a":1}' }, reg).type, 'json');
    assert.equal(analyzeWithRegistry({ text: 'hello' }, reg).data.format, 'grab');
  }
});

test('a throwing parse falls back to text with an info warning', () => {
  const reg = { structuredParsers: [{ id: 'wifi', detect: (t) => t.startsWith('WIFI:'), parse: () => { throw new Error('boom'); } }] };
  const a = analyzeWithRegistry({ text: 'WIFI:S:x;;' }, reg);
  assertShape(a);
  assert.equal(a.type, 'text');
  assert.ok(has(a, 'info', /could not be parsed/));
});

test('a throwing detect is skipped', () => {
  const reg = { structuredParsers: [{ id: 'bad', detect: () => { throw new Error('x'); }, parse: () => null }] };
  const a = analyzeWithRegistry({ text: 'https://example.com/' }, reg);
  assert.equal(a.type, 'url');
  assert.ok(has(a, 'info', /"bad" failed/));
});

test('invalid parser results are contained; null declines', () => {
  const junk = { structuredParsers: [{ id: 'junk', detect: () => true, parse: () => ({ type: 'nonsense' }) }] };
  assert.equal(analyzeWithRegistry({ text: 'https://example.com/' }, junk).type, 'text');
  const decline = { structuredParsers: [{ id: 'd', detect: () => true, parse: () => null }] };
  assert.equal(analyzeWithRegistry({ text: 'https://example.com/' }, decline).type, 'url');
  const sloppy = {
    structuredParsers: [{
      id: 'sloppy', detect: () => true,
      parse: () => ({ type: 'wifi', title: 7, fields: [{ label: 'a', value: 1 }, null], warnings: [{ level: 'weird', message: 'm' }, 'x'], actions: [{ kind: 'run', value: 'x' }] }),
    }],
  };
  const s = analyzeWithRegistry({ text: 'x' }, sloppy);
  assertShape(s);
  assert.equal(s.type, 'wifi');
  assert.equal(s.title, '7');
  assert.deepEqual(s.fields, [{ label: 'a', value: '1' }]);
  assert.deepEqual(s.actions, []);
  assert.equal(s.data.format, 'sloppy');
  assert.ok(has(s, 'caution', /^m$/));
});

test('parsers receive ctx with bytes, symbology, textSafety, analyzeUrl', () => {
  let seen;
  const reg = { structuredParsers: [{ id: 'spy', detect: (t, ctx) => { seen = ctx; return false; }, parse: () => null }] };
  analyzeWithRegistry({ text: 'BCD', bytesBase64: b64([0x42, 0x43, 0x44]), bytesKind: 'payload', symbology: 'QR' }, reg);
  assert.ok(seen.bytes instanceof Uint8Array);
  assert.deepEqual([...seen.bytes], [0x42, 0x43, 0x44]);
  assert.equal(seen.bytesKind, 'payload');
  assert.equal(seen.symbology, 'QR');
  assert.equal(seen.encoding, 'utf-8');
  assert.equal(typeof seen.textSafety, 'function');
  assert.equal(typeof seen.analyzeUrl, 'function');
  assert.equal(seen.textSafety('a\u200Bb', { context: 'single-line', label: 'X' }).warnings.length, 1);
});

test('real registry: otpauth:// and bitcoin: are not claimed by the URL parser when parsers exist', () => {
  const ids = (registry.structuredParsers || []).map((p) => p.id);
  const otp = analyzePayload({ text: 'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example' });
  const btc = analyzePayload({ text: 'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50' });
  assertShape(otp);
  assertShape(btc);
  if (ids.some((id) => /otp/.test(id))) assert.equal(otp.type, 'otp');
  else assert.equal(otp.type, 'url');
  if (ids.some((id) => /crypto|bitcoin/.test(id))) assert.equal(btc.type, 'crypto');
});

test('never throws on adversarial input', () => {
  const inputs = [
    { text: '\uD800\uDFFF\uDBFF' }, { text: 'x'.repeat(200000) }, { text: 'https://'.repeat(1000) },
    { text: `{"a":${'['.repeat(5000)}` }, { text: 'WIFI:;;;;;;' }, { text: 'BEGIN:VCARD\n' }, { text: '\u0000'.repeat(50) },
    { bytesBase64: b64(Array.from({ length: 3000 }, (_, i) => i & 255)), bytesKind: 'payload' },
    { text: 42 }, { text: 'https://a.b/?' + 'x=1&'.repeat(5000) },
  ];
  for (const input of inputs) assertShape(analyzePayload(input));
});

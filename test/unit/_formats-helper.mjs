// Shared helpers for the structured-format parser tests (not a test file itself).
import assert from 'node:assert/strict';
import { structuredParsers } from '../../src/renderer/parsers/formats/registry.js';
import { textSafety } from '../../src/renderer/parsers/text-safety.js';

export { structuredParsers };

const TYPES = new Set(['url', 'wifi', 'contact', 'otp', 'otp-migration', 'email', 'phone', 'sms', 'geo', 'event',
  'crypto', 'epc-payment', 'swiss-qr-bill', 'payment', 'json', 'text', 'binary']);
const LEVELS = new Set(['info', 'caution', 'danger']);
const OPENABLE = /^(https|http|mailto|tel|sms|facetime|facetime-audio):/i;

/** Builds a parser context with the real text-safety module. */
export function makeCtx(extra = {}) {
  return { bytes: null, bytesKind: null, symbology: 'QR', textSafety, ...extra };
}

/** Asserts that a result follows the Analysis-without-raw contract. */
export function assertShape(a) {
  assert.ok(a && typeof a === 'object', 'analysis object');
  assert.ok(TYPES.has(a.type), `type ${a.type}`);
  assert.equal(typeof a.title, 'string');
  assert.ok(a.title.length > 0, 'title');
  assert.equal(typeof a.summary, 'string');
  assert.ok(a.summary.length > 0 && !/[\r\n]/.test(a.summary), `one-line summary: ${a.summary}`);
  assert.ok(Array.isArray(a.fields));
  for (const f of a.fields) {
    assert.equal(typeof f.label, 'string');
    assert.equal(typeof f.value, 'string');
    assert.ok(f.value.length > 0, `non-empty field ${f.label}`);
  }
  assert.ok(Array.isArray(a.warnings));
  for (const w of a.warnings) {
    assert.ok(LEVELS.has(w.level), `level ${w.level}`);
    assert.equal(typeof w.message, 'string');
  }
  assert.ok(Array.isArray(a.actions));
  for (const x of a.actions) {
    assert.ok(['copy', 'open', 'save'].includes(x.kind), `action kind ${x.kind}`);
    assert.equal(typeof x.label, 'string');
    assert.equal(typeof x.value, 'string');
    if (x.kind === 'open') assert.match(x.value, OPENABLE, `open only allowlisted schemes: ${x.value}`);
    if (x.kind === 'save') {
      assert.ok(x.saveAs && ['vcf', 'ics', 'txt', 'bin'].includes(x.saveAs.kind), 'saveAs.kind');
      assert.ok(x.saveAs.suggestedName && !/[/\\]/.test(x.saveAs.suggestedName), 'safe suggestedName');
    }
  }
  assert.equal(typeof a.data?.format, 'string', 'data.format');
  assert.doesNotThrow(() => JSON.stringify(a), 'JSON-serialisable (no BigInt)');
}

/**
 * Runs the registry like the dispatcher: first parser whose detect() matches.
 * @returns {object|null} analysis + `parser` id, or null when no parser claims the text
 */
export function analyze(text, extra = {}) {
  const ctx = makeCtx(extra);
  const p = structuredParsers.find((x) => x.detect(text, ctx));
  if (!p) return null;
  const a = p.parse(text, ctx);
  assertShape(a);
  assert.equal(a.data.error, undefined, `parser ${p.id} threw: ${a.data.error}`);
  return { ...a, parser: p.id };
}

/** True if a warning with `level` (or any level when null) matches `re`. */
export function hasWarning(a, level, re) {
  return a.warnings.some((w) => (!level || w.level === level) && (!re || re.test(w.message)));
}

export function assertWarning(a, level, re) {
  assert.ok(hasWarning(a, level, re), `expected ${level} ${re} in ${JSON.stringify(a.warnings, null, 1)}`);
}

export function assertNoWarning(a, level, re) {
  assert.ok(!hasWarning(a, level, re), `unexpected ${level} ${re ?? ''} in ${JSON.stringify(a.warnings, null, 1)}`);
}

/** No caution/danger warnings. */
export function assertClean(a) {
  const bad = a.warnings.filter((w) => w.level !== 'info');
  assert.deepEqual(bad, [], 'no caution/danger warnings');
}

export const field = (a, label) => a.fields.find((f) => (label instanceof RegExp ? label.test(f.label) : f.label === label));
export const action = (a, re) => a.actions.find((x) => re.test(x.label));

/**
 * Adversarial robustness: every prefix truncation and a few mutations of `text` must
 * either be rejected by detect() or parse without throwing (checked via the guard).
 */
export function fuzz(text, { step = 1 } = {}) {
  const variants = new Set();
  const chars = Array.from(text);
  for (let i = 0; i <= chars.length; i += step) variants.add(chars.slice(0, i).join(''));
  const junk = ['\u0000', '‮', ';', ':', '%', '%ZZ', '\\', '"', '\n', '\r\n', '=', '?', '&', '#', '\uD800', '9'.repeat(30)];
  for (let i = 0; i < chars.length; i += Math.max(1, Math.floor(chars.length / 12))) {
    for (const j of junk) variants.add(chars.slice(0, i).join('') + j + chars.slice(i).join(''));
    variants.add(chars.slice(0, i).join('') + chars.slice(i + 1).join(''));
  }
  for (const v of variants) analyze(v);
  return variants.size;
}

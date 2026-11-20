// Payload analysis entry point (docs/ARCHITECTURE.md "Parsers contract").
//
// analyzePayload({ text, bytesBase64, bytesKind, symbology }) → Analysis
//
// 1. Choose the text: decode QR byte-mode payload bytes (UTF-8 → Shift_JIS →
//    ISO-8859-1, or binary) when the helper supplied them (`bytesKind: 'payload'`),
//    otherwise use the system decoder's text (PAYLOADS.md §11.9).
// 2. Normalise for detection only (§0.2): strip a leading BOM, trim whitespace.
// 3. Dispatch in the order of §0.3: structured formats from formats/registry.js
//    (rows 2–20), URLs (rows 19 + 21), JSON (22), late heuristics from the registry
//    (rows 23–25), plain text (26). A parser that throws never breaks analysis.
// 4. Attach `raw` and the text-safety warnings of the raw text (§1).
//
// Pure and synchronous; no DOM, no network.

import * as registry from './formats/registry.js';
import { textSafety, escapeForDisplay } from './text-safety.js';
import { urlParser, analyzeUrl } from './url.js';
import { jsonParser } from './json.js';
import { textParser } from './text.js';
import { analyzeBinary } from './binary.js';
import { base64ToBytes, bytesToHex, decodePayloadBytes, latin1Decode } from './bytes.js';
import { truncateDisplay } from './strings.js';

export { textSafety, escapeForDisplay } from './text-safety.js';
export { analyzeUrl } from './url.js';

const TYPES = new Set([
  'url', 'wifi', 'contact', 'otp', 'otp-migration', 'email', 'phone', 'sms', 'geo', 'event', 'crypto',
  'epc-payment', 'swiss-qr-bill', 'payment', 'json', 'text', 'binary',
]);
const LEVELS = new Set(['info', 'caution', 'danger']);
const LEVEL_RANK = { info: 0, caution: 1, danger: 2 };
/** Structured / URL parsing only looks at this much text (UTF-16 units). */
export const MAX_ANALYZED_CHARS = 64 * 1024;
const MAX_FIELDS = 200;
const MAX_WARNINGS = 100;

/** First `n` UTF-16 units of `str` without splitting a surrogate pair or grapheme. */
function head(str, n) {
  return truncateDisplay(str, n, { units: 'utf16', ellipsis: '' });
}

const ENCODING_NAMES = { 'utf-8': 'UTF-8', shift_jis: 'Shift_JIS', 'iso-8859-1': 'ISO-8859-1 (Latin-1)' };

/** Ordered parser lists: [before URL], [after URL + JSON]. */
function parserLists(reg) {
  const structured = Array.isArray(reg?.structuredParsers) ? reg.structuredParsers : [];
  const late = Array.isArray(reg?.lateParsers) ? reg.lateParsers : [];
  const valid = (p) => p && typeof p.detect === 'function' && typeof p.parse === 'function';
  return {
    early: structured.filter((p) => valid(p) && p.phase !== 'late'),
    late: [...structured.filter((p) => valid(p) && p.phase === 'late'), ...late.filter(valid)],
  };
}

/** Coerces a parser result to the Analysis shape (minus raw); null if unusable. */
function sanitize(result, id) {
  if (!result || typeof result !== 'object' || !TYPES.has(result.type)) return null;
  const str = (v, d = '') => (typeof v === 'string' ? v : v == null ? d : String(v));
  const fields = (Array.isArray(result.fields) ? result.fields : [])
    .filter((f) => f && typeof f === 'object' && f.label != null)
    .map((f) => ({ ...f, label: str(f.label), value: str(f.value) }));
  if (fields.length > MAX_FIELDS) {
    const more = fields.length - MAX_FIELDS;
    fields.length = MAX_FIELDS;
    fields.push({ label: 'More fields', value: `…${more} more not shown` });
  }
  const warnings = (Array.isArray(result.warnings) ? result.warnings : [])
    .filter((w) => w && typeof w === 'object' && w.message != null)
    .map((w) => ({ level: LEVELS.has(w.level) ? w.level : 'caution', message: str(w.message) }));
  const actions = (Array.isArray(result.actions) ? result.actions : [])
    .filter((a) => a && typeof a === 'object' && ['copy', 'open', 'save'].includes(a.kind))
    .map((a) => ({ ...a, label: str(a.label), value: str(a.value) }));
  const data = result.data && typeof result.data === 'object' ? { ...result.data } : {};
  if (typeof data.format !== 'string' || !data.format) data.format = id;
  return {
    type: result.type,
    title: str(result.title, 'Code'),
    summary: str(result.summary),
    fields,
    warnings,
    actions,
    data,
  };
}

function mergeWarnings(...lists) {
  const seen = new Set();
  const out = [];
  for (const w of lists.flat()) {
    const k = `${w.level}|${w.message}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(w);
  }
  out.sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
  if (out.length > MAX_WARNINGS) {
    const more = out.length - (MAX_WARNINGS - 1);
    out.length = MAX_WARNINGS - 1;
    out.push({ level: 'info', message: `…${more} more warnings not shown` });
  }
  return out;
}

/**
 * Runs detection + parsing over the ordered parsers.
 * @returns {{ analysis: object, notes: Array<{level, message}> }}
 */
function dispatch(text, ctx, reg) {
  const notes = [];
  const { early, late } = parserLists(reg);
  const order = [...early, urlParser, jsonParser, ...late];
  for (const parser of order) {
    let matched = false;
    try {
      matched = !!parser.detect(text, ctx);
    } catch {
      notes.push({ level: 'info', message: `Format check "${parser.id}" failed; skipped` });
      continue;
    }
    if (!matched) continue;
    let result;
    try {
      result = parser.parse(text, ctx);
    } catch {
      notes.push({ level: 'info', message: `This looks like "${parser.id}" data but could not be parsed; shown as text` });
      break;
    }
    if (result == null) continue; // parser declined after all
    const analysis = sanitize(result, parser.id);
    if (analysis) return { analysis, notes };
    notes.push({ level: 'info', message: `The "${parser.id}" parser returned an invalid result; shown as text` });
    break;
  }
  return { analysis: sanitize(textParser.parse(text, ctx), 'text'), notes };
}

/**
 * Analyses one decoded code.
 * @param {{ text?: string|null, bytesBase64?: string|null, bytesKind?: 'payload'|'raw'|null,
 *   symbology?: string|null }} input
 * @returns {object} Analysis (see docs/ARCHITECTURE.md)
 */
export function analyzePayload(input = {}) {
  return analyzeWithRegistry(input, registry);
}

/**
 * Same as `analyzePayload` with an explicit registry `{ structuredParsers, lateParsers? }`
 * (used by tests to exercise ordering and error handling).
 */
export function analyzeWithRegistry(input, reg) {
  try {
    return analyzeUnsafe(input || {}, reg);
  } catch {
    // Last-resort safety net: never let a payload crash the UI.
    const text = typeof input?.text === 'string' ? input.text : '';
    const safety = textSafety(text);
    return {
      type: 'text', title: 'Text', summary: 'Could not analyse this code', fields: [{ label: 'Text', value: text }],
      warnings: [{ level: 'info', message: 'Analysis failed; showing the raw content' }, ...safety.warnings],
      actions: text ? [{ kind: 'copy', label: 'Copy text', value: text }] : [],
      data: { format: 'text' },
      raw: { text, escaped: safety.escaped, hasInvisible: safety.hasInvisible, length: safety.length },
    };
  }
}

function analyzeUnsafe({ text = null, bytesBase64 = null, bytesKind = null, symbology = null }, reg) {
  const notes = [];
  const bytes = typeof bytesBase64 === 'string' && bytesBase64 ? base64ToBytes(bytesBase64) : null;
  if (bytesBase64 && !bytes) notes.push({ level: 'info', message: 'The code\'s byte data could not be read' });
  const kind = bytes ? bytesKind ?? null : null;

  // ---- 1. Choose the text
  let payloadText = typeof text === 'string' ? text : null;
  let encoding = null;
  let systemText = null;
  let binary = false;
  if (bytes && kind === 'payload') {
    const decoded = decodePayloadBytes(bytes);
    if (decoded.kind === 'binary') {
      binary = true;
      if (payloadText !== null) {
        systemText = payloadText;
        notes.push({ level: 'info', message: 'The bytes are not text; the system decoder read them as text anyway' });
      }
    } else {
      encoding = decoded.encoding;
      if (payloadText !== null && payloadText !== decoded.text) {
        systemText = payloadText;
        notes.push({ level: 'info', message: `Decoded as ${ENCODING_NAMES[encoding]}; the system decoder read it differently` });
      }
      if (encoding !== 'utf-8') notes.push({ level: 'info', message: `Not valid UTF-8; decoded as ${ENCODING_NAMES[encoding]}` });
      payloadText = decoded.text;
    }
  } else if (payloadText === null && bytes) {
    binary = true; // no text, only codewords (or unknown bytes)
  }
  if (payloadText === null) payloadText = binary && bytes ? (systemText ?? latin1Decode(bytes)) : '';

  const safety = textSafety(payloadText);
  const raw = {
    text: payloadText, escaped: safety.escaped, hasInvisible: safety.hasInvisible, length: safety.length,
  };
  if (bytes) {
    raw.bytesHex = bytesToHex(bytes);
    raw.byteLength = bytes.length;
    raw.bytesKind = kind;
  }
  if (encoding) raw.encoding = encoding;
  if (systemText !== null) raw.systemText = systemText;
  if (safety.hiddenText) raw.hiddenText = safety.hiddenText;

  if (binary) {
    const analysis = sanitize(analyzeBinary(bytes, { bytesKind: kind }), 'binary');
    return { ...analysis, warnings: mergeWarnings(analysis.warnings, notes), raw };
  }

  if (/Ã[\x80-\xBF]|Â[\x80-\xBF]/.test(payloadText)) {
    notes.push({ level: 'info', message: 'Looks like UTF-8 text shown as Latin-1 (garbled accents)' });
  }

  // ---- 2. Normalise for detection (§0.2)
  let work = payloadText;
  if (work.startsWith('\uFEFF')) work = work.slice(1); // reported by textSafety (leading BOM)
  const trimmed = work.trim();
  if (trimmed !== work && trimmed !== '') notes.push({ level: 'info', message: 'Payload has leading/trailing whitespace' });

  // ---- 3. Dispatch
  const ctx = {
    bytes, bytesKind: kind, symbology: symbology ?? null, textSafety, analyzeUrl, encoding,
  };
  let analysis;
  let dispatchNotes = [];
  if (trimmed.length > MAX_ANALYZED_CHARS) {
    // Too large for any real format: plain text over the first 64 KB only.
    const shown = head(trimmed, MAX_ANALYZED_CHARS);
    analysis = sanitize(textParser.parse(shown, ctx), 'text');
    analysis.fields = analysis.fields.map((f) => (f.label === 'Text' ? { ...f, value: `${shown}…` } : f));
    analysis.actions = analysis.actions.map((a) => (a.kind === 'copy' ? { ...a, value: trimmed } : a));
    analysis.data = { ...analysis.data, truncated: true, analyzedLength: shown.length };
    notes.push({ level: 'info', message: 'Very large payload — showing the first 64 KB' });
    raw.escaped = `${escapeForDisplay(head(payloadText, MAX_ANALYZED_CHARS))}…`;
  } else {
    ({ analysis, notes: dispatchNotes } = dispatch(trimmed, ctx, reg));
  }

  // ---- 4. Attach raw + safety
  return {
    ...analysis,
    warnings: mergeWarnings(analysis.warnings, dispatchNotes, notes, safety.warnings),
    raw,
  };
}

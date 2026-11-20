// Content-line reader shared by vCard (RFC 2426/6350, vCard 2.1) and iCalendar
// (RFC 5545): line splitting, unfolding, vCard 2.1 QUOTED-PRINTABLE soft breaks,
// parameter parsing with quoted values, and TEXT value unescaping.

import { splitLines } from './util.js';

/**
 * Finds the index of the first `ch` outside double quotes, or -1.
 */
function indexOfUnquoted(str, ch, from = 0) {
  let quoted = false;
  for (let i = from; i < str.length; i++) {
    const c = str[i];
    if (c === '"') quoted = !quoted;
    else if (c === ch && !quoted) return i;
  }
  return -1;
}

/** Splits on `sep` outside double quotes. */
function splitUnquoted(str, sep) {
  const out = [];
  let start = 0;
  for (;;) {
    const i = indexOfUnquoted(str, sep, start);
    if (i < 0) break;
    out.push(str.slice(start, i));
    start = i + 1;
  }
  out.push(str.slice(start));
  return out;
}

/** Parses the part before the value: `[group "."] name *(";" param)`. */
function parseHead(head) {
  const parts = splitUnquoted(head, ';');
  const fullName = parts[0];
  const dot = fullName.lastIndexOf('.');
  const group = dot > 0 ? fullName.slice(0, dot).toLowerCase() : null;
  const name = (dot > 0 ? fullName.slice(dot + 1) : fullName).toUpperCase();
  /** @type {Record<string, string[]>} */
  const params = {};
  for (const p of parts.slice(1)) {
    if (!p) continue;
    const eq = p.indexOf('=');
    let key;
    let values;
    if (eq < 0) {
      // vCard 2.1 bare parameter: an encoding, a charset-less value, or a TYPE value.
      const v = p.trim();
      const upper = v.toUpperCase();
      if (['QUOTED-PRINTABLE', 'BASE64', '8BIT', '7BIT', 'B'].includes(upper)) key = 'ENCODING';
      else key = 'TYPE';
      values = [v];
    } else {
      key = p.slice(0, eq).trim().toUpperCase();
      values = splitUnquoted(p.slice(eq + 1), ',').map((v) => v.replace(/^"(.*)"$/s, '$1'));
      // TYPE="voice,home" — a quoted list.
      if (key === 'TYPE') values = values.flatMap((v) => v.split(','));
    }
    (params[key] ??= []).push(...values.map((v) => v.trim()).filter((v) => v !== ''));
  }
  return { group, name, params };
}

function isQuotedPrintable(head) {
  return /(^|;)\s*(ENCODING\s*=\s*)?QUOTED-PRINTABLE\s*(;|$)/i.test(head);
}

/**
 * Reads content lines.
 * @param {string} text
 * @returns {Array<{ group: string|null, name: string, params: Record<string,string[]>, value: string, line: number }>}
 *   `value` is the raw (still escaped / still QP-encoded) value. Lines without a ':' are skipped.
 */
export function readContentLines(text) {
  const physical = splitLines(text);
  const logical = [];
  for (let i = 0; i < physical.length; i++) {
    const line = physical[i];
    const prev = logical.at(-1);
    if (prev) {
      // vCard 2.1 QUOTED-PRINTABLE soft line break: '=' at the end joins the next line verbatim.
      const colon = indexOfUnquoted(prev.text, ':');
      if (colon > 0 && prev.text.endsWith('=') && isQuotedPrintable(prev.text.slice(0, colon))) {
        prev.text = prev.text.slice(0, -1) + line;
        continue;
      }
      if (line.startsWith(' ') || line.startsWith('\t')) {
        prev.text += line.slice(1);
        continue;
      }
    }
    if (line === '') continue;
    logical.push({ text: line, line: i + 1 });
  }
  const out = [];
  for (const { text: l, line } of logical) {
    const colon = indexOfUnquoted(l, ':');
    if (colon <= 0) continue;
    const head = parseHead(l.slice(0, colon));
    out.push({ ...head, value: l.slice(colon + 1), line });
  }
  return out;
}

/** First value of a parameter (uppercase key), or undefined. */
export function param(cl, key) {
  return cl.params[key]?.[0];
}

/**
 * Decodes a QUOTED-PRINTABLE value to text using `charset`.
 * @returns {{ text: string, charsetOk: boolean }}
 */
export function decodeQuotedPrintable(value, charset = 'utf-8') {
  const bytes = [];
  const enc = new TextEncoder();
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '=' && /^[0-9A-Fa-f]{2}$/.test(value.slice(i + 1, i + 3))) {
      bytes.push(parseInt(value.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      for (const b of enc.encode(c)) bytes.push(b);
    }
  }
  let decoder;
  let charsetOk = true;
  try {
    decoder = new TextDecoder(charset);
  } catch {
    decoder = new TextDecoder('utf-8');
    charsetOk = false;
  }
  return { text: decoder.decode(new Uint8Array(bytes)), charsetOk };
}

/**
 * Splits a structured value on unescaped `sep` (vCard N/ADR/ORG, iCal lists).
 * Escapes are kept for `unescapeText`.
 */
export function splitStructured(value, sep = ';') {
  const out = [];
  let cur = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '\\' && i + 1 < value.length) {
      cur += c + value[i + 1];
      i++;
    } else if (c === sep) {
      out.push(cur);
      cur = '';
    } else {
      cur += c;
    }
  }
  out.push(cur);
  return out;
}

/** TEXT unescaping (RFC 6350 / 5545): `\\ \, \; \n \N`; other backslashes are kept. */
export function unescapeText(value) {
  return String(value).replace(/\\([\\,;nN:])/g, (_, c) => (c === 'n' || c === 'N' ? '\n' : c));
}

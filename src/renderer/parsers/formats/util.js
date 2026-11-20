// Shared helpers for the structured-format parsers (PAYLOADS.md §0, §1).
// Pure ES module: no DOM, no Node APIs, no dependencies outside this directory
// except the text-safety helpers owned by the dispatcher module.

import { mixedScriptWarnings, wholeScriptConfusable } from '../text-safety.js';
import { domainToUnicode } from '../punycode.js';
import { trimWith, trimEndChars, isAsciiSpace, groupThousands, stripTrailing, truncateDisplay } from '../strings.js';

/** URL schemes the main process allows `openExternal` for (ARCHITECTURE.md). */
export const OPENABLE_SCHEMES = new Set(['https', 'http', 'mailto', 'tel', 'sms', 'facetime', 'facetime-audio']);

/**
 * Detection copy of a payload (§0.2): strips one leading BOM and ASCII whitespace at
 * both ends. Parsers work on this copy; the dispatcher reports the whitespace.
 * @param {string} text
 */
export function prep(text) {
  const s = String(text ?? '');
  return trimWith(s.startsWith('\uFEFF') ? s.slice(1) : s, isAsciiSpace);
}

/** ASCII case-insensitive prefix test without lowercasing the payload (§0.2). */
export function hasPrefix(text, prefix) {
  return text.length >= prefix.length && text.slice(0, prefix.length).toUpperCase() === prefix.toUpperCase();
}

/** Returns the first prefix of `prefixes` that `text` starts with (case-insensitive), or null. */
export function matchPrefix(text, prefixes) {
  for (const p of prefixes) if (hasPrefix(text, p)) return p;
  return null;
}

/** Splits on CRLF, LF or CR. */
export function splitLines(text) {
  return String(text).split(/\r\n|\n|\r/);
}

/** Normalises any line endings to CRLF (vCard / iCalendar requirement). */
export function toCrlf(text) {
  return splitLines(text).join('\r\n');
}

/**
 * Percent-decodes as UTF-8, keeping `+` literal (RFC 3986 / 6068 / 5724).
 * Malformed input is returned unchanged with `ok: false`.
 * @returns {{ value: string, ok: boolean }}
 */
export function pctDecode(str, { plusAsSpace = false } = {}) {
  const s = plusAsSpace ? String(str).replace(/\+/g, ' ') : String(str);
  try {
    return { value: decodeURIComponent(s), ok: true };
  } catch {
    return { value: s, ok: false };
  }
}

/** `encodeURIComponent` that never throws (lone surrogates become U+FFFD). */
export function encodeComponent(str) {
  return encodeURIComponent(String(str ?? '').toWellFormed());
}

/**
 * Strict percent-decoding: every `%` must start a `%XX` escape and the bytes must be
 * valid UTF-8. Returns null otherwise.
 */
export function pctDecodeStrict(str) {
  if (/%(?![0-9A-Fa-f]{2})/.test(str)) return null;
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '%') {
      bytes.push(parseInt(str.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      for (const b of new TextEncoder().encode(ch)) bytes.push(b);
    }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

/**
 * Parses a `name=value&…` query keeping raw text and order. Names are lowercased
 * (ASCII), values percent-decoded with `+` literal unless `plusAsSpace`.
 * @returns {Array<{ name: string, rawName: string, raw: string, value: string, ok: boolean }>}
 */
export function parseQuery(query, opts = {}) {
  const out = [];
  if (!query) return out;
  for (const part of String(query).split('&')) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    const rawName = eq < 0 ? part : part.slice(0, eq);
    const raw = eq < 0 ? '' : part.slice(eq + 1);
    const name = pctDecode(rawName).value.replace(/[A-Z]/g, (c) => c.toLowerCase());
    const dec = pctDecode(raw, opts);
    out.push({ name, rawName, raw, value: dec.value, ok: dec.ok });
  }
  return out;
}

/** First value of a parsed query parameter, or undefined. */
export function qget(params, name) {
  const p = params.find((x) => x.name === name);
  return p ? p.value : undefined;
}

/**
 * Splits on `sep` characters that are not escaped by an odd number of backslashes
 * (MECARD / WIFI tokenising, §3.2 / §4.3).
 */
export function splitUnescaped(str, sep) {
  const parts = [];
  let cur = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '\\' && i + 1 < str.length) {
      cur += ch + str[i + 1];
      i++;
    } else if (ch === sep) {
      parts.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts;
}

/** Backslash-unescape: `\X` → `X` for any X; a lone trailing `\` stays. */
export function unescapeBackslash(str) {
  return String(str).replace(/\\([\s\S])/g, '$1');
}

/**
 * DoCoMo-style `KEY:value;KEY:value;;` tokenizer (MECARD, MATMSG, WIFI, BIZCARD).
 * @param {string} body text after the `PREFIX:`
 * @returns {{ tokens: Array<{ key: string, raw: string }>, terminated: boolean, junk: string[] }}
 *   `raw` is still escaped; `junk` lists tokens without a `:`.
 */
export function tokenizeDocomo(body) {
  const parts = splitUnescaped(body, ';');
  const terminated = parts.length >= 3 && parts.at(-1) === '' && parts.at(-2) === '';
  const tokens = [];
  const junk = [];
  for (const part of parts) {
    if (part === '') continue;
    const colon = part.indexOf(':');
    if (colon <= 0) {
      junk.push(part);
      continue;
    }
    tokens.push({ key: part.slice(0, colon).toUpperCase(), raw: part.slice(colon + 1) });
  }
  return { tokens, terminated, junk };
}

/** UTF-8 byte length of a string. */
export function utf8Length(str) {
  return new TextEncoder().encode(String(str)).length;
}

/** Groups a string in blocks of `n` separated by spaces ("DE71 1102 …"). */
export function group(str, n = 4) {
  return String(str).replace(new RegExp(`(.{${n}})(?=.)`, 'g'), '$1 ');
}

/**
 * Groups `str` in blocks of 4 without a 1–2 character fragment at the end: a remainder
 * of 2 becomes two blocks of 3, a remainder of 1 three blocks of 3 ("ABCD … EFG HIJ").
 */
export function groupBalanced(str, n = 4) {
  const s = String(str);
  const rem = s.length % n;
  if (s.length <= n + 2 || n !== 4 || rem === 0 || rem === 3) return group(s, n);
  const tail = rem === 2 ? 6 : 9; // 4+2 → 3+3, 4+4+1 → 3+3+3
  if (s.length < tail) return group(s, n);
  const headPart = s.slice(0, s.length - tail);
  const tailPart = s.slice(s.length - tail).replace(/(.{3})(?=.)/g, '$1 ');
  return headPart ? `${group(headPart, n)} ${tailPart}` : tailPart;
}

/**
 * Display grouping for crypto addresses: a natural prefix is split off first (`0x` of hex
 * addresses → `0x` + 10 groups of 4 for EVM; the `hrp1` of bech32 like `bc1`), the rest is
 * grouped in 4s without short leading/trailing fragments (groupBalanced).
 */
export function groupAddress(address) {
  const s = String(address ?? '');
  let m = /^(0x)([0-9a-fA-F]+)$/.exec(s);
  if (m) return `${m[1]} ${groupBalanced(m[2], 4)}`;
  m = /^([a-z]{1,83}1)([02-9ac-hj-np-z]{6,})$/.exec(s) || /^([A-Z]{1,83}1)([02-9AC-HJ-NP-Z]{6,})$/.exec(s);
  if (m) return `${m[1]} ${groupBalanced(m[2], 4)}`;
  return groupBalanced(s, 4);
}

/** "175tWp … Zv245W" — highlights first/last characters of long addresses (code points). */
export function ends(str, n = 6) {
  const chars = Array.from(String(str));
  return chars.length <= n * 2 + 1 ? chars.join('') : `${chars.slice(0, n).join('')} … ${chars.slice(-n).join('')}`;
}

/**
 * Shortens `str` to `max` code points with an ellipsis, on a code point / escape-token /
 * grapheme boundary (see strings.js truncateDisplay).
 */
export function truncate(str, max = 80) {
  return truncateDisplay(String(str), max);
}

/** One-line version of a string for titles/summaries (control chars → space). */
export function oneLine(str, max = 140) {
  return truncate(String(str).replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, ' ').replace(/\s+/g, ' ').trim(), max);
}

/** Safe file name stem for "Save as…" suggestions (no path separators, controls, bidi…). */
export function sanitizeFileName(name, fallback = 'download') {
  let s = String(name ?? '')
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '')
    .replace(/[/\\:*?"<>|]+/g, ' ')
    .replace(/\s+/g, ' ');
  s = trimWith(s, (ch) => ch === '.' || /\s/.test(ch));
  return truncateDisplay(s, 60, { ellipsis: '' }) || fallback;
}

/** Formats an integer string with thousands separators ("250000" → "250,000"). */
export function thousands(intStr) {
  return groupThousands(String(intStr));
}

/**
 * Converts a decimal string to integer units with `decimals` fraction digits
 * (exact, BigInt). Accepts optional scientific notation (`2.014e18`).
 * @returns {bigint|null} null when malformed or not representable exactly.
 */
export function decimalToUnits(str, decimals, { allowExponent = false } = {}) {
  const m = allowExponent
    ? /^(\d+)(?:\.(\d+))?(?:[eE]\+?(\d+))?$/.exec(String(str))
    : /^(\d*)(?:\.(\d*))?$/.exec(String(str));
  if (!m || (m[1] === '' && !m[2])) return null;
  let intPart = m[1] || '0';
  let frac = m[2] || '';
  const exp = m[3] ? Number(m[3]) : 0;
  if (exp > 1000) return null;
  // Apply exponent by moving the decimal point.
  const digits = intPart + frac;
  let pointPos = intPart.length + exp;
  intPart = digits.slice(0, pointPos).padEnd(pointPos, '0');
  frac = digits.slice(pointPos);
  frac = stripTrailing(frac, '0');
  if (frac.length > decimals) return null;
  return BigInt(intPart || '0') * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
}

/** Formats integer units as a decimal string without trailing zeros ("0.00001"). */
export function unitsToDecimal(units, decimals) {
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const base = 10n ** BigInt(decimals);
  const int = abs / base;
  const frac = stripTrailing((abs % base).toString().padStart(decimals, '0'), '0');
  return `${neg ? '-' : ''}${int}${frac ? `.${frac}` : ''}`;
}

/**
 * Validates the host part of an email address / domain for homographs (§1.3, §5.1).
 * @returns {Array<{level, message}>}
 */
export function domainWarnings(domain, label = 'Domain') {
  const warnings = [];
  if (!domain) return warnings;
  let unicode = domain;
  if (/(^|\.)xn--/i.test(domain)) {
    const res = safeCall(() => domainToUnicode(domain.toLowerCase()), { unicode: domain, errors: [] });
    unicode = res.unicode;
    if (res.errors.length) warnings.push({ level: 'danger', message: `${label} has invalid punycode (${res.errors.join(', ')})` });
  }
  if (/[^\x00-\x7f]/.test(unicode)) {
    const labels = unicode.split('.');
    const mixed = safeCall(() => mixedScriptWarnings(unicode, { labels: true, level: 'danger', label }), []);
    warnings.push(...mixed);
    const tld = labels.at(-1) || '';
    for (const l of labels.slice(0, -1)) {
      const look = safeCall(() => wholeScriptConfusable(l), null);
      if (look && /^[a-z]+$/i.test(tld)) {
        warnings.push({ level: 'danger', message: `${label} "${unicode}" looks like the Latin word "${look}" but uses other letters` });
      }
    }
    warnings.push({ level: 'info', message: `${label} is internationalised: ${unicode}${unicode !== domain ? ` (${domain})` : ''} — check for lookalike letters` });
  }
  return warnings;
}

function safeCall(fn, fallback) {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

/** Loose email address syntax check (`local@domain` with a plausible host). */
export function isEmailAddress(addr) {
  const at = addr.lastIndexOf('@');
  if (at <= 0 || at === addr.length - 1) return false;
  const local = addr.slice(0, at);
  const domain = addr.slice(at + 1);
  if (/[\s<>()[\],;:"\\]/.test(local) && !/^".*"$/.test(local)) return false;
  if (/[\s<>()[\],;:"\\/?#@]/.test(domain)) return false;
  return /^[^.].*[^.]$|^[^.]$/.test(domain) && !domain.includes('..');
}

// ---------------------------------------------------------------------------
// Embedded URL checks (URLs inside contacts, events, emails, payments…)
// ---------------------------------------------------------------------------

const SHORTENERS = new Set(`bit.ly bitly.com j.mp bit.do tinyurl.com tiny.cc t.co goo.gl g.co ow.ly buff.ly is.gd v.gd
rebrand.ly rb.gy cutt.ly shorturl.at t.ly s.id tr.ee linktr.ee lnkd.in fb.me m.me amzn.to amzn.eu a.co wp.me
ift.tt dlvr.it trib.al soo.gd x.co clck.ru shorte.st adf.ly ouo.io bl.ink short.io sl.ink hyperurl.co aka.ms
apple.co spoti.fi msft.it flic.kr db.tt 1drv.ms page.link app.link onelink.me qrco.de q-r.to l.ead.me qr.codes
qrfy.io me-qr.com scnv.io bitly.page`.split(/\s+/));

/** Extracts http(s) links from free text. */
export function extractUrls(text) {
  return [...String(text ?? '').matchAll(/https?:\/\/[^\s<>"'`]+/gi)].map((m) => trimEndChars(m[0], '.,;:!?)]'));
}

/**
 * Warnings for a URL embedded in another payload. Uses the full URL analysis from
 * `ctx.analyzeUrl(url)` when the dispatcher provides it; otherwise a compact offline
 * subset of §2 (scheme, userinfo, IP host, IDN, shorteners, control chars).
 * Messages are prefixed with `label`.
 * @returns {Array<{level, message}>}
 */
export function embeddedUrlWarnings(url, ctx, label = 'Link') {
  const prefix = (m) => `${label}: ${m}`;
  if (typeof ctx?.analyzeUrl === 'function') {
    try {
      const a = ctx.analyzeUrl(url);
      if (a && Array.isArray(a.warnings)) return a.warnings.map((w) => ({ level: w.level, message: prefix(w.message) }));
    } catch {
      /* fall through to the built-in subset */
    }
  }
  const out = [];
  const raw = String(url);
  if (/[\u0000-\u0020\u007f]/.test(raw)) out.push({ level: 'danger', message: prefix('contains spaces or control characters — it may open somewhere else') });
  let u;
  try {
    u = new URL(raw);
  } catch {
    out.push({ level: 'caution', message: prefix(`malformed link "${truncate(raw, 60)}"`) });
    return out;
  }
  const scheme = u.protocol.slice(0, -1);
  if (scheme === 'http') out.push({ level: 'caution', message: prefix(`not encrypted (http) — ${u.hostname}`) });
  else if (scheme !== 'https') {
    const bad = ['javascript', 'vbscript', 'data', 'file', 'blob', 'filesystem'].includes(scheme);
    out.push({ level: bad ? 'danger' : 'caution', message: prefix(`unusual link type "${scheme}:"`) });
  }
  if (u.username || u.password) out.push({ level: 'danger', message: prefix(`text before "@" is not the website — this link goes to ${u.hostname}`) });
  if (/^\d+\.\d+\.\d+\.\d+$|^\[/.test(u.hostname)) out.push({ level: 'caution', message: prefix(`points to a raw IP address (${u.hostname})`) });
  if (/\\/.test(raw.split(/[?#]/)[0])) out.push({ level: 'danger', message: prefix('contains a backslash — browsers may read it differently') });
  if (u.hostname) {
    out.push(...domainWarnings(u.hostname, `${label} domain`));
    const host = u.hostname.replace(/^www\./, '');
    if (SHORTENERS.has(host)) out.push({ level: 'caution', message: prefix(`shortened link (${host}) — the real destination is unknown until opened`) });
  }
  if (u.port) out.push({ level: 'caution', message: prefix(`non-standard port ${u.port}`) });
  return out;
}

// ---------------------------------------------------------------------------
// Analysis builder
// ---------------------------------------------------------------------------

const noSafety = (s) => ({ escaped: String(s), hasInvisible: false, warnings: [] });

/**
 * Collects fields, warnings and actions for one analysis.
 *
 * - `field(label, value, opts)` skips empty values and runs `ctx.textSafety` on the
 *   value (warnings prefixed with the label; generic wording for sensitive values).
 *   opts: `{ sensitive, mono, copy, singleLine, check: false }`.
 * - `warn(level, message)` de-duplicates by message.
 * - `copy` / `open` / `save` add actions; `open` silently refuses non-allowlisted schemes.
 */
export function createReport(ctx = {}) {
  const fields = [];
  const warnings = [];
  const actions = [];
  const warnSeen = new Set();
  const safety = typeof ctx.textSafety === 'function' ? ctx.textSafety : noSafety;

  const report = {
    fields,
    warnings,
    actions,

    warn(level, message) {
      if (!warnSeen.has(message)) {
        warnSeen.add(message);
        warnings.push({ level, message });
      }
      return report;
    },

    warnAll(list) {
      for (const w of list || []) report.warn(w.level, w.message);
      return report;
    },

    /** Runs text safety on a value; returns true if it had invisible characters. */
    check(label, value, { singleLine = false, sensitive = false, name = false } = {}) {
      const str = String(value ?? '');
      if (!str) return false;
      let res;
      try {
        res = safety(str, { context: singleLine ? 'single-line' : 'text', label }) || {};
      } catch {
        res = {};
      }
      const list = Array.isArray(res.warnings) ? res.warnings : [];
      if (sensitive) {
        if (list.length || res.hasInvisible) {
          const level = list.some((w) => w.level === 'danger') ? 'danger' : 'caution';
          report.warn(level, `${label}: contains invisible or unusual characters`);
        }
      } else {
        for (const w of list) {
          const level = typeof w === 'string' ? 'caution' : w.level || 'caution';
          const msg = typeof w === 'string' ? w : String(w.message ?? '');
          report.warn(level, msg.startsWith(`${label}:`) ? msg : `${label}: ${msg}`);
        }
      }
      if (singleLine && /[\r\n\t]/.test(str) && !list.length) {
        report.warn('caution', `${label}: contains a line break or tab`);
      }
      let mixed = false;
      if (name && /[^\x00-\x7f]/.test(str)) {
        const m = safeCall(() => mixedScriptWarnings(str, { label }), []);
        mixed = m.length > 0;
        report.warnAll(m);
      }
      return !!res.hasInvisible || mixed;
    },

    field(label, value, opts = {}) {
      if (value === undefined || value === null || value === '') return report;
      const f = { label, value: String(value) };
      if (opts.sensitive) f.sensitive = true;
      if (opts.mono) f.mono = true;
      if (opts.copy) f.copy = true;
      fields.push(f);
      if (opts.check !== false) report.check(label, f.value, opts);
      return report;
    },

    copy(label, value, { sensitive = false } = {}) {
      if (value === undefined || value === null || value === '') return report;
      const a = { kind: 'copy', label, value: String(value) };
      if (sensitive) a.sensitive = true;
      actions.push(a);
      return report;
    },

    open(label, url) {
      const m = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(String(url ?? ''));
      if (!m || !OPENABLE_SCHEMES.has(m[1].toLowerCase())) return report;
      if (/[\u0000-\u0020\u007f]/.test(url)) return report;
      actions.push({ kind: 'open', label, value: String(url) });
      return report;
    },

    save(label, value, suggestedName, kind) {
      actions.push({ kind: 'save', label, value: String(value), saveAs: { suggestedName, kind } });
      return report;
    },

    hasLevel(level) {
      return warnings.some((w) => w.level === level);
    },

    /** Final Analysis-without-raw. Warnings are sorted danger → caution → info. */
    result({ type, title, summary, data }) {
      const rank = { danger: 0, caution: 1, info: 2 };
      const sorted = warnings.map((w, i) => [w, i]).sort((a, b) => rank[a[0].level] - rank[b[0].level] || a[1] - b[1]).map((x) => x[0]);
      return { type, title, summary: oneLine(summary ?? title), fields, warnings: sorted, actions, data };
    },
  };
  return report;
}

/**
 * Wraps a parser so that `detect` never throws (→ false) and `parse` never throws
 * (→ best-effort text analysis with a caution).
 */
export function guarded(parser) {
  return {
    id: parser.id,
    ...(parser.phase ? { phase: parser.phase } : {}),
    detect(text, ctx) {
      try {
        return !!parser.detect(text, ctx);
      } catch {
        return false;
      }
    },
    parse(text, ctx) {
      try {
        return parser.parse(text, ctx);
      } catch (err) {
        return {
          type: 'text',
          title: 'Unreadable data',
          summary: `Looks like ${parser.label || parser.id} data, but it could not be read`,
          fields: [],
          warnings: [{ level: 'caution', message: `Could not parse this ${parser.label || parser.id} payload (${String(err?.message || err)})` }],
          actions: [{ kind: 'copy', label: 'Copy text', value: String(text ?? '') }],
          data: { format: parser.id, error: String(err?.message || err) },
        };
      }
    },
  };
}

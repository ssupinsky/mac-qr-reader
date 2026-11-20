// Text safety analysis (PAYLOADS.md §1): invisible / bidi / control characters,
// escaped display form, script detection, mixed-script and confusable checks.
// Pure functions, no DOM, no dependencies.

// ---------------------------------------------------------------------------
// Code point classification (§1.1)
// ---------------------------------------------------------------------------

/** Short names for the inline chips (§1.2). */
const NAMES = new Map([
  [0x00, 'NUL'], [0x07, 'BEL'], [0x08, 'BS'], [0x09, 'TAB'], [0x0a, 'LF'], [0x0b, 'VT'],
  [0x0c, 'FF'], [0x0d, 'CR'], [0x1b, 'ESC'], [0x7f, 'DEL'], [0x85, 'NEL'], [0xa0, 'NBSP'],
  [0xad, 'SHY'], [0x34f, 'CGJ'], [0x61c, 'ALM'], [0x115f, 'HCF'], [0x1160, 'HJF'],
  [0x1680, 'OGHAM SPACE'], [0x17b4, 'KIV AQ'], [0x17b5, 'KIV AA'], [0x180e, 'MVS'],
  [0x200b, 'ZWSP'], [0x200c, 'ZWNJ'], [0x200d, 'ZWJ'], [0x200e, 'LRM'], [0x200f, 'RLM'],
  [0x2028, 'LSEP'], [0x2029, 'PSEP'], [0x202a, 'LRE'], [0x202b, 'RLE'], [0x202c, 'PDF'],
  [0x202d, 'LRO'], [0x202e, 'RLO'], [0x202f, 'NNBSP'], [0x205f, 'MMSP'], [0x2060, 'WJ'],
  [0x2061, 'FUNCTION APPLICATION'], [0x2062, 'INVISIBLE TIMES'], [0x2063, 'INVISIBLE SEPARATOR'],
  [0x2064, 'INVISIBLE PLUS'], [0x2066, 'LRI'], [0x2067, 'RLI'], [0x2068, 'FSI'], [0x2069, 'PDI'],
  [0x3000, 'IDEOGRAPHIC SPACE'], [0x3164, 'HANGUL FILLER'], [0xfeff, 'BOM'],
  [0xffa0, 'HALFWIDTH HANGUL FILLER'], [0xfffd, 'REPLACEMENT'],
]);

const hex = (cp) => cp.toString(16).toUpperCase().padStart(4, '0');

/** Human-readable chip name for a code point, e.g. "RLO", "TAG 'a'", "U+E000". */
export function codePointName(cp) {
  if (NAMES.has(cp)) return NAMES.get(cp);
  if (cp >= 0xe0020 && cp <= 0xe007e) return `TAG '${String.fromCharCode(cp - 0xe0000)}'`;
  if (cp >= 0xe0000 && cp <= 0xe007f) return `TAG U+${hex(cp)}`;
  if (cp >= 0x2000 && cp <= 0x200a) return 'SPACE';
  if (cp >= 0xfe00 && cp <= 0xfe0f) return `VS${cp - 0xfe00 + 1}`;
  if (cp >= 0xe0100 && cp <= 0xe01ef) return `VS${cp - 0xe0100 + 17}`;
  if (cp < 0x20) return `C0 U+${hex(cp)}`;
  if (cp >= 0x80 && cp <= 0x9f) return `C1 U+${hex(cp)}`;
  return `U+${hex(cp)}`;
}

/**
 * Classes, in the order they are reported. `level` is the default level; some are
 * adjusted by context in `classify`.
 */
const CLASSES = {
  bidiControl: { level: 'danger', message: 'Contains bidirectional control characters — text may display in a misleading order' },
  tag: { level: 'danger', message: 'Contains invisible tag characters (hidden text)' },
  c0: { level: 'danger', message: 'Contains control characters' },
  loneSurrogate: { level: 'danger', message: 'Contains broken (lone surrogate) characters' },
  bidiMark: { level: 'caution', message: 'Contains invisible direction marks' },
  zeroWidth: { level: 'caution', message: 'Contains zero-width characters' },
  invisible: { level: 'caution', message: 'Contains invisible characters' },
  deprecatedFormat: { level: 'caution', message: 'Contains deprecated formatting characters' },
  format: { level: 'caution', message: 'Contains invisible formatting characters' },
  variationSupplement: { level: 'caution', message: 'Contains unusual variation selectors (can hide data)' },
  c1: { level: 'caution', message: 'Contains DEL/C1 control characters (often mis-decoded Windows-1252 text)' },
  lineSeparator: { level: 'caution', message: 'Contains Unicode line/paragraph separators' },
  privateUse: { level: 'caution', message: 'Contains private-use characters' },
  nonCharacter: { level: 'caution', message: 'Contains Unicode noncharacters' },
  unassigned: { level: 'caution', message: 'Contains unassigned code points' },
  lineBreak: { level: 'caution', message: 'Contains line breaks or tabs in a single-line value' },
  leadingBom: { level: 'info', message: 'Starts with a byte order mark (U+FEFF)' },
  variation: { level: 'info', message: 'Contains variation selectors' },
  space: { level: 'info', message: 'Contains unusual space characters' },
  replacement: { level: 'info', message: 'Contains U+FFFD — text was not valid in its encoding' },
};

const RE_CATCH_ALL = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u;
const RE_EMOJI = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\p{Regional_Indicator}\u{1F3FB}-\u{1F3FF}]/u;
const RE_VS_BASE = /[\p{Extended_Pictographic}\p{Emoji}\p{scx=Han}\p{scx=Hiragana}\p{scx=Katakana}]/u;

const isSpace = (cp) =>
  cp === 0xa0 || cp === 0x1680 || (cp >= 0x2000 && cp <= 0x200a) || cp === 0x202f ||
  cp === 0x205f || cp === 0x3000;

/**
 * Classifies one code point. Returns a class key or null for "fine".
 * @param {number} cp
 * @param {{ prev: string|undefined, next: string|undefined, index: number, singleLine: boolean }} c
 */
function classify(cp, c) {
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return c.singleLine ? 'lineBreak' : null;
  if (cp < 0x20) return 'c0';
  if (cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) return cp === 0x85 ? 'lineSeparator' : 'c1';
  if (cp < 0xa0) return null;
  if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) return 'bidiControl';
  if (cp === 0x200e || cp === 0x200f || cp === 0x61c) return 'bidiMark';
  if (cp === 0x200d) {
    // ZWJ inside an emoji sequence (👩\u200D💻) is normal.
    const prevOk = c.prev !== undefined && (RE_EMOJI.test(c.prev) || c.prev === '\uFE0F');
    const nextOk = c.next !== undefined && RE_EMOJI.test(c.next);
    return prevOk && nextOk ? null : 'zeroWidth';
  }
  if (cp === 0xfeff) return c.index === 0 ? 'leadingBom' : 'zeroWidth';
  if (cp === 0x200b || cp === 0x200c || cp === 0x2060) return 'zeroWidth';
  if ((cp >= 0x2061 && cp <= 0x2064) || cp === 0xad || cp === 0x34f || cp === 0x180e ||
      cp === 0x115f || cp === 0x1160 || cp === 0x3164 || cp === 0xffa0 || cp === 0x17b4 ||
      cp === 0x17b5) return 'invisible';
  if ((cp >= 0x206a && cp <= 0x206f) || (cp >= 0xfff9 && cp <= 0xfffb)) return 'deprecatedFormat';
  if (cp >= 0xe0000 && cp <= 0xe007f) return 'tag';
  if (cp >= 0xfe00 && cp <= 0xfe0f) {
    // Normal after emoji / CJK; otherwise worth an info note.
    return c.prev !== undefined && RE_VS_BASE.test(c.prev) ? null : 'variation';
  }
  if (cp >= 0xe0100 && cp <= 0xe01ef) return 'variationSupplement';
  if (cp === 0x2028 || cp === 0x2029) return 'lineSeparator';
  if (isSpace(cp)) return 'space';
  if ((cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xf0000 && cp <= 0xffffd) ||
      (cp >= 0x100000 && cp <= 0x10fffd)) return 'privateUse';
  if ((cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe) return 'nonCharacter';
  if (cp >= 0xd800 && cp <= 0xdfff) return 'loneSurrogate';
  if (cp === 0xfffd) return 'replacement';
  const ch = String.fromCodePoint(cp);
  if (RE_CATCH_ALL.test(ch)) return /\p{Cn}/u.test(ch) ? 'unassigned' : 'format';
  return null;
}

/** Classes that do not count towards `hasInvisible`. */
const VISIBLE_CLASSES = new Set(['lineBreak', 'replacement']);

/**
 * Escapes a string for display (§1.2): `\` → `\\`, LF/CR/TAB → `\n`/`\r`/`\t`, every
 * flagged code point → `\u{XXXX}`. With `{ multiline: true }` a real line break is kept
 * after each `\n`.
 * @param {string} text
 * @param {{ multiline?: boolean }} [opts]
 */
export function escapeForDisplay(text, opts = {}) {
  return scan(String(text ?? ''), { multiline: !!opts.multiline }).escaped;
}

/** Single pass over the string: findings + escaped form. */
function scan(text, { singleLine = false, multiline = false } = {}) {
  const chars = Array.from(text);
  const findings = [];
  let escaped = '';
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    const cp = ch.codePointAt(0);
    if (ch === '\\') { escaped += '\\\\'; continue; }
    const cls = classify(cp, { prev: chars[i - 1], next: chars[i + 1], index: i, singleLine });
    if (cp === 0x0a) escaped += multiline ? '\\n\n' : '\\n';
    else if (cp === 0x0d) escaped += '\\r';
    else if (cp === 0x09) escaped += '\\t';
    else if (cls) escaped += `\\u{${hex(cp)}}`;
    else escaped += ch;
    if (cls) findings.push({ index: i, codePoint: cp, name: codePointName(cp), cls });
  }
  return { chars, findings, escaped };
}

const LEVEL_RANK = { info: 0, caution: 1, danger: 2 };
const maxLevel = (a, b) => (LEVEL_RANK[a] >= LEVEL_RANK[b] ? a : b);

/**
 * Full text-safety analysis.
 *
 * @param {string} text
 * @param {{ context?: 'text'|'single-line'|'url', label?: string }} [opts]
 *   `single-line`: CR/LF/TAB flagged (caution) and unusual spaces raised to caution;
 *   `url`: as single-line, plus CR/LF/TAB, bidi marks and all controls are danger.
 *   `label` prefixes warning messages (e.g. "Network name").
 * @returns {{ escaped: string, hasInvisible: boolean, length: number,
 *   warnings: Array<{level, message}>, scripts: string[], hiddenText: string|null,
 *   findings: Array<{index, codePoint, name, cls, level}> }}
 */
export function textSafety(text, opts = {}) {
  const str = String(text ?? '');
  const context = opts.context || 'text';
  const singleLine = context !== 'text';
  const { chars, findings, escaped } = scan(str, { singleLine, multiline: false });

  // Per-class grouping with context-dependent levels.
  const groups = new Map();
  for (const f of findings) {
    let level = CLASSES[f.cls].level;
    if (singleLine && f.cls === 'space') level = 'caution';
    if (context === 'url' && (f.cls === 'lineBreak' || f.cls === 'bidiMark' || f.cls === 'c1')) level = 'danger';
    f.level = level;
    if (!groups.has(f.cls)) groups.set(f.cls, { level, items: [] });
    const g = groups.get(f.cls);
    g.level = maxLevel(g.level, level);
    g.items.push(f);
  }

  // Hidden ASCII carried by tag characters ("ASCII smuggling").
  let hiddenText = null;
  const tags = findings.filter((f) => f.cls === 'tag' && f.codePoint >= 0xe0020 && f.codePoint <= 0xe007e);
  if (tags.length) hiddenText = tags.map((f) => String.fromCharCode(f.codePoint - 0xe0000)).join('');

  const prefix = opts.label ? `${opts.label}: ` : '';
  const warnings = [];
  for (const [cls, g] of groups) {
    const names = [...new Set(g.items.map((f) => (cls === 'tag' ? 'TAG' : f.name)))];
    const where = g.items.slice(0, 5).map((f) => f.index).join(', ') + (g.items.length > 5 ? ', …' : '');
    let message = `${prefix}${CLASSES[cls].message} (${names.slice(0, 6).join(', ')}${names.length > 6 ? ', …' : ''}`;
    message += g.items.length === 1 ? ` at position ${where})` : ` at positions ${where})`;
    if (cls === 'tag' && hiddenText) message += `; hidden text: "${hiddenText}"`;
    warnings.push({ level: g.level, message });
  }
  warnings.sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);

  const hasInvisible = findings.some((f) => !VISIBLE_CLASSES.has(f.cls));
  return {
    escaped, hasInvisible, length: chars.length, warnings, scripts: detectScripts(str),
    hiddenText, findings,
  };
}

// ---------------------------------------------------------------------------
// Scripts, mixed-script detection (§1.3)
// ---------------------------------------------------------------------------

export const CANDIDATE_SCRIPTS = [
  'Latin', 'Cyrillic', 'Greek', 'Armenian', 'Georgian', 'Hebrew', 'Arabic', 'Syriac', 'Thaana',
  'Devanagari', 'Bengali', 'Gurmukhi', 'Gujarati', 'Oriya', 'Tamil', 'Telugu', 'Kannada',
  'Malayalam', 'Sinhala', 'Thai', 'Lao', 'Tibetan', 'Myanmar', 'Khmer', 'Hangul', 'Hiragana',
  'Katakana', 'Han', 'Bopomofo', 'Ethiopic', 'Cherokee', 'Canadian_Aboriginal', 'Mongolian',
  'Tifinagh', 'Vai', 'Coptic', 'Glagolitic', 'Runic', 'Ogham', 'Gothic',
];

// RegExp construction is not eval and is allowed under the app's CSP.
const SCRIPT_RES = CANDIDATE_SCRIPTS.map((s) => [s, new RegExp(`\\p{scx=${s}}`, 'u')]);
const RE_LETTER = /\p{L}/u;
const RE_COMMON_OR_INHERITED = /^[\p{scx=Common}\p{scx=Inherited}]$/u;

/**
 * Script_Extensions of one character restricted to the candidate list.
 * Common/Inherited-only characters → empty set; letters in other scripts → {'Other'}.
 * @param {string} ch one code point
 * @returns {Set<string>}
 */
export function scriptsOf(ch) {
  return new Set(scriptList(ch));
}

// Per-code-point cache: 40 regex tests per character are slow on long payloads.
const SCRIPT_CACHE = new Map();
function scriptList(ch) {
  let list = SCRIPT_CACHE.get(ch);
  if (list) return list;
  list = [];
  for (const [name, re] of SCRIPT_RES) if (re.test(ch)) list.push(name);
  if (list.length === 0 && RE_LETTER.test(ch) && !RE_COMMON_OR_INHERITED.test(ch)) list.push('Other');
  if (SCRIPT_CACHE.size >= 4096) SCRIPT_CACHE.clear();
  SCRIPT_CACHE.set(ch, list);
  return list;
}

/** Distinct scripts used in a string (union, Common/Inherited ignored), in first-seen order. */
export function detectScripts(str) {
  const seen = new Set();
  for (const ch of String(str)) {
    if (ch.charCodeAt(0) < 0x80) {
      if (/[A-Za-z]/.test(ch)) seen.add('Latin');
      continue;
    }
    for (const s of scriptList(ch)) seen.add(s);
  }
  return [...seen];
}

const ALLOWED_COMBOS = [
  new Set(['Latin', 'Han', 'Hiragana', 'Katakana']),
  new Set(['Latin', 'Han', 'Bopomofo']),
  new Set(['Latin', 'Han', 'Hangul']),
];

/**
 * UTS #39 "Highly Restrictive" check for one label/word.
 * @param {string} label
 * @returns {{ mixed: boolean, scripts: string[], resolved: string[] }}
 *   `scripts` = union of character scripts; `resolved` = intersection.
 */
export function scriptProfile(label) {
  let resolved = null;
  const union = new Set();
  for (const ch of String(label)) {
    const set = ch.charCodeAt(0) < 0x80 ? (/[A-Za-z]/.test(ch) ? new Set(['Latin']) : new Set()) : scriptsOf(ch);
    if (set.size === 0) continue;
    for (const s of set) union.add(s);
    resolved = resolved ? new Set([...resolved].filter((s) => set.has(s))) : new Set(set);
  }
  const scripts = [...union];
  const res = resolved ? [...resolved] : [];
  let mixed = false;
  if (scripts.length > 1 && res.length === 0) {
    mixed = !ALLOWED_COMBOS.some((combo) => scripts.every((s) => combo.has(s)));
  }
  return { mixed, scripts, resolved: res };
}

/**
 * Mixed-script warnings for a value, checked per word (split on whitespace and
 * punctuation) — or per label when `{ labels: true }` (split on dots).
 * @param {string} value
 * @param {{ level?: 'caution'|'danger', label?: string, labels?: boolean }} [opts]
 * @returns {Array<{level, message}>}
 */
export function mixedScriptWarnings(value, opts = {}) {
  const parts = opts.labels ? String(value).split('.') : String(value).split(/[\s\p{P}\p{S}]+/u);
  const warnings = [];
  const seen = new Set();
  for (const part of parts) {
    if (!part || seen.has(part)) continue;
    seen.add(part);
    const p = scriptProfile(part);
    if (p.mixed) {
      const what = opts.label ? `${opts.label} ` : '';
      warnings.push({
        level: opts.level || 'caution',
        message: `${what}"${part}" mixes ${humanList(p.scripts)} letters — it may imitate another name`,
      });
    }
  }
  return warnings;
}

function humanList(items) {
  const names = items.map((s) => s.replace(/_/g, ' '));
  return names.length <= 2 ? names.join(' and ') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
}

// ---------------------------------------------------------------------------
// Confusable skeletons (§1.3 step 4–5)
// ---------------------------------------------------------------------------

/** Strong Latin lookalikes (used for the whole-script confusable rule). */
const STRONG_MAP = {
  // Cyrillic
  'а': 'a', 'е': 'e', 'ё': 'e', 'һ': 'h', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k', 'ӏ': 'l',
  'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'ү': 'y', 'х': 'x', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q',
  'ԝ': 'w', 'ɡ': 'g',
  // Greek
  'α': 'a', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'υ': 'u', 'χ': 'x',
  // Latin extensions
  'ı': 'i', 'ɩ': 'i', 'ɑ': 'a', 'ʟ': 'l', 'ɴ': 'n', 'ᴏ': 'o', 'ꞵ': 'b', 'ſ': 's', 'ƚ': 'l', 'ꜱ': 's',
};

/** Weaker resemblances — only for brand checks. */
const WEAK_MAP = {
  'в': 'b', 'г': 'r', 'м': 'm', 'н': 'h', 'п': 'n', 'т': 't', 'ь': 'b',
  'β': 'b', 'ε': 'e', 'η': 'n', 'τ': 't', 'ω': 'w',
  '0': 'o', '1': 'l', '|': 'l',
};

function baseSkeleton(str, map) {
  const out = [];
  // NFD, drop combining marks, lowercase (per code point: never changes ASCII lengths
  // in a way that matters here), then map.
  for (const ch of String(str).normalize('NFD').replace(/\p{M}/gu, '').toLowerCase()) {
    out.push(map[ch] ?? STRONG_MAP[ch] ?? ch);
  }
  return out.join('');
}

/**
 * Latin skeleton of a string. `{ brand: true }` also applies the weak and the
 * digit/ASCII maps (0→o, 1→l, |→l, rn→m, vv→w, cl→d) — for brand lookalike checks only.
 */
export function skeleton(str, opts = {}) {
  if (!opts.brand) return baseSkeleton(str, {});
  return baseSkeleton(str, WEAK_MAP).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd');
}

/**
 * Whole-script confusable test (the `аррӏе.com` case): every letter is Cyrillic
 * (or every letter Greek) and every character has a strong Latin lookalike.
 * @param {string} label
 * @returns {string|null} the Latin lookalike word, or null.
 */
export function wholeScriptConfusable(label) {
  const chars = Array.from(String(label).normalize('NFC'));
  if (!chars.length) return null;
  let script = null;
  for (const ch of chars) {
    if (/[\d-]/.test(ch)) continue;
    const s = /\p{Script=Cyrillic}/u.test(ch) ? 'Cyrillic' : /\p{Script=Greek}/u.test(ch) ? 'Greek' : null;
    if (!s || (script && s !== script)) return null;
    script = s;
    if (!(ch.toLowerCase() in STRONG_MAP)) return null;
  }
  if (!script) return null;
  return skeleton(label);
}

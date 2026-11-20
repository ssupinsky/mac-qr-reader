// Plain-text fallback (PAYLOADS.md §11.11): nothing is linkified, but links,
// e-mail addresses and phone numbers found inside the text are listed (each link
// analysed offline) so the UI can show them as secondary chips.

import { analyzeUrl } from './url.js';
import { escapeForDisplay } from './text-safety.js';
import { trimEndChars, truncateDisplay } from './strings.js';

const RANK = { info: 0, caution: 1, danger: 2 };
const MAX_ITEMS = 20;

const isDigit = (c) => c >= '0' && c <= '9';
const isAlpha = (c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
const isWordOrDot = (c) => isDigit(c) || isAlpha(c) || c === '_' || c === '.';
const isLocalChar = (c) => isDigit(c) || isAlpha(c) || '._%+-'.includes(c);
const isDomainChar = (c) => isDigit(c) || isAlpha(c) || c === '.' || c === '-';
const isPhoneChar = (c) => isDigit(c) || ' ().-'.includes(c);

/**
 * Same matches as /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g in linear time
 * (the regex rescans the whole run from every start position when there is no "@").
 */
export function* scanEmails(text) {
  let lastEnd = 0;
  for (let at = text.indexOf('@'); at !== -1; at = text.indexOf('@', Math.max(at + 1, lastEnd))) {
    let s = at;
    while (s > lastEnd && isLocalChar(text[s - 1])) s--;
    if (s === at) continue;
    let j = at + 1;
    while (j < text.length && isDomainChar(text[j])) j++;
    // Rightmost "." (with at least one domain char before it) followed by 2+ letters.
    let k = j - 3;
    while (k >= at + 2 && !(text[k] === '.' && isAlpha(text[k + 1]) && isAlpha(text[k + 2]))) k--;
    if (k < at + 2) continue;
    let e = k + 3;
    while (e < text.length && isAlpha(text[e])) e++;
    yield text.slice(s, e);
    lastEnd = e;
  }
}

/**
 * Same matches as /(?<![\w.])\+?\d[\d ().-]{5,}\d(?![\w.])/g in linear time: the
 * greedy run's end only depends on the run of phone characters, so the last
 * acceptable end of each run is computed once.
 */
export function* scanPhones(text) {
  const n = text.length;
  let runEnd = -1; // end of the phone-char run containing the current digit
  let runBest = -1; // largest e ≤ runEnd with text[e-1] digit and text[e] not [\w.]
  const behindOk = (i) => i === 0 || !isWordOrDot(text[i - 1]);
  for (let i = 0; i < n;) {
    let d = -1;
    if (text[i] === '+' && i + 1 < n && isDigit(text[i + 1]) && behindOk(i)) d = i + 1;
    else if (isDigit(text[i]) && behindOk(i)) d = i;
    if (d === -1) { i++; continue; }
    if (d >= runEnd) {
      runEnd = d;
      while (runEnd < n && isPhoneChar(text[runEnd])) runEnd++;
      runBest = -1;
      for (let e = runEnd; e > d; e--) {
        if (isDigit(text[e - 1]) && (e === n || !isWordOrDot(text[e]))) { runBest = e; break; }
      }
    }
    if (runBest >= d + 7) {
      yield text.slice(i, runBest);
      i = runBest;
    } else {
      i++;
    }
  }
}

/** Finds links / e-mails / phone numbers inside free text (at most MAX_ITEMS). */
export function findEmbedded(text) {
  const found = [];
  const seen = new Set();
  const full = () => found.length >= MAX_ITEMS;
  const add = (kind, value, extra = {}) => {
    if (full() || seen.has(`${kind}|${value}`)) return;
    seen.add(`${kind}|${value}`);
    found.push({ kind, value, ...extra });
  };
  for (const m of text.matchAll(/\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi)) {
    if (full()) return found;
    const url = trimEndChars(m[0], '.,;:!?)]}');
    if (seen.has(`url|${url}`)) continue;
    const a = analyzeUrl(url, { depth: 1 });
    const level = a.warnings.reduce((acc, w) => (RANK[w.level] > RANK[acc] ? w.level : acc), 'info');
    add('url', url, {
      host: a.data.hostUnicode || a.data.host, summary: a.summary,
      level: a.warnings.length ? level : null, warnings: a.warnings,
    });
  }
  for (const email of scanEmails(text)) {
    if (full()) return found;
    // Skip the user@host part of links already listed.
    if (!found.some((f) => f.kind === 'url' && f.value.includes(email))) add('email', email);
  }
  for (const phone of scanPhones(text)) {
    if (full()) return found;
    let digits = 0;
    for (const c of phone) if (isDigit(c)) digits++;
    if (digits >= 7 && digits <= 15 && !found.some((f) => f.value.includes(phone))) add('phone', phone);
  }
  return found;
}

export const textParser = {
  id: 'text',
  detect: () => true,
  parse(text) {
    const firstLine = text.split(/\r\n|\r|\n/).find((l) => l.trim()) ?? '';
    const shown = escapeForDisplay(firstLine);
    const summary = text.length === 0 ? 'Empty' : truncateDisplay(shown, 80);
    const detected = text.length <= 20000 ? findEmbedded(text) : [];
    const warnings = [];
    for (const d of detected) {
      if (d.kind === 'url' && d.level === 'danger') {
        warnings.push({ level: 'caution', message: `Text contains a suspicious link (${d.host || d.value})` });
      }
    }
    return {
      type: 'text',
      title: 'Text',
      summary,
      fields: [{ label: 'Text', value: text, copy: true }],
      warnings,
      actions: text ? [{ kind: 'copy', label: 'Copy text', value: text }] : [],
      data: { format: 'text', detected, lines: text ? text.split(/\r\n|\r|\n/).length : 0 },
    };
  },
};

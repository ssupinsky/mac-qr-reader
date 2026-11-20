// Linear-time string helpers. Regexes like /[…]+$/ or /^\s+|\s+$/g are O(n²) on
// long runs of the class (the engine retries the run at every start position),
// and a payload is attacker-controlled, so trimming uses index loops instead.

/**
 * Removes characters matching `isTrim(ch)` from both ends (per UTF-16 unit).
 * @param {string} str
 * @param {(ch: string) => boolean} isTrim
 * @param {{ start?: boolean, end?: boolean }} [which]
 */
export function trimWith(str, isTrim, { start = true, end = true } = {}) {
  let i = 0;
  let j = str.length;
  if (start) while (i < j && isTrim(str[i])) i++;
  if (end) while (j > i && isTrim(str[j - 1])) j--;
  return i === 0 && j === str.length ? str : str.slice(i, j);
}

/** Predicate for a set of characters given as a string. */
export const charSet = (chars) => {
  const set = new Set(chars);
  return (ch) => set.has(ch);
};

/** Removes trailing characters contained in `chars`. */
export function trimEndChars(str, chars) {
  return trimWith(str, charSet(chars), { start: false });
}

/** Removes trailing repetitions of `suffix`. */
export function stripTrailing(str, suffix) {
  let j = str.length;
  while (j >= suffix.length && str.startsWith(suffix, j - suffix.length)) j -= suffix.length;
  return str.slice(0, j);
}

/** ASCII whitespace per §0.2 (space, TAB, LF, VT, FF, CR). */
export const isAsciiSpace = charSet(' \t\r\n\f\v');

const isDigit = (c) => c >= '0' && c <= '9';
const isWord = (c) => isDigit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c === '_';

/**
 * Same as `str.replace(/\B(?=(\d{3})+(?!\d))/g, sep)` in linear time (the regex
 * rescans the rest of the digit run at every position).
 */
export function groupThousands(str, sep = ',') {
  let out = '';
  let i = 0;
  while (i < str.length) {
    if (!isDigit(str[i])) { out += str[i++]; continue; }
    let j = i;
    while (j < str.length && isDigit(str[j])) j++;
    for (let k = i; k < j; k++) {
      if ((j - k) % 3 === 0 && (k > i || (k > 0 && isWord(str[k - 1])))) out += sep;
      out += str[k];
    }
    i = j;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Display truncation
// ---------------------------------------------------------------------------

/** One escapeForDisplay token: `\\`, `\n`, `\r`, `\t` or `\u{XXXX}` (sticky). */
const ESCAPE_TOKEN = /\\(?:[\\nrt]|u\{[0-9A-Fa-f]{1,6}\})/y;
/** Grapheme lookaround window (UTF-16 units) around the cut. */
const GRAPHEME_WINDOW = 32;
let graphemes;
function graphemeSegmenter() {
  if (graphemes === undefined) {
    try { graphemes = new Intl.Segmenter(undefined, { granularity: 'grapheme' }); } catch { graphemes = null; }
  }
  return graphemes;
}

/**
 * Shortens a display string to at most `max` units, ellipsis included — the one helper
 * for every truncated string shown to the user (summaries, warning quotes, previews).
 * The cut never splits a surrogate pair or an escapeForDisplay token (`\u{202E}`, `\\`,
 * `\n`…), and backs off to the start of a grapheme cluster (emoji ZWJ sequences, flags,
 * base + combining marks) when that cluster is short enough to see in a small window.
 * Linear in `max`, not in `str.length` (only the head of the string is looked at).
 * @param {string} str
 * @param {number} max
 * @param {{ ellipsis?: string, units?: 'codepoints'|'utf16' }} [opts]
 */
export function truncateDisplay(str, max = 80, { ellipsis = '…', units = 'codepoints' } = {}) {
  const s = String(str ?? '');
  if (s.length <= max) return s; // code points ≤ UTF-16 units
  const utf16 = units === 'utf16';
  const ellLen = utf16 ? ellipsis.length : Array.from(ellipsis).length;
  const budget = Math.max(0, max - ellLen);
  const bounds = [0]; // token boundaries up to the budget
  let i = 0;
  let used = 0;
  let cut = 0;
  while (i < s.length) {
    let len = 1;
    let width = 1;
    const c = s.charCodeAt(i);
    if (c === 0x5c) {
      ESCAPE_TOKEN.lastIndex = i;
      if (ESCAPE_TOKEN.test(s)) width = len = ESCAPE_TOKEN.lastIndex - i;
    } else if (c >= 0xd800 && c <= 0xdbff && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      len = 2;
      width = utf16 ? 2 : 1;
    }
    used += width;
    if (used > max) break;
    i += len;
    if (used <= budget) {
      cut = i;
      bounds.push(i);
    }
  }
  if (i >= s.length) return s; // fits after all

  const seg = graphemeSegmenter();
  if (seg && cut > 0) {
    const lo = Math.max(0, cut - GRAPHEME_WINDOW);
    const windowText = s.slice(lo, Math.min(s.length, cut + GRAPHEME_WINDOW));
    for (const { index, segment } of seg.segment(windowText)) {
      const start = lo + index;
      if (start >= cut) break;
      if (start + segment.length > cut) {
        // The cut is inside this cluster; trust it only if it starts inside the window.
        if (index > 0 || lo === 0) {
          let k = bounds.length - 1;
          while (k > 0 && bounds[k] > start) k--;
          if (bounds[k] > 0) cut = bounds[k];
        }
        break;
      }
    }
  }
  return s.slice(0, cut) + ellipsis;
}

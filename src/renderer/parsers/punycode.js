// RFC 3492 Punycode (Bootstring with the Punycode parameters) — decoder, encoder
// and ACE-domain → Unicode conversion. Browsers have no built-in ACE→Unicode
// conversion, so this small, dependency-free implementation is bundled.

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = '-';
const MAX_CODE_POINT = 0x10ffff;
const MAX_INT = 0x7fffffff;

/** Bias adaptation function (RFC 3492 §6.1). */
function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/** Basic code point (ASCII char code) → digit value 0..35, or -1. */
function digitValue(cp) {
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26; // 0-9 → 26..35
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41; // A-Z → 0..25
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61; // a-z → 0..25
  return -1;
}

/** Digit value 0..35 → lowercase basic code point. */
function digitChar(d) {
  return d < 26 ? 0x61 + d : 0x30 + d - 26;
}

/**
 * Decodes a Punycode string (without the "xn--" prefix) to Unicode.
 * @param {string} input
 * @returns {string}
 * @throws {RangeError} on invalid input or overflow.
 */
export function decode(input) {
  const output = [];
  const b = input.lastIndexOf(DELIMITER);
  const basicEnd = b < 0 ? 0 : b;
  for (let j = 0; j < basicEnd; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) throw new RangeError('Punycode: non-basic code point before delimiter');
    output.push(c);
  }
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  for (let pos = b < 0 ? 0 : b + 1; pos < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) throw new RangeError('Punycode: truncated input');
      const digit = digitValue(input.charCodeAt(pos++));
      if (digit < 0) throw new RangeError('Punycode: invalid digit');
      if (digit > Math.floor((MAX_INT - i) / w)) throw new RangeError('Punycode: overflow');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) throw new RangeError('Punycode: overflow');
      w *= BASE - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    if (Math.floor(i / len) > MAX_INT - n) throw new RangeError('Punycode: overflow');
    n += Math.floor(i / len);
    i %= len;
    if (n > MAX_CODE_POINT || (n >= 0xd800 && n <= 0xdfff)) {
      throw new RangeError('Punycode: invalid code point');
    }
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

/**
 * Encodes a Unicode string to Punycode (without the "xn--" prefix).
 * Uppercase basic code points are kept as is (case annotations unsupported).
 * @param {string} input
 * @returns {string}
 */
export function encode(input) {
  const cps = Array.from(input, (ch) => ch.codePointAt(0));
  const output = [];
  for (const cp of cps) if (cp < 0x80) output.push(String.fromCharCode(cp));
  const basicLength = output.length;
  let h = basicLength;
  if (basicLength > 0) output.push(DELIMITER);
  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  while (h < cps.length) {
    let m = MAX_CODE_POINT + 1;
    for (const cp of cps) if (cp >= n && cp < m) m = cp;
    if (m - n > Math.floor((MAX_INT - delta) / (h + 1))) throw new RangeError('Punycode: overflow');
    delta += (m - n) * (h + 1);
    n = m;
    for (const cp of cps) {
      if (cp < n && ++delta > MAX_INT) throw new RangeError('Punycode: overflow');
      if (cp === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
          if (q < t) break;
          output.push(String.fromCharCode(digitChar(t + ((q - t) % (BASE - t)))));
          q = Math.floor((q - t) / (BASE - t));
        }
        output.push(String.fromCharCode(digitChar(q)));
        bias = adapt(delta, h + 1, h === basicLength);
        delta = 0;
        h++;
      }
    }
    delta++;
    n++;
  }
  return output.join('');
}

/**
 * Converts an ACE domain ("xn--80ak6aa92e.com") to Unicode label by label.
 * @param {string} domain
 * @returns {{ unicode: string, errors: string[] }} errors lists labels that failed to decode
 *   (those are kept in ACE form).
 */
export function domainToUnicode(domain) {
  const errors = [];
  const labels = domain.split('.').map((label) => {
    if (!/^xn--/i.test(label)) return label;
    try {
      const decoded = decode(label.slice(4).toLowerCase());
      // A label that decodes to pure ASCII (or nothing) is not a valid IDNA A-label.
      if (!decoded || /^[\x00-\x7f]*$/.test(decoded)) throw new RangeError('not an IDN label');
      return decoded;
    } catch {
      errors.push(label);
      return label;
    }
  });
  return { unicode: labels.join('.'), errors };
}

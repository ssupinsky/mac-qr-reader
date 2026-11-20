// Banking validators shared by the payment parsers (PAYLOADS.md §10 "Common validators").

import { group } from './util.js';
import { groupThousands, stripTrailing } from '../strings.js';
import { getOwn } from '../dict.js';

/** IBAN lengths per country (ISO 13616 registry subset; unknown countries skip the length check). */
const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21,
  CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27,
  GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26,
  IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21, MC: 27, MD: 24,
  ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29,
  RO: 24, RS: 22, SA: 24, SC: 31, SE: 24, SI: 19, SK: 24, SM: 27, ST: 25, SV: 28, TL: 23, TN: 24,
  TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
};

/** Incremental mod-97 over an alphanumeric string (letters A=10 … Z=35). */
export function mod97(str) {
  let rem = 0;
  for (const ch of str) {
    const v = /[0-9]/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem;
}

/**
 * Validates an IBAN (ISO 13616 mod-97).
 * @returns {{ iban: string, valid: boolean, formatOk: boolean, lengthOk: boolean|null, country: string, display: string }}
 *   `iban` is normalised (spaces removed, uppercase).
 */
export function checkIban(input) {
  const iban = String(input ?? '').replace(/[  ]/g, '').toUpperCase();
  const formatOk = /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban);
  const country = iban.slice(0, 2);
  const expected = getOwn(IBAN_LENGTHS, country);
  const lengthOk = expected ? iban.length === expected : null;
  const valid = formatOk && lengthOk !== false && mod97(iban.slice(4) + iban.slice(0, 4)) === 1;
  return { iban, valid, formatOk, lengthOk, country, display: group(iban, 4) };
}

/** ISO 11649 creditor reference (`RF` + 2 check digits + 1–21 alphanumerics). */
export function checkRfReference(input) {
  const ref = String(input ?? '').replace(/ /g, '').toUpperCase();
  if (!/^RF\d{2}[A-Z0-9]{1,21}$/.test(ref)) return false;
  return mod97(ref.slice(4) + ref.slice(0, 4)) === 1;
}

/** Swiss QR reference / ESR: 27 digits, mod-10 recursive check digit. */
export function checkQrReference(input) {
  const ref = String(input ?? '').replace(/ /g, '');
  if (!/^\d{27}$/.test(ref)) return false;
  return mod10Recursive(ref.slice(0, 26)) === Number(ref[26]);
}

/** Mod-10 recursive check digit of a digit string. */
export function mod10Recursive(digits) {
  const table = [0, 9, 4, 6, 8, 2, 7, 1, 3, 5];
  let c = 0;
  for (const d of digits) c = table[(c + Number(d)) % 10];
  return (10 - c) % 10;
}

/** BIC / SWIFT code syntax. */
export function isBic(input) {
  return /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(String(input ?? ''));
}

/**
 * Normalises a decimal amount to two fraction digits ("12.3" → "12.30").
 * @param {string} str
 * @param {{ decimal?: '.'|',', maxFraction?: number }} [opts]
 * @returns {string|null} null when malformed
 */
export function normalizeAmount(str, { decimal = '.', maxFraction = 2 } = {}) {
  const s = String(str ?? '').trim();
  const re = decimal === ',' ? /^(\d+)(?:,(\d+))?$/ : /^(\d+)(?:\.(\d+))?$/;
  const m = re.exec(s);
  if (!m) return null;
  const frac = stripTrailing(m[2] || '', '0');
  if (frac.length > maxFraction) return null;
  const int = m[1].replace(/^0+(?=\d)/, '');
  return `${int}.${frac.padEnd(Math.max(2, frac.length), '0')}`;
}

const CURRENCY_SYMBOLS = { EUR: '€', USD: '$', GBP: '£', CHF: 'CHF ', CZK: 'CZK ', INR: '₹', BRL: 'R$ ', JPY: '¥' };

/** "€12.30", "CHF 1,949.75", "450.00 PLN". */
export function formatMoney(amount, currency) {
  if (!amount) return '';
  const [int, frac] = String(amount).split('.');
  const pretty = groupThousands(int) + (frac !== undefined ? `.${frac}` : '');
  const sym = getOwn(CURRENCY_SYMBOLS, currency);
  if (sym) return `${sym}${pretty}`;
  return currency ? `${pretty} ${currency}` : pretty;
}

/** Standard reminder shown on every payment analysis (§10). */
export const PAYMENT_INFO = 'Paying happens in your banking app; compare these details with the invoice.';

// Bank / instant-payment formats with `type: 'payment'` (PAYLOADS.md §10.3–10.6):
// Czech SPD ("QR Platba"), EMVCo merchant-presented QR (Pix, PromptPay, PayNow, …),
// UPI (`upi://`), Bezahlcode (`bank://`).

import { createReport, hasPrefix, prep, pctDecode, parseQuery, qget, embeddedUrlWarnings, truncate } from './util.js';
import { checkIban, isBic, normalizeAmount, formatMoney, PAYMENT_INFO } from './banking.js';
import { crc16ccitt, crc32 } from './codecs.js';
import { getOwn } from '../dict.js';

/** Copy actions + reminder shared by all payment formats. */
function paymentActions(r, { iban, amount, reference, name, all }) {
  r.warn('info', PAYMENT_INFO);
  if (iban) r.copy('Copy account', iban);
  if (amount) r.copy('Copy amount', amount);
  if (reference) r.copy('Copy reference', reference);
  if (name) r.copy('Copy beneficiary', name);
  if (all) r.copy('Copy all as text', all);
}

const ibanCheckField = (res) => (res.iban ? (res.valid ? '✓ Checksum valid' : '✗ Checksum invalid') : '');

// ---------------------------------------------------------------------------
// Czech SPD (§10.3)
// ---------------------------------------------------------------------------

export const spd = {
  id: 'spd',
  label: 'Czech QR payment',
  detect(text) {
    return hasPrefix(prep(text), 'SPD*');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const payload = prep(text);
    const parts = payload.split('*');
    const version = parts[1] ?? '';
    const entries = {};
    const order = [];
    for (const part of parts.slice(2)) {
      if (!part) continue;
      const colon = part.indexOf(':');
      if (colon <= 0) {
        r.warn('info', `Ignored malformed element "${truncate(part, 20)}"`);
        continue;
      }
      const key = part.slice(0, colon).toUpperCase();
      if (key in entries) {
        r.warn('caution', `Duplicate field ${key} (the first one is used)`);
        continue;
      }
      entries[key] = pctDecode(part.slice(colon + 1)).value;
      order.push([key, part.slice(colon + 1)]);
    }
    if (version !== '1.0') r.warn('info', `Unusual SPD version "${version}"`);

    const [accIban = '', accBic] = (entries.ACC ?? '').split('+');
    const ibanRes = checkIban(accIban);
    const data = {
      format: 'spd', version, iban: ibanRes.iban, ibanValid: ibanRes.valid, bic: accBic,
      altAccounts: entries['ALT-ACC'] ? entries['ALT-ACC'].split(',').map((a) => { const [iban, bic] = a.split('+'); return { iban, bic }; }) : [],
      amount: undefined, currency: entries.CC || 'CZK', reference: entries.RF, name: entries.RN,
      dueDate: undefined, paymentType: entries.PT, message: entries.MSG,
      vs: entries['X-VS'], ss: entries['X-SS'], ks: entries['X-KS'], url: entries['X-URL'],
      crc32: entries.CRC32,
    };
    const known = new Set(['ACC', 'ALT-ACC', 'AM', 'CC', 'RF', 'RN', 'DT', 'PT', 'MSG', 'CRC32', 'NT', 'NTA', 'X-VS', 'X-SS', 'X-KS', 'X-PER', 'X-ID', 'X-URL']);
    const extra = Object.fromEntries(Object.entries(entries).filter(([k]) => !known.has(k) || ['NT', 'NTA', 'X-PER', 'X-ID'].includes(k)));
    if (Object.keys(extra).length) data.extra = extra;

    if (!entries.ACC) r.warn('caution', 'Invalid payment code: the account (ACC) is missing');
    else if (!ibanRes.valid) r.warn('danger', 'IBAN checksum invalid — likely tampered or mistyped');
    if (accBic && !isBic(accBic)) r.warn('caution', `"${accBic}" is not a valid BIC`);
    for (const alt of data.altAccounts) if (alt.iban && !checkIban(alt.iban).valid) r.warn('danger', `Alternative account ${alt.iban} has an invalid checksum`);
    if (entries.AM !== undefined) {
      data.amount = normalizeAmount(entries.AM) ?? undefined;
      if (!data.amount) r.warn('caution', `Invalid amount "${entries.AM}"`);
    }
    if (entries.CC && !/^[A-Z]{3}$/.test(entries.CC)) r.warn('caution', `Invalid currency "${entries.CC}"`);
    if (entries.DT) {
      const m = /^(\d{4})(\d{2})(\d{2})$/.exec(entries.DT);
      data.dueDate = m ? `${m[1]}-${m[2]}-${m[3]}` : entries.DT;
      if (!m) r.warn('caution', `Invalid due date "${entries.DT}"`);
    }
    for (const k of ['X-VS', 'X-SS', 'X-KS']) if (entries[k] && !/^\d{1,10}$/.test(entries[k])) r.warn('caution', `Invalid ${k.slice(2)} symbol "${entries[k]}"`);
    if (data.url) r.warnAll(embeddedUrlWarnings(data.url, ctx, 'Link'));
    if (entries.CRC32) {
      // Canonical form: header + elements sorted by key, without CRC32 (unverified detail of the spec).
      const canonical = ['SPD', version, ...order.filter(([k]) => k !== 'CRC32').sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${k}:${v}`)].join('*');
      const crc = crc32(new TextEncoder().encode(canonical)).toString(16).toUpperCase().padStart(8, '0');
      data.crc32Valid = crc === entries.CRC32.toUpperCase() ? true : null;
      if (!data.crc32Valid) r.warn('info', 'CRC32 checksum present but could not be verified');
    }

    const money = data.amount ? formatMoney(data.amount, data.currency) : '';
    r.field('Amount', money || 'Not set (you enter it)', { check: false });
    r.field('Beneficiary', data.name, { name: true, singleLine: true, copy: true });
    r.field('IBAN', ibanRes.display, { mono: true, copy: true });
    r.field('IBAN check', ibanCheckField(ibanRes), { check: false });
    r.field('BIC', data.bic, { mono: true });
    data.altAccounts.forEach((a, i) => r.field(`Alternative account ${i + 1}`, `${a.iban}${a.bic ? ` (${a.bic})` : ''}`, { mono: true }));
    r.field('Variable symbol', data.vs, { mono: true, copy: true });
    r.field('Specific symbol', data.ss, { mono: true });
    r.field('Constant symbol', data.ks, { mono: true });
    r.field('Payment reference', data.reference, { mono: true });
    r.field('Message', data.message);
    r.field('Due date', data.dueDate, { check: false });
    r.field('Payment type', data.paymentType === 'IP' ? 'Instant payment' : data.paymentType);
    r.field('Link', data.url, { mono: true });
    paymentActions(r, {
      iban: ibanRes.iban, amount: data.amount, reference: data.vs || data.reference, name: data.name,
      all: [data.name && `Beneficiary: ${data.name}`, `IBAN: ${ibanRes.display}`, money && `Amount: ${money}`, data.vs && `VS: ${data.vs}`, data.message && `Message: ${data.message}`].filter(Boolean).join('\n'),
    });

    return r.result({
      type: 'payment',
      title: 'Czech QR payment',
      summary: money ? `Pay ${money} to ${data.name || ibanRes.display || 'unknown account'}` : `Payment to ${data.name || ibanRes.display || 'unknown account'} (amount not set)`,
      data,
    });
  },
};

// ---------------------------------------------------------------------------
// EMVCo merchant-presented QR (§10.5)
// ---------------------------------------------------------------------------

const TEMPLATE_IDS = (id) => {
  const n = Number(id);
  return (n >= 26 && n <= 51) || n === 62 || n === 64 || (n >= 80 && n <= 99);
};

/**
 * Parses EMV TLV (`ID(2) LEN(2) VALUE`). LEN counts code points; when that fails on
 * non-ASCII data, UTF-8 byte counting is tried (`byteCounting: true`).
 * @returns {{ items: Array<{ id: string, value: string }>, byteCounting: boolean }|null}
 */
export function parseTlv(str) {
  const byCodePoints = (s) => {
    const chars = Array.from(s);
    const items = [];
    let i = 0;
    while (i < chars.length) {
      if (i + 4 > chars.length) return null;
      const id = chars.slice(i, i + 2).join('');
      const len = chars.slice(i + 2, i + 4).join('');
      if (!/^\d\d$/.test(id) || !/^\d\d$/.test(len)) return null;
      const n = Number(len);
      if (i + 4 + n > chars.length) return null;
      items.push({ id, value: chars.slice(i + 4, i + 4 + n).join('') });
      i += 4 + n;
    }
    return items;
  };
  const byBytes = (s) => {
    const bytes = new TextEncoder().encode(s);
    const dec = new TextDecoder();
    const items = [];
    let i = 0;
    while (i < bytes.length) {
      if (i + 4 > bytes.length) return null;
      const head = dec.decode(bytes.subarray(i, i + 4));
      if (!/^\d{4}$/.test(head)) return null;
      const n = Number(head.slice(2));
      if (i + 4 + n > bytes.length) return null;
      items.push({ id: head.slice(0, 2), value: dec.decode(bytes.subarray(i + 4, i + 4 + n)) });
      i += 4 + n;
    }
    return items;
  };
  const items = byCodePoints(str);
  if (items) return { items, byteCounting: false };
  if (/[^\x00-\x7f]/.test(str)) {
    const b = byBytes(str);
    if (b) return { items: b, byteCounting: true };
  }
  return null;
}

/** Full EMV structure check used by detect(): starts 000201 and ends with a 4-char CRC (63). */
function emvStructure(text) {
  const t = prep(text);
  if (!t.startsWith('000201')) return null;
  const tlv = parseTlv(t);
  if (!tlv) return null;
  const { items } = tlv;
  if (items[0].id !== '00' || items[0].value !== '01') return null;
  const last = items.at(-1);
  if (last.id !== '63' || last.value.length !== 4) return null;
  return { t, ...tlv };
}

/** ISO 4217 numeric → alpha codes (field 53). */
const CURRENCIES = {};
{
  const list = `986 BRL 356 INR 764 THB 702 SGD 360 IDR 704 VND 344 HKD 458 MYR 840 USD 978 EUR
156 CNY 392 JPY 410 KRW 608 PHP 826 GBP 036 AUD 124 CAD 484 MXN 170 COP 604 PEN 152 CLP 032 ARS 116 KHR 418 LAK
050 BDT 524 NPR 144 LKR 586 PKR 784 AED 682 SAR 818 EGP 710 ZAR`.split(/\s+/);
  for (let i = 0; i < list.length; i += 2) CURRENCIES[list[i]] = list[i + 1];
}

const SCHEMES = [
  [/^br\.gov\.bcb\.pix$/i, 'Pix', 'pix'],
  [/^A000000677010111$/i, 'PromptPay (credit transfer)', 'emv'],
  [/^A000000677010112$/i, 'PromptPay (bill payment)', 'emv'],
  [/^SG\.PAYNOW$/i, 'PayNow', 'emv'],
  [/^SG\.COM\.NETS$/i, 'NETS', 'emv'],
  [/^ID\.CO\.QRIS\.WWW$/i, 'QRIS', 'emv'],
  [/^A000000727/i, 'VietQR (NAPAS)', 'emv'],
  [/^hk\.com\.hkicl$/i, 'FPS (Hong Kong)', 'emv'],
  [/^(A000000615|my\.com\.paynet)/i, 'DuitNow', 'emv'],
];
const CARD_NETWORKS = {
  '02': 'Visa', '03': 'Visa', '04': 'Mastercard', '05': 'Mastercard', '09': 'Discover', '10': 'Discover',
  '11': 'Amex', '12': 'Amex', '13': 'JCB', '14': 'JCB', '15': 'UnionPay', '16': 'UnionPay',
};

/** Kind of a Pix key: email, phone, CPF, CNPJ or random (EVP). */
function pixKeyKind(key) {
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(key)) return 'email';
  if (/^\+\d{8,15}$/.test(key)) return 'phone';
  if (/^\d{11}$/.test(key)) return 'cpf';
  if (/^\d{14}$/.test(key)) return 'cnpj';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(key)) return 'random';
  return 'unknown';
}
const PIX_KEY_LABELS = { email: 'email', phone: 'phone number', cpf: 'CPF (personal tax id)', cnpj: 'CNPJ (company tax id)', random: 'random key', unknown: 'unknown kind' };

export const emv = {
  id: 'emv',
  label: 'EMV merchant QR',
  detect(text) {
    return emvStructure(text) !== null;
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const s = emvStructure(text);
    if (!s) {
      r.warn('caution', 'Malformed EMV payment code');
      return r.result({ type: 'payment', title: 'Payment code', summary: 'Malformed EMV payment code', data: { format: 'emv' } });
    }
    const { t, items, byteCounting } = s;
    if (byteCounting) r.warn('info', 'Field lengths count bytes, not characters (non-standard)');
    const top = Object.create(null);
    for (const it of items) {
      if (it.id in top) r.warn('caution', `Duplicate field ${it.id}`);
      else top[it.id] = it.value;
    }
    const sub = (id) => {
      if (!(id in top)) return null;
      const res = parseTlv(top[id]);
      if (!res) {
        r.warn('info', `Field ${id} is not a valid nested template`);
        return null;
      }
      return Object.fromEntries(res.items.map((x) => [x.id, x.value]));
    };

    // CRC over everything up to and including "6304".
    const crcGiven = top['63'];
    const crcComputed = crc16ccitt(new TextEncoder().encode(t.slice(0, t.length - 4))).toString(16).toUpperCase().padStart(4, '0');
    const crcValid = crcGiven.toUpperCase() === crcComputed;
    if (!crcValid) r.warn('danger', 'Checksum wrong — the code is damaged or was altered');
    else if (crcGiven !== crcGiven.toUpperCase()) r.warn('info', 'Checksum is written in lowercase (non-standard)');
    if (!t.endsWith(`6304${crcGiven}`)) r.warn('caution', 'The checksum is not the last field');

    // Scheme.
    let scheme = null;
    let format = 'emv';
    let pix = null;
    const accounts = [];
    for (const it of items) {
      const n = Number(it.id);
      if (n >= 2 && n <= 25) accounts.push({ id: it.id, scheme: CARD_NETWORKS[it.id] || 'Card network', value: it.value });
      if (n >= 26 && n <= 51) {
        const tpl = sub(it.id);
        const gui = tpl?.['00'] ?? '';
        const match = SCHEMES.find(([re]) => re.test(gui));
        const name = match ? match[1] : gui || `Template ${it.id}`;
        accounts.push({ id: it.id, scheme: name, gui, fields: tpl });
        if (!scheme && match) {
          scheme = match[1];
          format = match[2];
          if (format === 'pix') pix = tpl;
        }
      }
    }
    if (!scheme) scheme = accounts.find((a) => a.gui)?.gui || accounts[0]?.scheme || 'EMV merchant QR';

    const poi = top['01'];
    const dynamic = poi === '12' || !!pix?.['25'];
    const currencyNumeric = top['53'];
    const currency = getOwn(CURRENCIES, currencyNumeric) || currencyNumeric;
    const additional = sub('62') || {};
    const language = sub('64');
    const data = {
      format, scheme, pointOfInitiation: poi === '12' ? 'dynamic' : poi === '11' ? 'static' : poi ? poi : 'static',
      dynamic, merchantName: top['59'], merchantCity: top['60'], countryCode: top['58'], postalCode: top['61'],
      mcc: top['52'], currency, currencyNumeric, amount: top['54'],
      billNumber: additional['01'], mobileNumber: additional['02'], storeLabel: additional['03'],
      referenceLabel: additional['05'], terminalLabel: additional['07'], purpose: additional['08'],
      crc: crcGiven, crcComputed, crcValid, accounts,
      tlv: items.map((x) => ({ id: x.id, value: x.value, ...(TEMPLATE_IDS(x.id) ? { template: true } : {}) })),
    };
    if (language) data.alternateLanguage = { language: language['00'], name: language['01'], city: language['02'] };
    if (pix) {
      data.pixKey = pix['01'];
      data.pixKeyKind = pix['01'] ? pixKeyKind(pix['01']) : undefined;
      data.description = pix['02'];
      data.url = pix['25'];
      data.txid = additional['05'];
      if (data.pixKeyKind === 'email' || data.pixKeyKind === 'phone') r.warn('info', `The Pix key is a ${PIX_KEY_LABELS[data.pixKeyKind]}; your bank app shows the registered owner — compare it`);
    }

    // Warnings.
    if (dynamic) {
      const host = data.url ? data.url.replace(/^https?:\/\//i, '').split('/')[0] : null;
      r.warn('info', `Final amount and recipient are fetched by your bank app${host ? ` from ${host}` : ''}`);
    }
    if (data.amount === undefined) r.warn('info', 'Amount to be entered by the payer');
    else if (!/^\d+(\.\d{1,2})?$/.test(data.amount)) r.warn('caution', `Invalid amount "${data.amount}"`);
    if (top['55'] === '01') r.warn('info', 'Your app will ask whether to add a tip');
    if (top['55'] === '02' && top['56']) r.warn('caution', `Adds a fixed convenience fee of ${top['56']}`);
    if (top['55'] === '03' && top['57']) r.warn('caution', `Adds a convenience fee of ${top['57']}%`);
    if (!data.merchantName) r.warn('caution', 'Merchant name is missing');

    // Fields.
    const money = data.amount ? formatMoney(data.amount, currency) : '';
    r.field('Scheme', scheme, { check: false });
    r.field('Amount', money || 'Not set (you enter it)', { check: false });
    r.field('Merchant', data.merchantName, { name: true, singleLine: true, copy: true });
    r.field('City', data.merchantCity);
    r.field('Country', data.countryCode);
    if (pix) {
      r.field(`Pix key (${PIX_KEY_LABELS[data.pixKeyKind] || 'unknown'})`, data.pixKey, { mono: true, copy: true });
      r.field('Description', data.description);
      r.field('Payment URL', data.url, { mono: true });
      r.field('Transaction id', data.txid === '***' ? '*** (none)' : data.txid, { mono: true });
    } else {
      for (const a of accounts) {
        const value = a.fields ? Object.entries(a.fields).filter(([k]) => k !== '00').map(([k, v]) => `${k}: ${v}`).join(', ') : a.value;
        r.field(`Account (${a.scheme})`, value, { mono: true });
      }
      r.field('Reference', data.referenceLabel, { mono: true });
      r.field('Bill number', data.billNumber, { mono: true });
    }
    r.field('Code type', data.dynamic ? 'Dynamic (one-time)' : 'Static (reusable)', { check: false });
    r.field('Merchant category', data.mcc && data.mcc !== '0000' ? data.mcc : '', { mono: true, check: false });
    r.field('Checksum', crcValid ? `✓ CRC ${crcGiven.toUpperCase()} valid` : `✗ CRC ${crcGiven} (expected ${crcComputed})`, { mono: true, check: false });
    paymentActions(r, {
      iban: data.pixKey, amount: data.amount, reference: data.txid && data.txid !== '***' ? data.txid : data.referenceLabel,
      name: data.merchantName,
      all: [`Scheme: ${scheme}`, data.merchantName && `Merchant: ${data.merchantName}`, data.merchantCity && `City: ${data.merchantCity}`, money && `Amount: ${money}`, data.pixKey && `Pix key: ${data.pixKey}`].filter(Boolean).join('\n'),
    });
    if (data.pixKey) {
      const copy = r.actions.find((a) => a.label === 'Copy account');
      if (copy) copy.label = 'Copy Pix key';
    }
    r.copy('Copy code', t);

    return r.result({
      type: 'payment',
      title: `${scheme} payment`,
      summary: money ? `Pay ${money} to ${data.merchantName || 'unknown merchant'} (${scheme})` : `${scheme} payment to ${data.merchantName || 'unknown merchant'} (amount not set)`,
      data,
    });
  },
};

// ---------------------------------------------------------------------------
// UPI (§10.6)
// ---------------------------------------------------------------------------

export const upi = {
  id: 'upi',
  label: 'UPI',
  detect(text) {
    return hasPrefix(prep(text), 'upi://');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const rest = prep(text).slice(6);
    const qi = rest.indexOf('?');
    const action = (qi < 0 ? rest : rest.slice(0, qi)).replace(/\/$/, '').toLowerCase();
    const params = parseQuery(qi < 0 ? '' : rest.slice(qi + 1));
    const g = (n) => qget(params, n);
    const data = {
      format: 'upi', action, vpa: g('pa'), name: g('pn'), amount: g('am'), minAmount: g('mam'), currency: g('cu'),
      note: g('tn'), ref: g('tr'), txnId: g('tid'), mcc: g('mc'), url: g('url'), mode: g('mode'),
      purpose: g('purpose'), orgId: g('orgid'), signed: g('sign') !== undefined,
    };
    if (action !== 'pay') {
      if (action === 'mandate') r.warn('caution', 'Sets up recurring debits (UPI AutoPay mandate)');
      else r.warn('caution', `Unknown UPI action "${action}"`);
    }
    if (!data.vpa) r.warn('caution', 'Invalid UPI code: the payee address (pa) is missing');
    else if (!/^[A-Za-z0-9._-]{2,256}@[A-Za-z][A-Za-z0-9.-]{1,63}$/.test(data.vpa)) r.warn('caution', `"${data.vpa}" is not a valid UPI address`);
    if (data.amount === undefined) r.warn('info', 'Amount to be entered by the payer');
    else {
      const norm = normalizeAmount(data.amount);
      if (!norm) r.warn('caution', `Invalid amount "${data.amount}"`);
      if (data.currency && data.currency !== 'INR') r.warn('caution', `Currency is ${data.currency}; UPI payments are in INR`);
    }
    if (data.name) r.warn('info', 'The payee name is set by whoever made this code; your UPI app shows the registered name — compare it');
    r.warn('info', 'Scanning a payment QR only ever SENDS money — nobody needs you to scan a code to receive money');
    if (data.url) r.warnAll(embeddedUrlWarnings(data.url, ctx, 'Info link'));

    const money = data.amount ? formatMoney(normalizeAmount(data.amount) || data.amount, data.currency || 'INR') : '';
    r.field('Amount', money || 'Not set (you enter it)', { check: false });
    r.field('Payee', data.name, { name: true, singleLine: true });
    r.field('UPI address', data.vpa, { mono: true, singleLine: true, copy: true });
    r.field('Minimum amount', data.minAmount);
    r.field('Note', data.note);
    r.field('Reference', data.ref, { mono: true });
    r.field('Transaction id', data.txnId, { mono: true });
    r.field('Merchant category', data.mcc, { mono: true });
    r.field('Info link', data.url, { mono: true });
    r.field('Signed', data.signed ? 'Yes (signature not verified)' : '', { check: false });
    paymentActions(r, {
      iban: data.vpa, amount: data.amount, reference: data.ref, name: data.name,
      all: [data.name && `Payee: ${data.name}`, data.vpa && `UPI: ${data.vpa}`, money && `Amount: ${money}`, data.note && `Note: ${data.note}`].filter(Boolean).join('\n'),
    });
    const copy = r.actions.find((a) => a.label === 'Copy account');
    if (copy) copy.label = 'Copy UPI address';

    return r.result({
      type: 'payment',
      title: action === 'mandate' ? 'UPI mandate' : 'UPI payment',
      summary: `${money ? `Pay ${money}` : 'UPI payment'} to ${data.name || data.vpa || 'unknown payee'}${data.name && data.vpa ? ` (${data.vpa})` : ''}`,
      data,
    });
  },
};

// ---------------------------------------------------------------------------
// Bezahlcode (§10.4, details unverified)
// ---------------------------------------------------------------------------

export const bezahlcode = {
  id: 'bezahlcode',
  label: 'Bezahlcode',
  detect(text) {
    return hasPrefix(prep(text), 'bank://');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const rest = prep(text).slice(7);
    const qi = rest.indexOf('?');
    const action = (qi < 0 ? rest : rest.slice(0, qi)).replace(/\/$/, '').toLowerCase();
    const params = parseQuery(qi < 0 ? '' : rest.slice(qi + 1));
    const g = (n) => qget(params, n);
    const ibanRes = checkIban(g('iban') ?? '');
    const data = {
      format: 'bezahlcode', action, name: g('name'), iban: g('iban') !== undefined ? ibanRes.iban : undefined,
      ibanValid: g('iban') !== undefined ? ibanRes.valid : undefined, bic: g('bic'), account: g('account'), bankCode: g('bnc'),
      amount: undefined, currency: g('currency') || 'EUR', reason: g('reason'), executionDate: undefined,
      period: g('period'), lastExecutionDate: g('periodlastexecutiondate'),
    };
    if (g('amount') !== undefined) {
      data.amount = normalizeAmount(g('amount'), { decimal: ',' }) ?? normalizeAmount(g('amount')) ?? undefined;
      if (!data.amount) r.warn('caution', `Invalid amount "${g('amount')}"`);
    }
    const ed = g('executiondate');
    if (ed) {
      const m = /^(\d{2})(\d{2})(\d{4})$/.exec(ed);
      data.executionDate = m ? `${m[3]}-${m[2]}-${m[1]}` : ed;
    }
    const known = ['singlepayment', 'singlepaymentsepa', 'singledirectdebit', 'singledirectdebitsepa', 'periodicsinglepayment', 'periodicsinglepaymentsepa'];
    if (!known.includes(action)) r.warn('caution', `Unknown Bezahlcode type "${action}"`);
    if (action.includes('directdebit')) r.warn('caution', 'This is a direct debit — it authorises taking money from your account');
    if (action.startsWith('periodic')) r.warn('info', `Recurring payment${data.period ? ` (${data.period})` : ''}`);
    if (data.iban !== undefined && !ibanRes.valid) r.warn('danger', 'IBAN checksum invalid — likely tampered or mistyped');
    if (data.iban === undefined && !data.account) r.warn('caution', 'No account given');
    if (data.bic && !isBic(data.bic)) r.warn('caution', `"${data.bic}" is not a valid BIC`);
    r.warn('info', 'Bezahlcode is a legacy format; most banking apps now use the EPC (GiroCode) QR');

    const money = data.amount ? formatMoney(data.amount, data.currency) : '';
    r.field('Amount', money || 'Not set (you enter it)', { check: false });
    r.field('Beneficiary', data.name, { name: true, singleLine: true, copy: true });
    r.field('IBAN', data.iban ? ibanRes.display : '', { mono: true, copy: true });
    r.field('IBAN check', data.iban !== undefined ? ibanCheckField(ibanRes) : '', { check: false });
    r.field('BIC', data.bic, { mono: true });
    r.field('Account number', data.account, { mono: true });
    r.field('Bank code', data.bankCode, { mono: true });
    r.field('Reason', data.reason);
    r.field('Execution date', data.executionDate, { check: false });
    paymentActions(r, {
      iban: data.iban || data.account, amount: data.amount, reference: data.reason, name: data.name,
      all: [data.name && `Beneficiary: ${data.name}`, data.iban && `IBAN: ${ibanRes.display}`, money && `Amount: ${money}`, data.reason && `Reason: ${data.reason}`].filter(Boolean).join('\n'),
    });

    return r.result({
      type: 'payment',
      title: 'Bank transfer (Bezahlcode)',
      summary: money ? `Pay ${money} to ${data.name || 'unknown beneficiary'}` : `Bank transfer to ${data.name || 'unknown beneficiary'} (amount not set)`,
      data,
    });
  },
};


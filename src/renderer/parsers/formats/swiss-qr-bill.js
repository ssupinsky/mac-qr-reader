// Swiss QR-bill (`SPC`, Implementation Guidelines v2.3), PAYLOADS.md §10.2.

import { createReport, prep, group } from './util.js';
import { checkIban, checkQrReference, checkRfReference, formatMoney, PAYMENT_INFO } from './banking.js';

/** Extended character set allowed since v2.3. */
const ALLOWED = /^[ -~ -ſȘ-ț€]*$/u;

/** Reads a 7-line address block starting at `i` (AdrTp, Name, …, Country). */
function address(l, i) {
  const [type = '', name = '', a = '', b = '', postcode = '', town = '', country = ''] = l.slice(i, i + 7);
  if (![type, name, a, b, postcode, town, country].some(Boolean)) return null;
  if (type === 'K') return { addressType: 'K', name, addressLine1: a, addressLine2: b, postcode, town, country };
  return { addressType: type, name, street: a, building: b, postcode, town, country };
}

function formatAddress(adr) {
  if (!adr) return '';
  const street = adr.addressType === 'K'
    ? [adr.addressLine1, adr.addressLine2].filter(Boolean).join(', ')
    : [adr.street, adr.building].filter(Boolean).join(' ');
  const town = [adr.postcode, adr.town].filter(Boolean).join(' ');
  return [street, town, adr.country].filter(Boolean).join(', ');
}

export const swissQrBill = {
  id: 'swiss-qr-bill',
  label: 'Swiss QR-bill',
  detect(text) {
    return /^SPC(\r\n|\n|$)/.test(prep(text));
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const payload = prep(text);
    const crlf = payload.includes('\r\n');
    if (crlf && /[^\r]\n/.test(payload)) r.warn('info', 'Mixed line endings (CRLF and LF)');
    const l = payload.split(/\r\n|\n/);

    const version = l[1] ?? '';
    const coding = l[2] ?? '';
    const ibanRes = checkIban(l[3] ?? '');
    const iid = Number(ibanRes.iban.slice(4, 9));
    const qrIban = /^(CH|LI)/.test(ibanRes.iban) && iid >= 30000 && iid <= 31999;
    const creditor = address(l, 4) || { addressType: '', name: '' };
    const ultimateCreditor = address(l, 11);
    const amount = l[18] ?? '';
    const currency = l[19] ?? '';
    const debtor = address(l, 20);
    const refType = l[27] ?? '';
    const reference = (l[28] ?? '').replace(/ /g, '');
    const message = l[29] ?? '';
    const trailer = l[30] ?? '';
    const billInfo = l[31] ?? '';
    const altProcedures = l.slice(32).filter(Boolean);

    const data = {
      format: 'swiss-qr-bill', version, coding, iban: ibanRes.iban, qrIban, ibanValid: ibanRes.valid,
      creditor, ultimateCreditor, amount, currency, debtor, refType, reference, referenceValid: null,
      message, trailer, billInfo, altProcedures,
    };

    // Header.
    if (!/^02\d\d$/.test(version)) r.warn('caution', `Unsupported QR-bill version "${version}"`);
    if (coding !== '1') r.warn('caution', `Unsupported coding type "${coding}" (1 = UTF-8 expected)`);
    if (trailer !== 'EPD') r.warn('caution', 'Not a complete QR-bill (the "EPD" trailer is missing)');
    if (Array.from(payload).length > 997) r.warn('caution', 'Payload is longer than 997 characters');

    // Account.
    if (!ibanRes.iban) r.warn('caution', 'IBAN is missing');
    else if (!ibanRes.valid) r.warn('danger', 'IBAN checksum invalid — likely tampered or mistyped');
    if (ibanRes.iban && !/^(CH|LI)/.test(ibanRes.iban)) r.warn('caution', 'QR-bills require a Swiss or Liechtenstein IBAN');

    // Addresses.
    if (!creditor.name) r.warn('caution', 'Creditor name is missing');
    if (creditor.addressType === 'K') r.warn('info', 'Outdated address format (combined address, not allowed since 21 Nov 2025)');
    else if (creditor.addressType && creditor.addressType !== 'S') r.warn('caution', `Unknown address type "${creditor.addressType}"`);
    if (ultimateCreditor) r.warn('caution', 'The "ultimate creditor" block must be empty, but it is filled');
    if (debtor?.addressType === 'K') r.warn('info', 'Debtor uses the outdated combined address format');

    // Amount.
    if (!amount) r.warn('info', 'Amount to be entered by the payer');
    else if (!/^\d{1,9}\.\d{2}$/.test(amount) || Number(amount) < 0.01) r.warn('caution', `Invalid amount "${amount}"`);
    if (currency !== 'CHF' && currency !== 'EUR') r.warn('caution', `Invalid currency "${currency}" (CHF or EUR expected)`);

    // Reference vs account type.
    if (refType === 'QRR') {
      data.referenceValid = checkQrReference(reference);
      if (!data.referenceValid) r.warn('danger', 'QR reference check digit is wrong — likely tampered or mistyped');
      else if (/^0+$/.test(reference)) r.warn('caution', 'QR reference must not be all zeros');
      if (!qrIban && ibanRes.iban) r.warn('danger', "Reference type doesn't match the account type (QR reference with a normal IBAN)");
    } else if (refType === 'SCOR') {
      data.referenceValid = checkRfReference(reference) && reference.length >= 5 && reference.length <= 25;
      if (!data.referenceValid) r.warn('caution', `Creditor reference "${reference}" is invalid`);
      if (qrIban) r.warn('danger', "Reference type doesn't match the account type (QR-IBAN requires a QR reference)");
    } else if (refType === 'NON') {
      if (reference) r.warn('caution', 'Reference type is NON but a reference is set');
      if (qrIban) r.warn('danger', "Reference type doesn't match the account type (QR-IBAN requires a QR reference)");
    } else {
      r.warn('caution', `Unknown reference type "${refType}"`);
    }
    if (Array.from(message + billInfo).length > 140) r.warn('caution', 'Message and bill information together exceed 140 characters');
    if (altProcedures.length > 2) r.warn('caution', `Too many alternative procedures (${altProcedures.length}; at most 2)`);
    if (altProcedures.some((a) => Array.from(a).length > 100)) r.warn('caution', 'An alternative procedure is longer than 100 characters');
    if (!ALLOWED.test(payload.replace(/\r?\n/g, ''))) r.warn('caution', 'Contains characters not allowed in QR-bills');

    // Presentation.
    const money = amount ? formatMoney(amount, currency) : '';
    const refDisplay = refType === 'QRR' && /^\d{27}$/.test(reference)
      ? `${reference.slice(0, 2)} ${group(reference.slice(2), 5)}`
      : refType === 'SCOR' ? group(reference, 4) : reference;
    r.field('Amount', money || `Not set (you enter it${currency ? `, ${currency}` : ''})`, { check: false });
    r.field('Pay to', creditor.name, { name: true, singleLine: true, copy: true });
    r.field('Creditor address', formatAddress(creditor));
    r.field(qrIban ? 'QR-IBAN' : 'IBAN', ibanRes.display, { mono: true, copy: true });
    r.field('IBAN check', ibanRes.iban ? (ibanRes.valid ? '✓ Checksum valid' : '✗ Checksum invalid') : '', { check: false });
    r.field(refType === 'QRR' ? 'QR reference' : refType === 'SCOR' ? 'Creditor reference' : 'Reference', refDisplay, { mono: true, copy: true });
    if (data.referenceValid !== null) r.field('Reference check', data.referenceValid ? '✓ Check digit valid' : '✗ Check digit invalid', { check: false });
    r.field('Message', message);
    if (debtor) {
      r.field('Payable by', debtor.name, { name: true, singleLine: true });
      r.field('Payer address', formatAddress(debtor));
    }
    r.field('Bill information', billInfo, { mono: true });
    altProcedures.forEach((a, i) => r.field(`Alternative procedure ${i + 1}`, a, { mono: true }));
    r.warn('info', PAYMENT_INFO);

    if (ibanRes.iban) r.copy('Copy IBAN', ibanRes.iban);
    if (amount) r.copy('Copy amount', amount);
    if (reference) r.copy('Copy reference', reference);
    if (creditor.name) r.copy('Copy beneficiary', creditor.name);
    r.copy('Copy all as text', [
      `Pay to: ${creditor.name}`, formatAddress(creditor), `IBAN: ${ibanRes.display}`, money && `Amount: ${money}`,
      reference && `Reference: ${refDisplay}`, message && `Message: ${message}`,
    ].filter(Boolean).join('\n'));

    return r.result({
      type: 'swiss-qr-bill',
      title: 'Swiss QR-bill',
      summary: money ? `Pay ${money} to ${creditor.name || 'unknown creditor'}` : `QR-bill from ${creditor.name || 'unknown creditor'} (amount not set)`,
      data,
    });
  },
};

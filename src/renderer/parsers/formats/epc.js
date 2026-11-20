// EPC069-12 SEPA Credit Transfer QR ("GiroCode", `BCD`), PAYLOADS.md §10.1.

import { createReport, prep, utf8Length } from './util.js';
import { checkIban, checkRfReference, isBic, formatMoney, PAYMENT_INFO } from './banking.js';

/** EPC character set codes → WHATWG TextDecoder labels. */
const CHARSETS = {
  1: 'utf-8', 2: 'iso-8859-1', 3: 'iso-8859-2', 4: 'iso-8859-4',
  5: 'iso-8859-5', 6: 'iso-8859-7', 7: 'iso-8859-10', 8: 'iso-8859-15',
};

const lines = (s) => s.split(/\r\n|\n/);

export const epc = {
  id: 'epc',
  label: 'SEPA payment',
  detect(text) {
    const l = lines(prep(text));
    return l[0] === 'BCD' && l[3] === 'SCT';
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    let payload = prep(text);
    let l = lines(payload);
    const version = l[1] ?? '';
    const charsetRaw = l[2] ?? '';
    const charset = /^[1-8]$/.test(charsetRaw) ? Number(charsetRaw) : null;

    // Re-decode from the raw bytes using the declared character set (§10.1).
    let byteLength = utf8Length(payload);
    if (charset && charset !== 1) {
      if (ctx.bytes instanceof Uint8Array && ctx.bytesKind !== 'raw') {
        try {
          const decoded = prep(new TextDecoder(CHARSETS[charset]).decode(ctx.bytes));
          if (lines(decoded)[0] === 'BCD') {
            if (decoded !== payload) r.warn('info', `Decoded with the declared character set (${CHARSETS[charset].toUpperCase()})`);
            payload = decoded;
            l = lines(payload);
            byteLength = ctx.bytes.length;
          }
        } catch {
          r.warn('info', `Character set ${charset} declared; text decoding not verified`);
        }
      } else {
        r.warn('info', `Character set ${charset} (${CHARSETS[charset].toUpperCase()}) declared; text decoding not verified`);
      }
    }

    const [, , , , bic = '', name = '', ibanRaw = '', amountRaw = '', purpose = '', reference = '', remittance = '', info = ''] = l;
    const ibanRes = checkIban(ibanRaw);
    const data = {
      format: 'epc', version, charset: charset ?? charsetRaw, bic, name, iban: ibanRes.iban, ibanValid: ibanRes.valid,
      amount: null, currency: null, purpose, reference, referenceValid: null, text: remittance, info,
    };

    // Validation.
    if (version !== '001' && version !== '002') r.warn('caution', `Unknown EPC version "${version}"`);
    if (!charset) r.warn('caution', `Invalid character set "${charsetRaw}" (1–8 expected)`);
    if (version === '001' && !bic) r.warn('caution', 'Version 001 requires the BIC, but it is missing');
    if (bic && !isBic(bic)) r.warn('caution', `"${bic}" is not a valid BIC`);
    if (!name) r.warn('caution', 'Beneficiary name is missing');
    if (!ibanRaw) r.warn('caution', 'IBAN is missing');
    else if (!ibanRes.valid) r.warn('danger', 'IBAN checksum invalid — likely tampered or mistyped');
    if (amountRaw) {
      const m = /^([A-Z]{3})(\d{1,9}(?:\.\d{1,2})?)$/.exec(amountRaw);
      if (!m) r.warn('caution', `Invalid amount "${amountRaw}" (expected e.g. EUR12.30)`);
      else {
        const [int, frac = ''] = m[2].split('.');
        data.amount = `${int.replace(/^0+(?=\d)/, '')}.${frac.padEnd(2, '0')}`;
        data.currency = m[1];
        if (m[1] !== 'EUR') r.warn('caution', `Amount is in ${m[1]}; SEPA transfers must be in EUR`);
        if (Number(data.amount) < 0.01) r.warn('caution', 'Amount must be at least 0.01');
      }
    }
    if (purpose && !/^[A-Z0-9]{1,4}$/.test(purpose)) r.warn('caution', `Invalid purpose code "${purpose}"`);
    if (reference && remittance) r.warn('caution', 'Both a structured reference and a free-text remittance are set; only one is allowed');
    if (reference && /^RF/i.test(reference)) {
      data.referenceValid = checkRfReference(reference);
      if (!data.referenceValid) r.warn('caution', `Creditor reference "${reference}" fails its check digits`);
    }
    const limits = [['BIC', bic, 11], ['Beneficiary name', name, 70], ['IBAN', ibanRaw, 34], ['Reference', reference, 35], ['Remittance text', remittance, 140], ['Note to payer', info, 70]];
    for (const [label, value, max] of limits) if (Array.from(value).length > max) r.warn('caution', `${label} is longer than allowed (${Array.from(value).length} > ${max})`);
    if (byteLength > 331) r.warn('info', `Payload is ${byteLength} bytes; the EPC limit is 331`);
    if (l.length > 12) r.warn('caution', `Unexpected extra lines (${l.length} instead of at most 12)`);

    // Presentation ("What you'd pay").
    const money = data.amount ? formatMoney(data.amount, data.currency) : '';
    r.field('Amount', money || 'Not set (you enter it)', { check: false });
    r.field('Beneficiary', name, { name: true, singleLine: true, copy: true });
    r.field('IBAN', ibanRes.display || ibanRaw, { mono: true, singleLine: true, copy: true });
    r.field('IBAN check', ibanRaw ? (ibanRes.valid ? '✓ Checksum valid' : '✗ Checksum invalid') : '', { check: false });
    r.field('BIC', bic, { mono: true });
    r.field('Reference', reference, { mono: true, copy: true });
    if (data.referenceValid !== null) r.field('Reference check', data.referenceValid ? '✓ Check digits valid' : '✗ Check digits invalid', { check: false });
    r.field('Remittance', remittance);
    r.field('Purpose code', purpose, { mono: true });
    r.field('Note to payer', info);
    r.warn('info', PAYMENT_INFO);
    r.warn('info', 'Your bank will check the name against the IBAN (EU Verification of Payee)');

    if (ibanRes.iban) r.copy('Copy IBAN', ibanRes.iban);
    if (data.amount) r.copy('Copy amount', data.amount);
    if (reference || remittance) r.copy('Copy reference', reference || remittance);
    if (name) r.copy('Copy beneficiary', name);
    r.copy('Copy all as text', [
      `Beneficiary: ${name}`, `IBAN: ${ibanRes.display}`, bic && `BIC: ${bic}`, money && `Amount: ${money}`,
      reference && `Reference: ${reference}`, remittance && `Remittance: ${remittance}`,
    ].filter(Boolean).join('\n'));

    return r.result({
      type: 'epc-payment',
      title: 'SEPA bank transfer',
      summary: money ? `Pay ${money} to ${name || 'unknown beneficiary'}` : `Bank transfer to ${name || 'unknown beneficiary'} (amount not set)`,
      data,
    });
  },
};

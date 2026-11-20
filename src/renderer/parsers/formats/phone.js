// Phone, SMS and FaceTime payloads (PAYLOADS.md §6): `tel:` (RFC 3966) with USSD/MMI
// detection, `sms:`/`mms:` (RFC 5724), DoCoMo `SMSTO:`/`MMSTO:`, `facetime:` and
// `facetime-audio:` (with or without `//`).

import { createReport, hasPrefix, matchPrefix, prep, pctDecode, parseQuery, qget, embeddedUrlWarnings, extractUrls, isEmailAddress, domainWarnings, truncate, encodeComponent } from './util.js';
import { hasOwn, setOwn } from '../dict.js';

/** Calling-code prefixes (longest match wins) → region, for display only. */
const CALLING_CODES = {
  1: 'USA / Canada / Caribbean', 7: 'Russia / Kazakhstan', 20: 'Egypt', 27: 'South Africa', 30: 'Greece',
  31: 'Netherlands', 32: 'Belgium', 33: 'France', 34: 'Spain', 36: 'Hungary', 39: 'Italy', 40: 'Romania',
  41: 'Switzerland', 43: 'Austria', 44: 'United Kingdom', 45: 'Denmark', 46: 'Sweden', 47: 'Norway',
  48: 'Poland', 49: 'Germany', 51: 'Peru', 52: 'Mexico', 54: 'Argentina', 55: 'Brazil', 56: 'Chile',
  57: 'Colombia', 60: 'Malaysia', 61: 'Australia', 62: 'Indonesia', 63: 'Philippines', 64: 'New Zealand',
  65: 'Singapore', 66: 'Thailand', 81: 'Japan', 82: 'South Korea', 84: 'Vietnam', 86: 'China', 90: 'Turkey',
  91: 'India', 92: 'Pakistan', 98: 'Iran', 351: 'Portugal', 352: 'Luxembourg', 353: 'Ireland', 354: 'Iceland',
  358: 'Finland', 359: 'Bulgaria', 370: 'Lithuania', 371: 'Latvia', 372: 'Estonia', 380: 'Ukraine',
  381: 'Serbia', 385: 'Croatia', 386: 'Slovenia', 420: 'Czechia', 421: 'Slovakia', 423: 'Liechtenstein',
  852: 'Hong Kong', 853: 'Macau', 880: 'Bangladesh', 886: 'Taiwan', 966: 'Saudi Arabia', 971: 'United Arab Emirates',
  972: 'Israel', 974: 'Qatar',
};

function regionOf(digits) {
  for (const len of [3, 2, 1]) {
    const region = CALLING_CODES[digits.slice(0, len)];
    if (region) return region;
  }
  return null;
}

/**
 * Checks a phone number string (already percent-decoded) per §6.1.
 * @param {string} input
 * @param {{ label?: string }} [opts] prefix for warning messages
 * @returns {{ normalized: string, digits: string, global: boolean, ussd: boolean, region: string|null,
 *   warnings: Array<{level, message}> }}
 */
export function analyzePhoneNumber(input, { label = 'Phone number' } = {}) {
  const raw = String(input ?? '');
  const warnings = [];
  const ussd = /[*#]/.test(raw);
  const global = raw.trim().startsWith('+');
  const normalized = raw.replace(/[\s\-.() ]/g, '');
  const digits = normalized.replace(/\D/g, '');
  if (ussd) {
    warnings.push({
      level: 'danger',
      message: `${label} "${truncate(raw, 40)}" is a USSD/MMI service code, not a phone number — it can change phone settings (e.g. *21* call forwarding)`,
    });
  }
  if (!digits && !ussd) warnings.push({ level: 'caution', message: `${label} is empty or invalid` });
  if (/[A-Za-z]/.test(normalized.replace(/^\+/, ''))) warnings.push({ level: 'info', message: `${label} contains letters (vanity number)` });
  if (digits.length > 15) warnings.push({ level: 'caution', message: `${label} has ${digits.length} digits — longer than any valid international number` });
  if (!global && !ussd && digits.length >= 3 && digits.length <= 6) warnings.push({ level: 'info', message: `${label} is a short code` });
  return { normalized, digits, global, ussd, region: global ? regionOf(digits) : null, warnings };
}

// ---------------------------------------------------------------------------
// tel:
// ---------------------------------------------------------------------------

export const tel = {
  id: 'tel',
  label: 'phone',
  detect(text) {
    return hasPrefix(prep(text), 'tel:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const body = prep(text).slice(4);
    const rawUssd = /%2[3Aa]/.test(body);
    const [numberPart, ...paramParts] = body.split(';');
    const display = pctDecode(numberPart).value;
    const params = {};
    for (const p of paramParts) {
      const eq = p.indexOf('=');
      const name = (eq < 0 ? p : p.slice(0, eq)).toLowerCase();
      if (name) setOwn(params, name, eq < 0 ? '' : pctDecode(p.slice(eq + 1)).value);
    }
    const info = analyzePhoneNumber(display);
    if (rawUssd && !info.ussd) info.ussd = true;
    r.warnAll(info.warnings);
    if (/\s/.test(numberPart)) r.warn('caution', 'Spaces are not allowed in tel: links (accepted anyway)');
    if (!info.global && !info.ussd && !hasOwn(params, 'phone-context') && info.digits.length > 6) {
      r.warn('info', 'No country code — the number depends on where you call from');
    }

    const data = {
      format: 'tel',
      number: info.normalized,
      display,
      global: info.global,
      ussd: info.ussd,
      ext: params.ext,
      isub: params.isub,
      phoneContext: params['phone-context'],
      params,
    };
    r.field('Number', display, { mono: true, singleLine: true, copy: true });
    r.field('Extension', data.ext, { mono: true });
    r.field('Subaddress', data.isub, { mono: true });
    r.field('Phone context', data.phoneContext, { mono: true });
    r.field('Region', info.region, { check: false });

    if (!info.ussd && info.digits) {
      r.open('Call…', `tel:${info.normalized}${data.ext ? `;ext=${encodeComponent(data.ext)}` : ''}`);
    }
    r.copy('Copy number', info.normalized || display);

    return r.result({
      type: 'phone',
      title: info.ussd ? 'Service code (USSD)' : 'Phone number',
      summary: `${info.ussd ? 'Service code' : 'Call'} ${display}${data.ext ? ` ext. ${data.ext}` : ''}`,
      data,
    });
  },
};

// ---------------------------------------------------------------------------
// FaceTime
// ---------------------------------------------------------------------------

export const facetime = {
  id: 'facetime',
  label: 'FaceTime',
  detect(text) {
    return !!matchPrefix(prep(text), ['facetime-audio:', 'facetime:']);
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const service = hasPrefix(t, 'facetime-audio:') ? 'facetime-audio' : 'facetime';
    let rest = t.slice(service.length + 1);
    if (rest.startsWith('//')) rest = rest.slice(2);
    rest = rest.split(/[?#]/)[0].replace(/\/$/, '');
    const target = pctDecode(rest).value;
    const isEmail = target.includes('@');
    const data = { format: service, service, target, targetKind: isEmail ? 'email' : 'phone' };
    if (isEmail) {
      if (!isEmailAddress(target)) r.warn('caution', `"${truncate(target, 40)}" is not a valid email address`);
      r.warnAll(domainWarnings(target.slice(target.lastIndexOf('@') + 1), 'Email domain'));
    } else {
      r.warnAll(analyzePhoneNumber(target).warnings);
    }
    const kind = service === 'facetime-audio' ? 'FaceTime Audio' : 'FaceTime';
    r.field('Service', kind, { check: false });
    r.field(isEmail ? 'Email' : 'Number', target, { mono: true, singleLine: true, copy: true });
    if (!r.hasLevel('danger') && target) r.open(`${kind} call…`, `${service}:${isEmail ? target : target.replace(/[\s\-.()]/g, '')}`);
    r.copy(isEmail ? 'Copy address' : 'Copy number', target);
    return r.result({ type: 'phone', title: `${kind} call`, summary: `${kind} call to ${target || '(nobody)'}`, data });
  },
};

// ---------------------------------------------------------------------------
// sms: / mms: / SMSTO: / MMSTO:
// ---------------------------------------------------------------------------

export const sms = {
  id: 'sms',
  label: 'SMS',
  detect(text) {
    return !!matchPrefix(prep(text), ['smsto:', 'mmsto:', 'sms:', 'mms:']);
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const prefix = matchPrefix(t, ['smsto:', 'mmsto:', 'sms:', 'mms:']);
    const format = prefix.slice(0, -1).toLowerCase();
    const rest = t.slice(prefix.length);
    let recipientsRaw;
    let body;
    let subject;

    if (format === 'smsto' || format === 'mmsto') {
      // DoCoMo/ZXing: number, first ':' then the raw (not percent-encoded) message.
      const colon = rest.indexOf(':');
      recipientsRaw = colon < 0 ? rest : rest.slice(0, colon);
      body = colon < 0 ? '' : rest.slice(colon + 1);
    } else {
      let q = rest.indexOf('?');
      let path = q < 0 ? rest : rest.slice(0, q);
      let query = q < 0 ? '' : rest.slice(q + 1);
      if (q < 0) {
        const amp = rest.search(/&body=/i);
        if (amp >= 0) {
          path = rest.slice(0, amp);
          query = rest.slice(amp + 1);
          r.warn('info', 'Non-standard format ("&body=" without "?"); read it like iOS does');
        }
      }
      recipientsRaw = path;
      const params = parseQuery(query);
      body = qget(params, 'body');
      subject = qget(params, 'subject');
      const others = params.filter((p) => !['body', 'subject'].includes(p.name)).map((p) => p.name);
      if (others.length) r.warn('info', `Unknown parameters: ${others.join(', ')}`);
    }

    const recipients = recipientsRaw.split(',').map((x) => pctDecode(x).value.trim()).filter(Boolean);
    const normalizedRecipients = [];
    recipients.forEach((rcpt, i) => {
      const label = recipients.length > 1 ? `Recipient ${i + 1}` : 'Recipient';
      const info = analyzePhoneNumber(rcpt, { label });
      normalizedRecipients.push(info.normalized);
      r.warnAll(info.warnings.filter((w) => !/short code/.test(w.message)));
      if (!info.global && !info.ussd && info.digits.length >= 1 && info.digits.length <= 6) {
        r.warn('caution', `${label} ${rcpt} is a short code — it could be a premium-rate service`);
      }
    });
    if (!recipients.length) r.warn('info', 'No recipient — you would choose one in Messages');
    if (recipients.length > 1) r.warn('info', `${recipients.length} recipients`);

    const data = { format, recipients, body: body ?? '', subject };
    recipients.forEach((rcpt, i) => r.field(recipients.length > 1 ? `To (${i + 1})` : 'To', rcpt, { mono: true, singleLine: true, copy: true }));
    r.field('Subject', subject);
    if (body) {
      const invisible = r.check('Message', body);
      if (invisible) r.warn('caution', 'Message contains hidden characters');
      r.field('Message', body, { check: false, copy: true });
      for (const url of extractUrls(body)) r.warnAll(embeddedUrlWarnings(url, ctx, 'Message link'));
    }

    if (!r.hasLevel('danger') && (recipients.length || body)) {
      const to = normalizedRecipients.join(',');
      r.open('Open in Messages…', `sms:${to}${body ? `?body=${encodeComponent(body)}` : ''}`);
    }
    if (recipients.length) r.copy(recipients.length > 1 ? 'Copy numbers' : 'Copy number', recipients.join(', '));
    if (body) r.copy('Copy message', body);

    const kind = format.startsWith('mms') ? 'MMS' : 'Text message';
    return r.result({
      type: 'sms',
      title: kind,
      summary: `${kind} to ${recipients.join(', ') || '(no recipient)'}${body ? `: “${truncate(body, 50)}”` : ''}`,
      data,
    });
  },
};

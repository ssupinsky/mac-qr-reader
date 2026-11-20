// Two-factor `otpauth://` Key URIs (Google Authenticator format, PAYLOADS.md §9.1).
// The live code is computed asynchronously by `../totp.js` from `data.otpParams`.

import { createReport, hasPrefix, prep, pctDecode, group, encodeComponent } from './util.js';
import { base32Decode } from './codecs.js';
import { hasOwn, setOwn } from '../dict.js';

export const SECRET_WARNING = "Contains a 2FA secret — anyone who sees this code can generate your login codes. Don't share or screenshot it.";

/**
 * Builds an otpauth:// URI (used by the migration parser and for normalised copies).
 * @param {{ type: 'totp'|'hotp', issuer?: string, account?: string, secretB32: string,
 *   algorithm?: string, digits?: number, period?: number, counter?: number|string }} p
 */
export function buildOtpauthUri(p) {
  const label = p.issuer
    ? `${encodeComponent(p.issuer)}:${encodeComponent(p.account || '')}`
    : encodeComponent(p.account || '');
  const q = [`secret=${p.secretB32}`];
  if (p.issuer) q.push(`issuer=${encodeComponent(p.issuer)}`);
  if (p.algorithm) q.push(`algorithm=${p.algorithm}`);
  if (p.digits) q.push(`digits=${p.digits}`);
  if (p.type === 'hotp') q.push(`counter=${p.counter ?? 0}`);
  else if (p.period) q.push(`period=${p.period}`);
  return `otpauth://${p.type}/${label}?${q.join('&')}`;
}

export const otpauth = {
  id: 'otpauth',
  label: 'otpauth',
  detect(text) {
    const t = prep(text);
    return hasPrefix(t, 'otpauth://') && !hasPrefix(t, 'otpauth-migration:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const uri = prep(text);
    r.warn('caution', SECRET_WARNING);

    // Manual split: otpauth://TYPE/LABEL?QUERY (WHATWG keeps opaque hosts as-is anyway).
    const rest = uri.slice('otpauth://'.length).replace(/#.*$/s, '');
    const qi = rest.indexOf('?');
    const path = qi < 0 ? rest : rest.slice(0, qi);
    const query = qi < 0 ? '' : rest.slice(qi + 1);
    const slash = path.indexOf('/');
    const type = (slash < 0 ? path : path.slice(0, slash)).toLowerCase();
    const rawLabel = slash < 0 ? '' : path.slice(slash + 1);
    const labelDec = pctDecode(rawLabel);
    if (!labelDec.ok) r.warn('info', 'Label is not valid percent-encoding; shown as-is');
    const label = labelDec.value;

    const params = {};
    for (const part of query.split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const name = pctDecode(eq < 0 ? part : part.slice(0, eq)).value.toLowerCase();
      if (hasOwn(params, name)) {
        r.warn('caution', `Duplicate parameter "${name}" (the first one is used)`);
        continue;
      }
      setOwn(params, name, eq < 0 ? '' : pctDecode(part.slice(eq + 1)).value);
    }

    // Label: "Issuer:account" (literal or %3A colon), leading spaces of account trimmed.
    let labelIssuer;
    let account = label;
    const colon = label.indexOf(':');
    if (colon >= 0) {
      labelIssuer = label.slice(0, colon);
      account = label.slice(colon + 1).replace(/^ +/, '');
      if (account.includes(':')) r.warn('caution', 'Label contains more than one ":"; the rest is kept in the account name');
    }
    const issuer = params.issuer ?? labelIssuer;
    if (params.issuer !== undefined && labelIssuer !== undefined && params.issuer !== labelIssuer) {
      r.warn('caution', `Issuer mismatch (label says "${labelIssuer}", issuer says "${params.issuer}")`);
    }

    if (type !== 'totp' && type !== 'hotp') r.warn('caution', `Unknown OTP type "${type}"; most apps only support TOTP and HOTP`);

    // Secret.
    const data = { format: 'otpauth', type, issuer, account, label };
    let computable = type === 'totp' || type === 'hotp';
    if (params.secret === undefined || params.secret.trim() === '') {
      r.warn('caution', 'Invalid code: the secret is missing');
      computable = false;
    } else {
      const dec = base32Decode(params.secret);
      if (dec.invalid.length) {
        r.warn('caution', `Invalid secret: not base32 (contains ${dec.invalid.map((c) => `"${c}"`).join(', ')})`);
        computable = false;
        data.secretB32 = dec.normalized;
      } else {
        data.secretB32 = dec.normalized;
        data.secretBytes = dec.bytes.length;
        if (params.secret !== dec.normalized) r.warn('info', 'Secret was normalised (lowercase, spaces or padding removed)');
        if (dec.leftoverNonZero) r.warn('info', 'Secret has leftover bits that are ignored');
        if (dec.bytes.length * 8 < 80) r.warn('caution', `Weak secret (${dec.bytes.length * 8} bits; at least 128 are recommended)`);
        if (!dec.bytes.length) computable = false;
      }
    }

    // Parameters.
    const algorithm = (params.algorithm ?? 'SHA1').toUpperCase().replace('-', '');
    if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) {
      r.warn('caution', `Unsupported algorithm "${params.algorithm}"`);
      computable = false;
    }
    const digits = params.digits === undefined ? 6 : /^\d+$/.test(params.digits) ? Number(params.digits) : NaN;
    if (!(digits >= 6 && digits <= 8)) {
      r.warn('caution', `Unusual number of digits "${params.digits}" (6–8 expected)`);
      if (!(digits >= 1 && digits <= 10)) computable = false;
    }
    data.algorithm = algorithm;
    data.digits = digits;

    if (type === 'hotp') {
      if (params.counter === undefined) {
        r.warn('caution', 'Invalid HOTP code: the counter is missing');
        computable = false;
      } else if (!/^\d+$/.test(params.counter)) {
        r.warn('caution', `Invalid counter "${params.counter}"`);
        computable = false;
      } else {
        const big = BigInt(params.counter);
        data.counter = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : params.counter;
      }
    } else {
      const period = params.period === undefined ? 30 : /^\d+$/.test(params.period) ? Number(params.period) : NaN;
      if (!(period > 0)) {
        r.warn('caution', `Invalid period "${params.period}"`);
        computable = false;
      } else if (period !== 30) {
        r.warn('info', `Non-standard period ${period} s (some apps ignore it)`);
      }
      data.period = period;
    }
    if (algorithm !== 'SHA1' || digits !== 6 || (data.period !== undefined && data.period !== 30)) {
      r.warn('info', 'Some apps (Google Authenticator historically) ignore the algorithm, digits and period settings');
    }
    if (params.image) {
      data.image = params.image;
      r.warn('caution', 'Contains a remote image link (an authenticator app may fetch it)');
    }
    const known = new Set(['secret', 'issuer', 'algorithm', 'digits', 'period', 'counter', 'image']);
    const extra = Object.keys(params).filter((k) => !known.has(k));
    if (extra.length) data.extra = Object.fromEntries(extra.map((k) => [k, params[k]]));

    data.codeComputable = computable;
    if (computable) {
      data.otpParams = {
        secret: data.secretB32, algorithm, digits,
        ...(type === 'hotp' ? { counter: data.counter } : { period: data.period }),
      };
    }

    // Presentation.
    r.field('Issuer', issuer, { name: true, singleLine: true });
    r.field('Account', account, { singleLine: true, copy: true });
    r.field('Type', type === 'totp' ? 'Time-based (TOTP)' : type === 'hotp' ? 'Counter-based (HOTP)' : type, { check: false });
    r.field('Algorithm', algorithm, { check: false });
    r.field('Digits', Number.isNaN(digits) ? params.digits : digits, { check: false });
    if (type === 'hotp') r.field('Counter', data.counter ?? params.counter, { mono: true, check: false });
    else r.field('Period', Number.isNaN(data.period) ? params.period : `${data.period} s`, { check: false });
    r.field('Secret', group(data.secretB32 ?? params.secret ?? '', 4), { sensitive: true, mono: true, copy: true });
    for (const [k, v] of Object.entries(data.extra || {})) r.field(`Parameter ${k}`, v, { mono: true });

    if (data.secretB32) r.copy('Copy secret', data.secretB32, { sensitive: true });
    r.copy('Copy URI', uri, { sensitive: true });

    const who = [issuer, account].filter(Boolean).join(' — ') || 'unnamed account';
    return r.result({
      type: 'otp',
      title: 'Two-factor code setup',
      summary: `2FA ${type === 'hotp' ? 'HOTP' : type === 'totp' ? 'TOTP' : type} for ${who}`,
      data,
    });
  },
};

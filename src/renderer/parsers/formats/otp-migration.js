// Google Authenticator export `otpauth-migration://offline?data=…` (PAYLOADS.md §9.4):
// base64 protobuf `MigrationPayload`, decoded with a minimal wire-format reader
// (BigInt varints) into a list of accounts, each convertible to an otpauth:// URI.

import { createReport, hasPrefix, prep, pctDecode } from './util.js';
import { base64ToBytes, base32Encode } from './codecs.js';
import { buildOtpauthUri } from './otp.js';

const MAX_BYTES = 8 * 1024;
const MAX_ENTRIES = 100;

/** Thrown for malformed protobuf data. */
class ProtoError extends Error {}

/** Minimal protobuf wire-format reader. */
class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  get done() {
    return this.pos >= this.bytes.length;
  }

  varint() {
    let result = 0n;
    for (let i = 0; i < 10; i++) {
      if (this.pos >= this.bytes.length) throw new ProtoError('truncated');
      const b = this.bytes[this.pos++];
      result |= BigInt(b & 0x7f) << BigInt(7 * i);
      if (!(b & 0x80)) return result;
    }
    throw new ProtoError('varint longer than 10 bytes');
  }

  take(n) {
    if (n < 0 || this.pos + n > this.bytes.length) throw new ProtoError('truncated');
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** Reads one field: `{ field, wire, value }` (value: bigint for varints, bytes for length-delimited). */
  field() {
    const key = this.varint();
    const field = Number(key >> 3n);
    const wire = Number(key & 7n);
    if (field === 0) throw new ProtoError('invalid field number 0');
    switch (wire) {
      case 0: return { field, wire, value: this.varint() };
      case 1: return { field, wire, value: this.take(8) };
      case 2: {
        const len = this.varint();
        if (len > BigInt(this.bytes.length)) throw new ProtoError('truncated');
        return { field, wire, value: this.take(Number(len)) };
      }
      case 5: return { field, wire, value: this.take(4) };
      default: throw new ProtoError(`unsupported wire type ${wire}`);
    }
  }
}

const utf8 = new TextDecoder('utf-8', { fatal: false });

function expect(f, wire) {
  if (f.wire !== wire) throw new ProtoError(`field ${f.field} has wire type ${f.wire}, expected ${wire}`);
  return f.value;
}

function decodeOtpParameters(bytes) {
  const rd = new Reader(bytes);
  const p = { secret: new Uint8Array(0), name: '', issuer: '', algorithm: 0, digits: 0, type: 0, counter: 0n };
  while (!rd.done) {
    const f = rd.field();
    switch (f.field) {
      case 1: p.secret = expect(f, 2); break;
      case 2: p.name = utf8.decode(expect(f, 2)); break;
      case 3: p.issuer = utf8.decode(expect(f, 2)); break;
      case 4: p.algorithm = Number(BigInt.asIntN(32, expect(f, 0))); break;
      case 5: p.digits = Number(BigInt.asIntN(32, expect(f, 0))); break;
      case 6: p.type = Number(BigInt.asIntN(32, expect(f, 0))); break;
      case 7: p.counter = BigInt.asIntN(64, expect(f, 0)); break;
      default: break; // unknown field: skipped
    }
  }
  return p;
}

/**
 * Decodes a MigrationPayload.
 * @param {Uint8Array} bytes
 * @returns {{ otp: Array<object>, version: number, batchSize: number, batchIndex: number, batchId: number, truncatedList: boolean }}
 * @throws {ProtoError}
 */
export function decodeMigrationPayload(bytes) {
  const rd = new Reader(bytes);
  const out = { otp: [], version: 0, batchSize: 0, batchIndex: 0, batchId: 0, truncatedList: false };
  while (!rd.done) {
    const f = rd.field();
    switch (f.field) {
      case 1:
        if (out.otp.length >= MAX_ENTRIES) out.truncatedList = true;
        else out.otp.push(decodeOtpParameters(expect(f, 2)));
        break;
      case 2: out.version = Number(BigInt.asIntN(32, expect(f, 0))); break;
      case 3: out.batchSize = Number(BigInt.asIntN(32, expect(f, 0))); break;
      case 4: out.batchIndex = Number(BigInt.asIntN(32, expect(f, 0))); break;
      case 5: out.batchId = Number(BigInt.asIntN(32, expect(f, 0))); break;
      default: break;
    }
  }
  return out;
}

const ALGORITHMS = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5' };
const DIGITS = { 0: 6, 1: 6, 2: 8 };

/** Raw `data=` value from the query (not URLSearchParams: '+' must stay '+'). */
function extractData(uri) {
  const m = /[?&]data=([^&#]*)/i.exec(uri);
  if (!m) return null;
  return pctDecode(m[1]).value.replace(/ /g, '+');
}

/** Converts a decoded entry into a display-ready account. */
function toAccount(p, r, index) {
  const n = index + 1;
  const algorithm = ALGORITHMS[p.algorithm] ?? `unknown (${p.algorithm})`;
  const digits = DIGITS[p.digits] ?? null;
  const type = p.type === 1 ? 'hotp' : p.type === 2 || p.type === 0 ? 'totp' : `unknown (${p.type})`;
  const unspecified = [];
  if (p.algorithm === 0) unspecified.push('algorithm');
  if (p.digits === 0) unspecified.push('digits');
  if (p.type === 0) unspecified.push('type');
  if (unspecified.length) r.warn('info', `Account ${n}: ${unspecified.join(', ')} unspecified (defaults used)`);
  if (algorithm === 'MD5') r.warn('caution', `Account ${n}: MD5 is not supported by most apps; its code can't be computed here`);
  else if (!(p.algorithm in ALGORITHMS)) r.warn('caution', `Account ${n}: unknown algorithm ${p.algorithm}`);
  if (digits === null) r.warn('caution', `Account ${n}: unknown digit count ${p.digits}`);
  if (type.startsWith('unknown')) r.warn('caution', `Account ${n}: unknown OTP type ${p.type}`);
  if (!p.secret.length) r.warn('caution', `Account ${n}: empty secret`);
  else if (p.secret.length * 8 < 80) r.warn('caution', `Account ${n}: weak secret (${p.secret.length * 8} bits)`);

  // "Issuer:account" names: strip the issuer prefix when it equals the issuer.
  let account = p.name;
  let issuer = p.issuer;
  const colon = p.name.indexOf(':');
  if (colon >= 0) {
    const prefix = p.name.slice(0, colon);
    if (!issuer || prefix === issuer) {
      issuer = issuer || prefix;
      account = p.name.slice(colon + 1).replace(/^ +/, '');
    }
  }
  const counter = p.counter <= BigInt(Number.MAX_SAFE_INTEGER) && p.counter >= 0n ? Number(p.counter) : p.counter.toString();
  const secretB32 = base32Encode(p.secret);
  const acc = {
    issuer, name: p.name, account, type, algorithm, digits: digits ?? 6, secretB32,
    ...(type === 'hotp' ? { counter } : { period: 30 }),
  };
  const computable = ['SHA1', 'SHA256', 'SHA512'].includes(algorithm) && digits !== null
    && (type === 'totp' || type === 'hotp') && p.secret.length > 0;
  acc.codeComputable = computable;
  if (computable) {
    acc.otpParams = { secret: secretB32, algorithm, digits, ...(type === 'hotp' ? { counter } : { period: 30 }) };
  }
  acc.uri = type === 'totp' || type === 'hotp'
    ? buildOtpauthUri({ type, issuer, account, secretB32, algorithm: algorithm === 'MD5' ? 'MD5' : algorithm, digits: digits ?? 6, period: 30, counter })
    : null;
  return acc;
}

export const otpMigration = {
  id: 'otp-migration',
  label: 'authenticator export',
  detect(text) {
    return hasPrefix(prep(text), 'otpauth-migration://');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const uri = prep(text);
    const data = { format: 'otpauth-migration', accounts: [] };
    const b64 = extractData(uri);
    let payload = null;
    if (b64 === null || b64 === '') {
      r.warn('caution', 'Invalid authenticator export: the data parameter is missing');
    } else {
      const bytes = base64ToBytes(b64);
      if (!bytes) r.warn('caution', 'Invalid authenticator export: data is not base64');
      else if (bytes.length > MAX_BYTES) r.warn('caution', `Authenticator export is too large to read (${bytes.length} bytes)`);
      else {
        try {
          payload = decodeMigrationPayload(bytes);
        } catch (err) {
          if (!(err instanceof ProtoError)) throw err;
          r.warn('caution', `Invalid authenticator export: ${err.message}`);
          data.decodeError = err.message;
        }
      }
    }

    if (payload) {
      data.version = payload.version;
      data.batch = { size: payload.batchSize, index: payload.batchIndex, id: payload.batchId };
      data.accounts = payload.otp.map((p, i) => toAccount(p, r, i));
      if (payload.truncatedList) r.warn('caution', `Only the first ${MAX_ENTRIES} accounts are shown`);
      if (payload.batchSize > 1) r.warn('info', `Part ${payload.batchIndex + 1} of ${payload.batchSize} — scan every part to get all accounts`);
      if (!data.accounts.length) r.warn('caution', 'This export contains no accounts');
    }
    const n = data.accounts.length;
    if (n) {
      r.warn('danger', `This QR contains ${n} two-factor secret${n === 1 ? '' : 's'}. Anyone who sees it can take over ${n === 1 ? "that account's" : "those accounts'"} 2FA.`);
    }

    data.accounts.forEach((a, i) => {
      const p = `${i + 1}.`;
      r.field(`${p} ${a.issuer || 'Account'}`, a.account || '(no name)', { singleLine: true });
      const kind = `${a.type === 'hotp' ? `HOTP (counter ${a.counter})` : a.type.toUpperCase()} · ${a.algorithm} · ${a.digits} digits`;
      r.field(`${p} Details`, kind, { check: false });
      r.field(`${p} Secret`, a.secretB32.replace(/(.{4})(?=.)/g, '$1 '), { sensitive: true, mono: true, check: false });
      if (a.uri) r.copy(`Copy otpauth URI (${a.issuer || a.account || `account ${i + 1}`})`, a.uri, { sensitive: true });
    });
    r.copy('Copy export URI', uri, { sensitive: true });

    return r.result({
      type: 'otp-migration',
      title: `Authenticator export (${n} account${n === 1 ? '' : 's'})`,
      summary: n
        ? `Authenticator export: ${data.accounts.slice(0, 3).map((a) => a.issuer || a.account).join(', ')}${n > 3 ? ` and ${n - 3} more` : ''}`
        : 'Authenticator export (unreadable)',
      data,
    });
  },
};

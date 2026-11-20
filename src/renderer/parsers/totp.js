// One-time password generation (RFC 4226 HOTP, RFC 6238 TOTP) with WebCrypto HMAC.
// Works in the sandboxed renderer and in Node (globalThis.crypto.subtle). PAYLOADS.md §9.2.

import { base32Decode } from './formats/codecs.js';

const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

/**
 * Time step for TOTP.
 * @param {number} period seconds (default 30)
 * @param {number} [nowMs]
 * @returns {{ counter: number, secondsRemaining: number }}
 */
export function otpTimeStep(period = 30, nowMs = Date.now()) {
  const p = Number(period) > 0 ? Number(period) : 30;
  const seconds = Math.floor(nowMs / 1000);
  return { counter: Math.floor(seconds / p), secondsRemaining: p - (seconds % p) };
}

/**
 * Computes an OTP code.
 * @param {{ secret: string|Uint8Array, algorithm?: 'SHA1'|'SHA256'|'SHA512', digits?: number,
 *   period?: number, counter?: number|bigint|string }} params
 *   `secret`: base32 string (spaces/padding/lowercase tolerated) or raw key bytes.
 *   With `counter` → HOTP for that counter; otherwise TOTP for `nowMs`.
 * @param {number} [nowMs] Unix time in milliseconds (TOTP only)
 * @returns {Promise<string>} zero-padded code
 * @throws {Error} for unsupported algorithms (e.g. MD5), invalid secrets or digits
 */
export async function generateOtp({ secret, algorithm = 'SHA1', digits = 6, period = 30, counter } = {}, nowMs = Date.now()) {
  const hash = HASHES[String(algorithm).toUpperCase().replace('-', '')];
  if (!hash) throw new Error(`Unsupported OTP algorithm: ${algorithm}`);
  const d = Number(digits);
  if (!Number.isInteger(d) || d < 1 || d > 10) throw new Error(`Unsupported digit count: ${digits}`);

  let key;
  if (secret instanceof Uint8Array) key = secret;
  else {
    const dec = base32Decode(String(secret ?? ''));
    if (dec.invalid.length) throw new Error('Invalid base32 secret');
    key = dec.bytes;
  }
  if (!key.length) throw new Error('Empty secret');

  const c = counter !== undefined && counter !== null
    ? BigInt(counter)
    : BigInt(otpTimeStep(period, nowMs).counter);
  if (c < 0n || c > 0xffffffffffffffffn) throw new Error('Counter out of range');
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, c);

  const subtle = globalThis.crypto.subtle;
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  const mac = new Uint8Array(await subtle.sign('HMAC', k, msg));
  const o = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[o] & 0x7f) * 2 ** 24) + (mac[o + 1] << 16) + (mac[o + 2] << 8) + mac[o + 3];
  return String(bin % 10 ** d).padStart(d, '0');
}

// Binary-to-text codecs used by the format parsers: base32 (RFC 4648), base64,
// base45 (RFC 9285), base58/base58check, bech32/bech32m (BIP-173/350), hex, CRCs.
// All functions are pure and synchronous; malformed input yields null, never throws.

import { sha256 } from './hash.js';

// ---------------------------------------------------------------------------
// hex / UTF-8
// ---------------------------------------------------------------------------

export function bytesToHex(bytes, sep = '') {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(sep);
}

export function hexToBytes(hex) {
  if (!/^(?:[0-9A-Fa-f]{2})*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** UTF-8 decode; with `fatal` returns null for invalid sequences. */
export function utf8Decode(bytes, fatal = false) {
  try {
    return new TextDecoder('utf-8', { fatal }).decode(bytes);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// base32 (RFC 4648, no padding on output)
// ---------------------------------------------------------------------------

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Lenient base32 decode for OTP secrets: spaces and `=` ignored, case-insensitive.
 * @returns {{ bytes: Uint8Array, normalized: string, invalid: string[], leftoverNonZero: boolean }}
 *   `invalid` lists characters outside the alphabet (bytes then cover only valid ones).
 */
export function base32Decode(input) {
  const normalized = String(input).replace(/[\s=]/g, '').toUpperCase();
  const invalid = [];
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of normalized) {
    const v = B32.indexOf(ch);
    if (v < 0) {
      if (!invalid.includes(ch)) invalid.push(ch);
      continue;
    }
    buffer = ((buffer << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  const leftoverNonZero = bits > 0 && (buffer & ((1 << bits) - 1)) !== 0;
  return { bytes: new Uint8Array(out), normalized, invalid, leftoverNonZero };
}

export function base32Encode(bytes) {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = ((buffer << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) out += B32[(buffer << (5 - bits)) & 31];
  return out;
}

// ---------------------------------------------------------------------------
// base64 / base64url
// ---------------------------------------------------------------------------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

/**
 * Decodes standard or URL-safe base64; whitespace ignored, padding optional.
 * @returns {Uint8Array|null}
 */
export function base64ToBytes(input) {
  const s = String(input).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (/[^A-Za-z0-9+/]/.test(s) || s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let o = 0;
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    buffer = (buffer << 6) | B64_INDEX.get(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >>> bits) & 0xff;
    }
    buffer &= 0xff;
  }
  return out.subarray(0, o);
}

export function bytesToBase64(bytes, { url = false, pad = true } = {}) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >>> 18] + B64[(n >>> 12) & 63] + B64[(n >>> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64[n >>> 18] + B64[(n >>> 12) & 63] + (pad ? '==' : '');
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[n >>> 18] + B64[(n >>> 12) & 63] + B64[(n >>> 6) & 63] + (pad ? '=' : '');
  }
  return url ? out.replace(/\+/g, '-').replace(/\//g, '_') : out;
}

// ---------------------------------------------------------------------------
// base45 (RFC 9285)
// ---------------------------------------------------------------------------

const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

/** @returns {Uint8Array|null} */
export function base45Decode(input) {
  const s = String(input);
  if (s.length % 3 === 1) return null;
  const out = [];
  for (let i = 0; i < s.length; i += 3) {
    const chunk = s.slice(i, i + 3);
    const v = [...chunk].map((c) => B45.indexOf(c));
    if (v.some((x) => x < 0)) return null;
    if (chunk.length === 3) {
      const n = v[0] + v[1] * 45 + v[2] * 45 * 45;
      if (n > 0xffff) return null;
      out.push(n >> 8, n & 0xff);
    } else {
      const n = v[0] + v[1] * 45;
      if (n > 0xff) return null;
      out.push(n);
    }
  }
  return new Uint8Array(out);
}

// ---------------------------------------------------------------------------
// base58 / base58check (Bitcoin alphabet)
// ---------------------------------------------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** @returns {Uint8Array|null} */
export function base58Decode(input) {
  const s = String(input);
  if (!s || s.length > 200) return null;
  const bytes = [0];
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  const body = bytes.reverse();
  while (body.length > 1 && body[0] === 0) body.shift();
  if (body.length === 1 && body[0] === 0) body.length = 0;
  return new Uint8Array([...new Array(zeros).fill(0), ...body]);
}

/**
 * Base58check: last 4 bytes = first 4 of SHA-256(SHA-256(payload)).
 * @returns {{ valid: boolean, version: number, payload: Uint8Array }|null} null if not base58.
 */
export function base58CheckDecode(input) {
  const raw = base58Decode(input);
  if (!raw || raw.length < 5) return null;
  const payload = raw.subarray(0, raw.length - 4);
  const check = sha256(sha256(payload));
  const valid = check.subarray(0, 4).every((b, i) => b === raw[raw.length - 4 + i]);
  return { valid, version: payload[0], payload };
}

// ---------------------------------------------------------------------------
// bech32 / bech32m (BIP-173, BIP-350)
// ---------------------------------------------------------------------------

const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;

function polymod(values) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= G[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

/**
 * Decodes a bech32/bech32m string.
 * @param {string} str
 * @param {{ limit?: number }} [opts] max length (90 for addresses; Infinity for BOLT11/LNURL)
 * @returns {{ hrp: string, data: number[], encoding: 'bech32'|'bech32m'|null, mixedCase: boolean }|null}
 *   null when not bech32-shaped; `encoding` null when the checksum fails. `data` excludes the checksum.
 */
export function bech32Decode(str, { limit = 90 } = {}) {
  const s = String(str);
  if (s.length > limit || s.length < 8) return null;
  if ([...s].some((c) => c.charCodeAt(0) < 33 || c.charCodeAt(0) > 126)) return null;
  const mixedCase = s !== s.toLowerCase() && s !== s.toUpperCase();
  const lower = s.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) return null;
  const hrp = lower.slice(0, pos);
  const data = [];
  for (const c of lower.slice(pos + 1)) {
    const v = BECH32.indexOf(c);
    if (v < 0) return null;
    data.push(v);
  }
  const pm = polymod([...hrpExpand(hrp), ...data]);
  const encoding = pm === 1 ? 'bech32' : pm === BECH32M_CONST ? 'bech32m' : null;
  return { hrp, data: data.slice(0, -6), encoding: mixedCase ? null : encoding, mixedCase };
}

/** Encodes 5-bit `data` with the given HRP (used by tests and LNURL helpers). */
export function bech32Encode(hrp, data, encoding = 'bech32') {
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const pm = polymod(values) ^ (encoding === 'bech32m' ? BECH32M_CONST : 1);
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((pm >>> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map((v) => BECH32[v]).join('');
}

/** Regroups bits (e.g. 5-bit words → bytes). Returns null on invalid padding. */
export function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) return null;
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
    acc &= (1 << bits) - 1;
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null;
  }
  return out;
}

/**
 * Validates a SegWit address (BIP-173/350).
 * @returns {{ valid: boolean, hrp: string, version: number|null, programLength: number|null, reason?: string }|null}
 *   null when the string is not bech32-shaped at all.
 */
export function decodeSegwit(addr) {
  const d = bech32Decode(addr);
  if (!d) return null;
  const res = { valid: false, hrp: d.hrp, version: null, programLength: null };
  if (d.mixedCase) return { ...res, reason: 'mixed upper/lower case' };
  if (!d.encoding) return { ...res, reason: 'checksum mismatch' };
  if (!d.data.length) return { ...res, reason: 'empty data' };
  const version = d.data[0];
  const program = convertBits(d.data.slice(1), 5, 8, false);
  res.version = version;
  if (!program) return { ...res, reason: 'invalid padding' };
  res.programLength = program.length;
  if (version > 16 || program.length < 2 || program.length > 40) return { ...res, reason: 'invalid program' };
  if (version === 0 && program.length !== 20 && program.length !== 32) return { ...res, reason: 'invalid v0 program length' };
  if ((version === 0) !== (d.encoding === 'bech32')) return { ...res, reason: 'wrong checksum variant' };
  return { ...res, valid: true };
}

// ---------------------------------------------------------------------------
// CRCs
// ---------------------------------------------------------------------------

/** CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) — EMVCo merchant QR. */
export function crc16ccitt(bytes) {
  let c = 0xffff;
  for (const b of bytes) {
    c ^= b << 8;
    for (let i = 0; i < 8; i++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) & 0xffff : (c << 1) & 0xffff;
  }
  return c;
}

let CRC32_TABLE = null;
/** CRC-32 (IEEE 802.3) — Czech SPD. */
export function crc32(bytes) {
  if (!CRC32_TABLE) {
    CRC32_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC32_TABLE[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const b of bytes) c = CRC32_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

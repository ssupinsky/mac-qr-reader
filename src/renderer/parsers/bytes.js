// Byte payload helpers (PAYLOADS.md §11.9): base64/hex conversion, the text
// decision for QR byte-mode payloads (UTF-8 → Shift_JIS → ISO-8859-1 → binary),
// magic-byte guesses and hex dumps.

/** Decodes standard base64 (whitespace tolerated) to bytes; null when invalid. */
export function base64ToBytes(b64) {
  if (typeof b64 !== 'string') return null;
  try {
    const bin = atob(b64.replace(/\s+/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Bytes → standard base64. */
export function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/** Bytes → lowercase hex, optionally separated. */
export function bytesToHex(bytes, sep = '') {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(sep);
}

function tryDecode(label, bytes) {
  try {
    return new TextDecoder(label, { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** ISO-8859-1 decoding (byte n → U+00nn; never fails, unlike the WHATWG "latin1" label = windows-1252). */
export function latin1Decode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return s;
}

const RE_KANA_KANJI = /[\p{scx=Hiragana}\p{scx=Katakana}\p{scx=Han}]/u;

/**
 * Text decision for payload bytes (§11.9 steps 2–4; ECI headers are not available
 * to the renderer, so step 1 does not apply).
 * @param {Uint8Array} bytes
 * @returns {{ kind: 'text', encoding: 'utf-8'|'shift_jis'|'iso-8859-1', text: string }
 *   | { kind: 'binary', reason: string }}
 */
export function decodePayloadBytes(bytes) {
  const utf8 = tryDecode('utf-8', bytes);
  if (utf8 !== null) {
    // A leading UTF-8 BOM is kept in the text (TextDecoder strips it by default).
    const bom = bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
    const text = bom ? `\uFEFF${utf8}` : utf8;
    if (!binaryLike(text)) return { kind: 'text', encoding: 'utf-8', text };
    return { kind: 'binary', reason: 'control characters' };
  }
  const sjis = tryDecode('shift_jis', bytes);
  if (sjis !== null && RE_KANA_KANJI.test(sjis) && !binaryLike(sjis)) {
    return { kind: 'text', encoding: 'shift_jis', text: sjis };
  }
  const latin1 = latin1Decode(bytes);
  if (binaryLike(latin1)) return { kind: 'binary', reason: 'not valid text in any common encoding' };
  return { kind: 'text', encoding: 'iso-8859-1', text: latin1 };
}

/** NUL anywhere, or > 10 % C0 controls other than TAB/LF/CR → binary (§11.9 step 4). */
function binaryLike(text) {
  if (!text.length) return false;
  let controls = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0) return true;
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) controls++;
  }
  return controls / text.length > 0.1;
}

/** Magic-byte file type guess (§11.8). */
export function guessMagic(bytes) {
  const b = bytes;
  const starts = (...sig) => sig.every((v, i) => b[i] === v);
  if (b.length >= 2 && starts(0x1f, 0x8b)) return 'gzip';
  if (b.length >= 2 && b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(b[1])) return 'zlib';
  if (b.length >= 4 && starts(0x89, 0x50, 0x4e, 0x47)) return 'PNG image';
  if (b.length >= 3 && starts(0xff, 0xd8, 0xff)) return 'JPEG image';
  if (b.length >= 4 && starts(0x25, 0x50, 0x44, 0x46)) return 'PDF document';
  if (b.length >= 4 && starts(0x50, 0x4b, 0x03, 0x04)) return 'ZIP archive';
  if (b.length >= 4 && starts(0x47, 0x49, 0x46, 0x38)) return 'GIF image';
  if (b.length >= 2 && (starts(0xd2, 0x84) || b[0] === 0x84)) return 'COSE/CBOR';
  if (b.length >= 2 && b[0] === 0x0a && b[1] > 0 && b[1] < b.length) return 'possibly protobuf';
  return null;
}

/**
 * Classic hex dump: `00000000  48 65 6c 6c 6f …  |Hello…|`, 16 bytes per row.
 * @param {Uint8Array} bytes
 * @param {number} [max=4096] maximum bytes shown
 */
export function hexDump(bytes, max = 4096) {
  const rows = [];
  const n = Math.min(bytes.length, max);
  for (let off = 0; off < n; off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, n));
    const hexPart = Array.from(row, (x) => x.toString(16).padStart(2, '0'));
    const left = hexPart.slice(0, 8).join(' ');
    const right = hexPart.slice(8).join(' ');
    const ascii = Array.from(row, (x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : '.')).join('');
    rows.push(`${off.toString(16).padStart(8, '0')}  ${left.padEnd(23)}  ${right.padEnd(23)}  |${ascii}|`);
  }
  if (bytes.length > max) rows.push(`… ${bytes.length - max} more bytes`);
  return rows.join('\n');
}

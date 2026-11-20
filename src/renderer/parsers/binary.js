// Binary payloads (PAYLOADS.md §11.9): size, magic-type guess, hex dump; copy as
// hex/base64 and save as .bin.

import { bytesToBase64, bytesToHex, guessMagic, hexDump } from './bytes.js';

/**
 * @param {Uint8Array} bytes
 * @param {{ bytesKind?: string|null }} [opts] `raw` = symbol codewords, not the payload.
 */
export function analyzeBinary(bytes, opts = {}) {
  const raw = opts.bytesKind === 'raw';
  const magic = raw ? null : guessMagic(bytes);
  const dump = hexDump(bytes);
  const base64 = bytesToBase64(bytes);
  const warnings = [];
  if (raw) {
    warnings.push({ level: 'info', message: 'The system decoder returned no text; these are the raw symbol codewords, not the decoded content' });
  }
  const fields = [
    { label: 'Size', value: `${bytes.length} byte${bytes.length === 1 ? '' : 's'}` },
    ...(magic ? [{ label: 'Looks like', value: magic }] : []),
    { label: 'Hex', value: dump, mono: true },
  ];
  return {
    type: 'binary',
    title: 'Binary data',
    summary: `${bytes.length} bytes of binary data${magic ? ` (looks like ${magic})` : ''}`,
    fields,
    warnings,
    actions: [
      { kind: 'copy', label: 'Copy hex', value: bytesToHex(bytes) },
      { kind: 'copy', label: 'Copy base64', value: base64 },
      { kind: 'save', label: 'Save as…', value: base64, saveAs: { suggestedName: 'payload.bin', kind: 'bin' } },
    ],
    data: { format: raw ? 'binary-codewords' : 'binary', size: bytes.length, magic, hexDump: dump, base64 },
  };
}

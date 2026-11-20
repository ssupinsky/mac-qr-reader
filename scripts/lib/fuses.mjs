// Minimal Electron fuse reader/flipper (replaces @electron/fuses, see docs/SECURITY.md §6.2).
// Layout (from @electron/fuses src/index.ts + src/constants.ts): the ASCII sentinel
// "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" is followed by one version byte (1 = V1, numeric), one
// length byte, then `length` state bytes: '0' (0x30) disabled, '1' (0x31) enabled,
// 'r' (0x72) removed. Produces byte-identical output to @electron/fuses for the same config.
import fs from 'node:fs';
import path from 'node:path';

const SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'ascii');
const DISABLE = 0x30, ENABLE = 0x31, REMOVED = 0x72;

/** Fuse indices of wire version 1 (FuseV1Options). */
export const FUSES = Object.freeze({
  RunAsNode: 0,
  EnableCookieEncryption: 1,
  EnableNodeOptionsEnvironmentVariable: 2,
  EnableNodeCliInspectArguments: 3,
  EnableEmbeddedAsarIntegrityValidation: 4,
  OnlyLoadAppFromAsar: 5,
  LoadBrowserProcessSpecificV8Snapshot: 6,
  GrantFileProtocolExtraPrivileges: 7,
  WasmTrapHandlers: 8,
});

export const fuseFile = (app) =>
  path.join(app, 'Contents/Frameworks/Electron Framework.framework/Electron Framework');

function locate(buf) {
  const at = buf.indexOf(SENTINEL);
  if (at < 0) throw new Error('fuse sentinel not found');
  if (buf.indexOf(SENTINEL, at + 1) >= 0) throw new Error('fuse sentinel found more than once (universal binary?)');
  const pos = at + SENTINEL.length;
  const version = buf[pos], length = buf[pos + 1];
  if (version !== 1) throw new Error(`unsupported fuse wire version ${version}`);
  if (length < Object.keys(FUSES).length) throw new Error(`fuse wire too short (${length})`);
  return { wire: pos + 2, length };
}

/** → wire string, e.g. "010011001" ('r' marks removed fuses). */
export function readFuses(app) {
  const buf = fs.readFileSync(fuseFile(app));
  const { wire, length } = locate(buf);
  return buf.subarray(wire, wire + length).toString('latin1');
}

/** config: { FuseName: boolean }. Writes in place, reads back and asserts. → new wire string. */
export function flipFuses(app, config) {
  const file = fuseFile(app);
  const buf = fs.readFileSync(file);
  const { wire, length } = locate(buf);
  const bytes = Buffer.from(buf.subarray(wire, wire + length));
  for (const [name, on] of Object.entries(config)) {
    const i = FUSES[name];
    if (i === undefined || typeof on !== 'boolean') throw new Error(`bad fuse config: ${name}`);
    if (bytes[i] === REMOVED) throw new Error(`fuse ${name} is marked removed in this Electron`);
    bytes[i] = on ? ENABLE : DISABLE;
  }
  const fd = fs.openSync(file, 'r+');
  try { fs.writeSync(fd, bytes, 0, bytes.length, wire); } finally { fs.closeSync(fd); }
  const back = readFuses(app);
  if (back !== bytes.toString('latin1')) throw new Error(`fuse read-back mismatch: ${back}`);
  return back;
}

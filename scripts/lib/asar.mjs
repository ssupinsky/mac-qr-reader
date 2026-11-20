// Minimal ASAR packer/verifier with embedded per-file integrity (replaces @electron/asar,
// see docs/SECURITY.md §6.2). Format (Chromium Pickle, as written by @electron/asar):
//   UInt32LE 4 | UInt32LE headerPickleSize                      (size pickle, 8 bytes)
//   UInt32LE payloadSize | UInt32LE jsonLen | JSON | pad to 4   (header pickle)
//   file bodies, concatenated in header order (offsets are decimal strings)
// Electron's Info.plist ElectronAsarIntegrity hash = SHA-256 of the header JSON string.
import fs from 'node:fs';
import crypto from 'node:crypto';

const BLOCK = 4 * 1024 * 1024;
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

function integrity(data) {
  const blocks = [];
  for (let o = 0; o < data.length; o += BLOCK) blocks.push(sha256(data.subarray(o, o + BLOCK)));
  if (data.length === 0) blocks.push(sha256(data));
  return { algorithm: 'SHA256', hash: sha256(data), blockSize: BLOCK, blocks };
}

/** entries: [{ name: 'src/main/main.js', data: Buffer, executable?: boolean }] → { headerHash, size } */
export function packAsar(outPath, entries) {
  const root = { files: {} };
  const bodies = [];
  let offset = 0;
  for (const e of [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    const parts = e.name.split('/');
    if (parts.some((p) => !p || p === '.' || p === '..')) throw new Error(`bad asar path: ${e.name}`);
    let dir = root;
    for (const p of parts.slice(0, -1)) dir = (dir.files[p] ??= { files: {} });
    const leaf = parts.at(-1);
    if (dir.files[leaf]) throw new Error(`duplicate asar path: ${e.name}`);
    const node = { size: e.data.length, offset: String(offset) };
    if (e.executable) node.executable = true;
    node.integrity = integrity(e.data);
    dir.files[leaf] = node;
    bodies.push(e.data);
    offset += e.data.length;
  }
  const json = JSON.stringify(root);
  const jsonLen = Buffer.byteLength(json);
  const padded = (jsonLen + 3) & ~3;
  const header = Buffer.alloc(8 + padded);
  header.writeUInt32LE(4 + padded, 0);
  header.writeUInt32LE(jsonLen, 4);
  header.write(json, 8, 'utf8');
  const size = Buffer.alloc(8);
  size.writeUInt32LE(4, 0);
  size.writeUInt32LE(header.length, 4);
  const out = Buffer.concat([size, header, ...bodies]);
  fs.writeFileSync(outPath, out);
  return { headerHash: sha256(json), size: out.length };
}

/** Reads the archive and checks every file against its embedded integrity.
 *  → { headerHash, files: number, problems: string[] } */
export function verifyAsar(asarPath) {
  const buf = fs.readFileSync(asarPath);
  const problems = [];
  if (buf.length < 16 || buf.readUInt32LE(0) !== 4) throw new Error('not an asar archive');
  const headerSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  if (16 + jsonLen > 8 + headerSize || 8 + headerSize > buf.length) throw new Error('corrupt asar header');
  const json = buf.subarray(16, 16 + jsonLen).toString('utf8');
  const base = 8 + headerSize;
  let files = 0, end = base;
  const walk = (dir, prefix) => {
    for (const [name, node] of Object.entries(dir.files)) {
      const p = prefix + name;
      if (node.files) { walk(node, p + '/'); continue; }
      if (node.unpacked || node.link) { problems.push(`${p}: unpacked/link entries are not allowed`); continue; }
      files++;
      const start = base + Number(node.offset);
      const data = buf.subarray(start, start + node.size);
      end = Math.max(end, start + node.size);
      const want = node.integrity;
      if (data.length !== node.size) problems.push(`${p}: truncated`);
      else if (!want || want.algorithm !== 'SHA256') problems.push(`${p}: missing integrity`);
      else {
        const got = integrity(data);
        if (got.hash !== want.hash || got.blockSize !== want.blockSize || got.blocks.join() !== want.blocks.join()) {
          problems.push(`${p}: content hash mismatch`);
        }
      }
    }
  };
  walk(JSON.parse(json), '');
  if (end !== buf.length) problems.push(`trailing/missing bytes (${buf.length - end})`);
  return { headerHash: sha256(json), files, problems };
}

/** Returns the bytes of one file inside the archive (no integrity check; use verifyAsar). */
export function readAsarFile(asarPath, name) {
  const buf = fs.readFileSync(asarPath);
  const headerSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  let node = JSON.parse(buf.subarray(16, 16 + jsonLen).toString('utf8'));
  for (const part of name.split('/')) {
    node = node.files?.[part];
    if (!node) throw new Error(`${name} not in ${asarPath}`);
  }
  const start = 8 + headerSize + Number(node.offset);
  return buf.subarray(start, start + node.size);
}

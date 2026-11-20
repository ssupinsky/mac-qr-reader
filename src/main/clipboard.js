'use strict';
// System clipboard: explicit paste (image / Finder file URLs / text), copy (plain or
// sensitive with nspasteboard.org markers + auto-clear), and auto-scan on window focus.
// Electron 45 clipboard API is async/W3C-style (docs/SECURITY.md §3.1, §8).

const crypto = require('node:crypto');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const { app, clipboard, ClipboardItem } = require('electron');
const decoder = require('./decoder');
const files = require('./files');

const OS = (uti) => `electron application/osclipboard;format="${uti}"`;
const MARK = OS('local.qr-reader.sensitive');
const FILENAMES = OS('NSFilenamesPboardType');
const MAX_TEXT = 1024 * 1024;
const MAX_COPY = 1024 * 1024;
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.tif', '.tiff', '.bmp', '.webp', '.ico', '.heic', '.heif', '.avif', '.pdf']);

const DEFAULT_CLEAR_MS = 60_000;
function sensitiveClearMs() {
  // Test-only override, honoured only in the unpackaged dev build.
  if (!app.isPackaged && /^\d{2,6}$/.test(process.env.QR_TEST_SENSITIVE_CLEAR_MS || '')) {
    return Number(process.env.QR_TEST_SENSITIVE_CLEAR_MS);
  }
  return DEFAULT_CLEAR_MS;
}

// ---------------------------------------------------------------- reading
const XML_ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
function decodeXml(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    }
    return XML_ENT[e.toLowerCase()];
  });
}

async function blobText(item, type) {
  try {
    const b = await item.getType(type);
    return b && typeof b.text === 'function' ? await b.text() : null;
  } catch { return null; }
}

/** File paths copied in Finder (all of them; text/uri-list only carries the first). */
async function filePathsFrom(items) {
  const out = [];
  for (const it of items) {
    const types = it.types.map((t) => t.toLowerCase());
    if (types.includes(FILENAMES.toLowerCase())) {
      const plist = await blobText(it, it.types[types.indexOf(FILENAMES.toLowerCase())]);
      if (plist) for (const m of plist.matchAll(/<string>([^<]*)<\/string>/g)) out.push(decodeXml(m[1]));
    }
    if (!out.length && types.includes('text/uri-list')) {
      const list = await blobText(it, 'text/uri-list');
      for (const line of (list || '').split(/\r?\n/)) {
        if (line.startsWith('file://')) { try { out.push(fileURLToPath(line)); } catch { /* skip */ } }
      }
    }
  }
  return [...new Set(out.filter((p) => path.isAbsolute(p)))];
}

/** First image on the clipboard as bytes: image/png, else any image/* or TIFF flavour. */
async function imageFrom(items) {
  for (const it of items) {
    const types = it.types;
    const pick = types.find((t) => t === 'image/png')
      || types.find((t) => t.startsWith('image/'))
      || types.find((t) => /tiff/i.test(t) && t.startsWith('electron application/osclipboard'));
    if (!pick) continue;
    try {
      const blob = await it.getType(pick);
      if (blob.size > decoder.MAX_INPUT_BYTES) return { tooLarge: true };
      return { bytes: new Uint8Array(await blob.arrayBuffer()) };
    } catch { /* try next item */ }
  }
  return null;
}

const sha = (u8) => crypto.createHash('sha256').update(u8).digest('hex');
let lastSignature = null; // hash of the last clipboard image/file list we scanned (memory only)

async function fileSignature(paths) {
  const fs = require('node:fs');
  const parts = await Promise.all(paths.map(async (p) => {
    try { const s = await fs.promises.stat(p); return `${p}\0${s.size}\0${s.mtimeMs}`; } catch { return p; }
  }));
  return sha(Buffer.from(parts.join('\n')));
}

/** Explicit, user-initiated paste (menu / Cmd+V fallback). Resolves ScanResult[]. */
/**
 * clipboard.read(), retried briefly when file URLs are present but macOS has not yet
 * synthesised NSFilenamesPboardType (the only flavour listing ALL copied files; without it
 * we'd see just the first file). Observed right after another process wrote file URLs.
 */
async function readItems() {
  let items = [];
  for (let attempt = 0; attempt < 4; attempt++) {
    try { items = await clipboard.read(); } catch { items = []; }
    const types = items.flatMap((it) => it.types.map((t) => t.toLowerCase()));
    if (!types.includes('text/uri-list') || types.includes(FILENAMES.toLowerCase())) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  return items;
}

async function pasteFromClipboard() {
  const items = await readItems();
  const paths = await filePathsFrom(items);
  if (paths.length) {
    lastSignature = await fileSignature(paths);
    return files.scanPaths(paths, 'paste');
  }
  const img = await imageFrom(items);
  if (img?.tooLarge) return [decoder.errorResult({ kind: 'paste', name: 'Clipboard image' }, 'too_large', 'The clipboard image is too large.')];
  if (img) {
    lastSignature = sha(img.bytes);
    return [await decoder.decode(img.bytes, { kind: 'paste', name: 'Clipboard image' })];
  }
  for (const it of items) {
    if (!it.types.includes('text/plain')) continue;
    const text = await blobText(it, 'text/plain');
    if (text) {
      return [{
        id: decoder.newId(), source: { kind: 'text', name: 'Clipboard text' }, ok: true, codes: [],
        text: text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text,
      }];
    }
  }
  return [decoder.errorResult({ kind: 'paste' }, 'clipboard_empty', 'The clipboard contains no image, file or text.')];
}

/**
 * Auto-scan on window focus. Probes type metadata first (has()), never reads text, skips
 * unchanged content, only considers image-like files. Resolves ScanResult[] to push, or
 * null when there is nothing new with at least one code.
 */
let autoBusy = false;
async function autoScan() {
  if (autoBusy) return null;
  autoBusy = true;
  try {
    const [hasImage, hasFiles] = await Promise.all([clipboard.has('image/png'), clipboard.has('text/uri-list')]);
    if (!hasImage && !hasFiles) return null;
    if (await clipboard.has(MARK)) return null; // our own sensitive copy
    const items = await readItems();
    let results;
    if (hasFiles) {
      const paths = (await filePathsFrom(items)).filter((p) => IMAGE_EXT.has(path.extname(p).toLowerCase()));
      if (!paths.length) return null;
      const sig = await fileSignature(paths);
      if (sig === lastSignature) return null;
      lastSignature = sig;
      results = await files.scanPaths(paths, 'clipboard-auto');
    } else {
      const img = await imageFrom(items);
      if (!img || img.tooLarge) return null;
      const sig = sha(img.bytes);
      if (sig === lastSignature) return null;
      lastSignature = sig;
      results = [await decoder.decode(img.bytes, { kind: 'clipboard-auto', name: 'Clipboard image' })];
    }
    return results.some((r) => r.ok && r.codes.length) ? results : null;
  } catch {
    return null;
  } finally {
    autoBusy = false;
  }
}

/** Marks bytes as already seen (e.g. renderer pasted the same image itself). */
function noteSeenImage(bytes) {
  try { lastSignature = sha(bytes); } catch { /* ignore */ }
}

// ---------------------------------------------------------------- writing
let clearTimer = null;
let sensitivePending = false; // we wrote a sensitive copy that may still be on the clipboard

async function copyText(text, { sensitive = false } = {}) {
  if (typeof text !== 'string' || text.length > MAX_COPY) throw new Error('invalid text');
  clearTimeout(clearTimer);
  clearTimer = null;
  if (!sensitive) {
    sensitivePending = false;
    await clipboard.writeText(text);
    return;
  }
  await clipboard.write([new ClipboardItem({
    'text/plain': text,
    [OS('org.nspasteboard.ConcealedType')]: '',
    [OS('org.nspasteboard.TransientType')]: '',
    [OS('org.nspasteboard.AutoGeneratedType')]: '',
    [MARK]: '',
  })]);
  sensitivePending = true;
  clearTimer = setTimeout(() => { clearTimer = null; clearSensitive(); }, sensitiveClearMs());
  clearTimer.unref?.();
}

/** Clears the clipboard only if it still holds our sensitive copy (checks the marker, never the content). */
async function clearSensitive() {
  sensitivePending = false;
  try {
    if (await clipboard.has(MARK)) { clipboard.clear(); return true; }
  } catch { /* ignore */ }
  return false;
}

const hasPendingSensitive = () => sensitivePending;

module.exports = { hasPendingSensitive, pasteFromClipboard, autoScan, copyText, clearSensitive, noteSeenImage, MARK };

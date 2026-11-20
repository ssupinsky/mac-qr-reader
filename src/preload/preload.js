'use strict';
// Sandboxed preload: exposes exactly the `window.qr` API (docs/ARCHITECTURE.md
// "IPC contract"). No ipcRenderer, no event objects, no Node globals reach the page.
// Electron 45 sandboxed preloads have no Buffer/events/timers/url — don't use them.

const { contextBridge, ipcRenderer } = require('electron');

const MAX_BYTES = 64 * 1024 * 1024;

/** Copies the caller's bytes into a fresh, exactly-sized Uint8Array (never a view onto a larger buffer). */
function copyBytes(bytes) {
  if (bytes instanceof ArrayBuffer) bytes = new Uint8Array(bytes);
  if (!(bytes instanceof Uint8Array)) throw new TypeError('decodeImage: bytes must be a Uint8Array');
  if (bytes.byteLength > MAX_BYTES) throw new RangeError('decodeImage: file is larger than 64 MiB');
  return bytes.slice();
}

function plainMeta(meta) {
  const m = meta && typeof meta === 'object' ? meta : {};
  const out = { source: m.source === 'paste' ? 'paste' : 'drop' };
  if (typeof m.name === 'string') out.name = m.name.slice(0, 1024);
  return out;
}

function subscribe(channel, cb) {
  if (typeof cb !== 'function') throw new TypeError('callback must be a function');
  const h = (_e, payload) => { cb(payload); };
  ipcRenderer.on(channel, h);
  return () => { ipcRenderer.removeListener(channel, h); };
}

contextBridge.exposeInMainWorld('qr', Object.freeze({
  decodeImage: (bytes, meta) => ipcRenderer.invoke('qr:decode-image', copyBytes(bytes), plainMeta(meta)),
  pasteFromClipboard: () => ipcRenderer.invoke('qr:paste-from-clipboard'),
  openFiles: () => ipcRenderer.invoke('qr:open-files'),
  copyText: (text, opts) => ipcRenderer.invoke('qr:copy-text', String(text),
    { sensitive: !!(opts && opts.sensitive) }),
  openExternal: (url) => ipcRenderer.invoke('qr:open-external', String(url)),
  saveText: (opts) => {
    const o = opts && typeof opts === 'object' ? opts : {};
    const out = { kind: String(o.kind), suggestedName: typeof o.suggestedName === 'string' ? o.suggestedName : undefined };
    if (typeof o.text === 'string') out.text = o.text;
    if (typeof o.bytesBase64 === 'string') out.bytesBase64 = o.bytesBase64;
    return ipcRenderer.invoke('qr:save-text', out);
  },
  onScanResults: (cb) => subscribe('qr:scan-results', cb),
  onCommand: (cb) => subscribe('qr:command', cb),
  getSettings: () => ipcRenderer.invoke('qr:get-settings'),
  setSetting: (key, value) => ipcRenderer.invoke('qr:set-setting', String(key), value),
}));

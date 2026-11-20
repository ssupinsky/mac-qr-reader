'use strict';
// Validated IPC handlers (docs/ARCHITECTURE.md "IPC contract", SECURITY.md §5.6, §5.9).

const fs = require('node:fs');
const path = require('node:path');
const url = require('node:url');
const { app, ipcMain, dialog, shell, BrowserWindow } = require('electron');
const { ORIGIN } = require('./security');
const decoder = require('./decoder');
const files = require('./files');
const clip = require('./clipboard');
const settings = require('./settings');
const testhooks = require('./testhooks');
const linkinfo = require('./linkinfo');

const CH = {
  decodeImage: 'qr:decode-image',
  paste: 'qr:paste-from-clipboard',
  openFiles: 'qr:open-files',
  copyText: 'qr:copy-text',
  openExternal: 'qr:open-external',
  saveText: 'qr:save-text',
  getSettings: 'qr:get-settings',
  setSetting: 'qr:set-setting',
};

const OPEN_SCHEMES = new Set(['https:', 'http:', 'mailto:', 'tel:', 'sms:', 'facetime:', 'facetime-audio:']);
// What the link is, for the dialog. We do not name the app: LaunchServices picks the user's
// default handler for the scheme, which may be any installed app.
const SCHEME_KIND = {
  'https:': 'web', 'http:': 'web (unencrypted HTTP)', 'mailto:': 'e-mail', 'tel:': 'phone call',
  'sms:': 'text message', 'facetime:': 'FaceTime video call', 'facetime-audio:': 'FaceTime audio call',
};
// C0/C1 controls, soft hyphen, bidi controls, zero-width & invisible formatting, BOM, tag chars.
const UNSAFE_RANGES = [
  [0x0000, 0x0020], [0x007f, 0x00a0], [0x00ad, 0x00ad], [0x061c, 0x061c], [0x115f, 0x1160], [0x180e, 0x180e],
  [0x200b, 0x200f], [0x2028, 0x202f], [0x205f, 0x206f], [0x3000, 0x3000], [0x3164, 0x3164], [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff], [0xffa0, 0xffa0], [0xfff0, 0xffff], [0x1d173, 0x1d17a], [0xe0000, 0xe0fff],
];
const inRanges = (cp, ranges) => ranges.some(([a, b]) => cp >= a && cp <= b);
const hasUnsafeChars = (s) => { for (const ch of s) if (inRanges(ch.codePointAt(0), UNSAFE_RANGES)) return true; return false; };
const NAME_STRIP = [[0x0000, 0x001f], [0x007f, 0x009f], [0x200b, 0x200f], [0x202a, 0x202e], [0x2066, 0x2069], [0xfeff, 0xfeff]];
const stripNameChars = (s) => [...s].filter((ch) => !inRanges(ch.codePointAt(0), NAME_STRIP) && !'/\\:'.includes(ch)).join('');
const IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif', 'tif', 'tiff', 'bmp', 'webp', 'ico', 'heic', 'heif', 'avif', 'pdf'];
const SAVE_KINDS = {
  vcf: { ext: 'vcf', name: 'Contact (vCard)' },
  ics: { ext: 'ics', name: 'Calendar event' },
  txt: { ext: 'txt', name: 'Text' },
  bin: { ext: 'bin', name: 'Binary data' },
};

let getWindow = () => null;

function assertSender(e) {
  const win = getWindow();
  const f = e.senderFrame;
  if (!win || win.isDestroyed() || !f || e.sender !== win.webContents || f !== win.webContents.mainFrame
      || f.origin !== ORIGIN || !f.url.startsWith(`${ORIGIN}/`)) {
    throw new Error('forbidden');
  }
  return win;
}

const RESULT_CHANNELS = new Set(['qr:decode-image', 'qr:paste-from-clipboard', 'qr:open-files']);

function handle(channel, fn) {
  ipcMain.handle(channel, async (e, ...args) => {
    const win = assertSender(e);
    const r = await fn(win, ...args);
    if (testhooks.enabled && RESULT_CHANNELS.has(channel)) testhooks.record(channel, Array.isArray(r) ? r : [r]);
    return r;
  });
}

const isPlainObject = (o) => o !== null && typeof o === 'object' && !Array.isArray(o)
  && (Object.getPrototypeOf(o) === Object.prototype || Object.getPrototypeOf(o) === null);
const optString = (v, max) => v === undefined || (typeof v === 'string' && v.length <= max);

// ---------------------------------------------------------------- openExternal
/** Validates a URL for opening. → {ok:true, u} | {ok:false, reason} */
function checkExternalUrl(s) {
  if (typeof s !== 'string' || s.length === 0) return { ok: false, reason: 'empty' };
  if (s.length > 2048) return { ok: false, reason: 'too long' };
  if (hasUnsafeChars(s)) return { ok: false, reason: 'contains invisible, control or bidi characters' };
  let u;
  try { u = new URL(s); } catch { return { ok: false, reason: 'not a valid URL' }; }
  if (!OPEN_SCHEMES.has(u.protocol)) return { ok: false, reason: `scheme ${u.protocol} is not allowed` };
  if ((u.protocol === 'https:' || u.protocol === 'http:')) {
    if (!u.hostname) return { ok: false, reason: 'no host' };
    if (u.username || u.password) return { ok: false, reason: 'URL contains a user name or password' };
  }
  if (u.href.length > 4096) return { ok: false, reason: 'too long' };
  return { ok: true, u };
}

async function confirmAndOpen(win, s) {
  const c = checkExternalUrl(s);
  if (!c.ok) {
    await dialog.showMessageBox(win, {
      type: 'error', buttons: ['OK'], defaultId: 0, cancelId: 0,
      message: 'This link cannot be opened.', detail: `Reason: ${c.reason}.`,
    });
    return { opened: false };
  }
  const { u } = c;
  // The bold `message` carries what matters most (site + host); `detail` the full link.
  // Hosts are wrapped in bidi isolates; the href is shown truncated, but exactly u.href is opened.
  const lines = [linkinfo.truncateForDisplay(u.href), ''];
  let message = 'Open this link?';
  if (u.protocol === 'https:' || u.protocol === 'http:') {
    const host = u.hostname;
    const uni = url.domainToUnicode(host);
    const idn = !!uni && uni !== host;
    const local = linkinfo.localAddressKind(host);
    const reg = local ? null : await linkinfo.registrableDomain(host); // no "site" for local names/addresses
    const regUni = reg ? url.domainToUnicode(reg) || reg : null;
    const head = [];
    if (reg) head.push(`Site: ${linkinfo.isolate(regUni)}${regUni !== reg ? ` (${reg})` : ''}`);
    head.push(`Host: ${linkinfo.isolate(host)}`);
    if (idn) head.push(`Host (Unicode): ${linkinfo.isolate(uni)}`);
    message = `Open this link?\n\n${head.join('\n')}`;
    if (idn) lines.push('⚠ Internationalized domain name — check it carefully for look-alike characters.');
    if (local) {
      lines.push(`⚠ This link points to this Mac or your local network (${local} address). ` +
        'Links in QR codes can use this to reach routers, printers or local services.');
    }
    if (u.protocol === 'http:') lines.push('⚠ Not encrypted (http).');
    if (u.port) lines.push(`Port: ${u.port}`);
  }
  lines.push('', `Kind: ${SCHEME_KIND[u.protocol]} link. Opens with the default app for this link.`);
  const { response } = await dialog.showMessageBox(win, {
    type: 'warning',
    buttons: ['Cancel', 'Open'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
    message,
    detail: lines.join('\n'),
  });
  if (response !== 1) return { opened: false };
  await shell.openExternal(u.href, { activate: true });
  return { opened: true };
}

// ---------------------------------------------------------------- saveText
function safeFileName(name, ext) {
  let n = typeof name === 'string' ? name : '';
  n = stripNameChars(n).trim();
  n = n.replace(/^\.+/, '').slice(0, 100);
  if (!n) n = 'scan';
  if (!n.toLowerCase().endsWith(`.${ext}`)) n = `${n}.${ext}`;
  return n;
}

async function saveText(win, opts) {
  if (!isPlainObject(opts) || !SAVE_KINDS[opts.kind] || !optString(opts.suggestedName, 255)) throw new Error('invalid arguments');
  let data;
  if (opts.kind === 'bin') {
    const b64 = opts.bytesBase64 ?? opts.text;
    if (typeof b64 !== 'string' || b64.length > 64 * 1024 * 1024 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new Error('invalid arguments');
    data = Buffer.from(b64, 'base64');
  } else {
    if (typeof opts.text !== 'string' || opts.text.length > 16 * 1024 * 1024) throw new Error('invalid arguments');
    data = Buffer.from(opts.text, 'utf8');
  }
  const k = SAVE_KINDS[opts.kind];
  const r = await dialog.showSaveDialog(win, {
    defaultPath: path.join(app.getPath('downloads'), safeFileName(opts.suggestedName, k.ext)),
    filters: [{ name: k.name, extensions: [k.ext] }],
    properties: ['createDirectory', 'showOverwriteConfirmation'],
  });
  if (r.canceled || !r.filePath) return { saved: false };
  await fs.promises.writeFile(r.filePath, data, { mode: 0o600 });
  return { saved: true };
}

// ---------------------------------------------------------------- open dialog
async function openFilesDialog(win) {
  const r = await dialog.showOpenDialog(win, {
    title: 'Open Images',
    properties: ['openFile', 'multiSelections'],
    filters: [{ name: 'Images and PDF', extensions: IMAGE_EXTENSIONS }],
  });
  if (r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return [];
  return files.scanPaths(r.filePaths, 'file');
}

// ---------------------------------------------------------------- register
function register(windowGetter) {
  getWindow = windowGetter;

  handle(CH.decodeImage, async (_win, bytes, meta) => {
    if (!(bytes instanceof Uint8Array)) throw new Error('invalid arguments');
    if (!isPlainObject(meta) || !['drop', 'paste'].includes(meta.source) || !optString(meta.name, 1024)) {
      throw new Error('invalid arguments');
    }
    const name = typeof meta.name === 'string' ? path.basename(meta.name).slice(0, 255) : undefined;
    if (meta.source === 'paste') clip.noteSeenImage(bytes);
    return decoder.decode(bytes, name ? { kind: meta.source, name } : { kind: meta.source }); // size limits → error results
  });

  handle(CH.paste, () => clip.pasteFromClipboard());
  handle(CH.openFiles, (win) => openFilesDialog(win));

  handle(CH.copyText, async (_win, text, opts) => {
    if (typeof text !== 'string' || text.length > 1024 * 1024) throw new Error('invalid arguments');
    if (opts !== undefined && opts !== null && (!isPlainObject(opts) || (opts.sensitive !== undefined && typeof opts.sensitive !== 'boolean'))) {
      throw new Error('invalid arguments');
    }
    await clip.copyText(text, { sensitive: opts?.sensitive === true });
  });

  handle(CH.openExternal, (win, s) => confirmAndOpen(win, s));
  handle(CH.saveText, (win, opts) => saveText(win, opts));
  handle(CH.getSettings, () => settings.get());
  handle(CH.setSetting, (_win, key, value) => {
    if (!settings.isKey(key)) throw new Error('invalid arguments');
    return settings.set(key, value);
  });
}

module.exports = { register, checkExternalUrl, CH };

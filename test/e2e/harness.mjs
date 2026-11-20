// Shared real-app launch helpers for scripts/verify.mjs and test/e2e/*.test.mjs.
// Launches the UNFUSED dev Electron binary with the project dir (Playwright cannot drive
// the fused .app, docs/SECURITY.md §6.5) and drives the real input paths.

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileP = promisify(execFile);
export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const FIXTURES = path.join(ROOT, 'test/fixtures');
export const GEN_FIXTURES = path.join(ROOT, 'build/bin/gen-fixtures');
const ELECTRON_REL = 'node_modules/electron/dist/Electron.app/Contents/MacOS/Electron';
// Fallback scratch install used before the project's node_modules existed.
const FALLBACK_DIRS = (process.env.QR_FALLBACK_NODE_MODULES_DIR || '').split(':').filter(Boolean);

function candidateDirs() {
  return [ROOT, ...FALLBACK_DIRS];
}

export function electronPath() {
  if (process.env.QR_ELECTRON_BIN) return process.env.QR_ELECTRON_BIN;
  for (const d of candidateDirs()) {
    const p = path.join(d, ELECTRON_REL);
    if (fs.existsSync(p)) return p;
  }
  throw new Error(`Electron binary not found (${ELECTRON_REL}). Run ./start.sh (or npm run setup) first.`);
}

let pw;
let pwLoader;
export async function playwright() {
  if (pw) return pw;
  for (const d of candidateDirs()) {
    const pkg = path.join(d, 'node_modules/playwright-core/package.json');
    if (fs.existsSync(pkg)) {
      pw = createRequire(pkg)('playwright-core');
      pwLoader = path.join(path.dirname(pkg), 'lib/server/electron/loader.js');
      return pw;
    }
  }
  throw new Error('playwright-core not found in node_modules. Run ./start.sh (or npm run setup) first.');
}

export function manifest() {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8')).fixtures;
}

export function fixture(name) {
  return path.join(FIXTURES, name);
}

/** Asserts a ScanResult against its test/fixtures/manifest.json entry. */
export function checkAgainstManifest(fx, r) {
  const e = fx.expect;
  assert.equal(r.source.name, fx.file);
  if (e.anyResult || e.ok === undefined) return;
  assert.equal(r.ok, e.ok, `${fx.file}: ok (${JSON.stringify(r.error)})`);
  if (!e.ok) { assert.equal(r.error.code, e.error, `${fx.file}: error code`); return; }
  assert.equal(r.image.format, e.format, `${fx.file}: format`);
  assert.match(r.image.previewDataUrl, /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+=*$/, `${fx.file}: preview`);
  if (e.pages) assert.equal(r.image.pages, e.pages, `${fx.file}: pages`);
  const texts = r.codes.map((c) => c.text);
  for (const c of e.codes || []) assert.ok(texts.includes(c.text), `${fx.file}: missing ${JSON.stringify(c.text)} in ${JSON.stringify(texts)}`);
  if (e.exactCount) assert.equal(r.codes.length, e.codes.length, `${fx.file}: code count`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Makes an ad-hoc QR PNG with gen-fixtures. Returns the absolute path. */
export async function makeQr(text, outPath) {
  await execFileP(GEN_FIXTURES, ['one', text, outPath]);
  return outPath;
}

export function tmpDir(prefix = 'qr-e2e-') {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

/**
 * Launches the real app.
 * @param {{autoScan?: boolean, env?: object, files?: string[], userData?: string, appDir?: string}} opts
 * @returns {Promise<{app, page, userData, close: () => Promise<void>}>}
 */
export async function launch(opts = {}) {
  const { _electron } = await playwright();
  const userData = opts.userData || tmpDir('qr-userdata-');
  if (!fs.existsSync(path.join(userData, 'settings.json'))) {
    fs.writeFileSync(path.join(userData, 'settings.json'), JSON.stringify({ autoScanClipboard: !!opts.autoScan }));
  }
  const env = { ...process.env, QR_DEV_USER_DATA: userData, QR_TEST_HOOKS: '1', ...(opts.env || {}) };
  for (const k of Object.keys(env)) if (k.startsWith('ELECTRON_') || k === 'NODE_OPTIONS') delete env[k];
  // With `executablePath` Playwright does not inject its loader (`-r loader.js`), which holds
  // back app 'ready' until Playwright has attached. Without it the window navigates while
  // Playwright attaches, and if the attach lands mid-commit (frame tree still "") launch hangs
  // until its timeout (Playwright 1.64 race; see test/e2e-packaged/harness.mjs launchAttached).
  // The dev binary is unfused, so pass the loader ourselves (default_app handles `-r`).
  if (!fs.existsSync(pwLoader)) throw new Error(`Playwright Electron loader not found: ${pwLoader}`);
  const app = await _electron.launch({
    executablePath: electronPath(),
    args: ['-r', pwLoader, opts.appDir || ROOT, ...(opts.files || [])],
    env,
    cwd: ROOT,
    timeout: 30_000,
    colorScheme: null, // follow nativeTheme (Playwright otherwise emulates 'light')
  });
  const page = await app.firstWindow();
  await page.waitForLoadState('load');
  await page.waitForFunction(() => typeof window.qr === 'object' && window.qr !== null);
  // Window must be visible (ready-to-show) before screenshots look right.
  await waitFor(() => app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().some((w) => w.isVisible())), 10_000, 'window visible');
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    const proc = app.process();
    await Promise.race([app.close().catch(() => {}), sleep(8000)]);
    if (proc && proc.exitCode === null) { try { proc.kill('SIGKILL'); } catch { /* gone */ } }
  };
  return { app, page, userData, close };
}

export async function waitFor(fn, timeoutMs = 20_000, what = 'condition') {
  const t0 = Date.now();
  let last;
  while (Date.now() - t0 < timeoutMs) {
    try {
      last = await fn();
      if (last) return last;
    } catch (e) { last = e; }
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what}${last instanceof Error ? `: ${last.message}` : ''}`);
}

// ------------------------------------------------------------------ observing results
const seqNow = (app) => app.evaluate(() => globalThis.__qrTestSeq || 0);

/**
 * Runs `action` and waits for the next `count` result batches recorded by main
 * (filtered by `via`: 'push' | 'qr:decode-image' | 'qr:paste-from-clipboard' | 'qr:open-files').
 * Resolves the concatenated ScanResult[].
 */
export async function nextResults(app, action, { timeoutMs = 30_000, via, count = 1 } = {}) {
  const seq0 = await seqNow(app);
  await action();
  return waitFor(async () => {
    const log = await app.evaluate(() => globalThis.__qrTestLog || []);
    const fresh = log.filter((b) => b.seq > seq0 && (!via || b.via === via));
    return fresh.length >= count ? fresh.slice(0, count).flatMap((b) => b.results) : null;
  }, timeoutMs, 'scan results');
}

/** Waits for the renderer to settle (images decoded, a couple of frames). */
export async function settle(page, ms = 300) {
  await page.evaluate(async () => {
    await Promise.all([...document.images].map((i) => (i.complete ? null : i.decode().catch(() => {}))));
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
  await sleep(ms);
}

// ------------------------------------------------------------------ real input paths
/** Finder "Open With" / dock drop: emits the real `open-file` app event in main. */
export async function openWith(app, paths) {
  return nextResults(app, () => app.evaluate(({ app: a }, ps) => {
    for (const p of ps) a.emit('open-file', { preventDefault() {} }, p);
  }, paths), { via: 'push' });
}

/** Clicks a native application-menu item by label (runs its real click handler in main). */
export async function clickMenu(app, label) {
  const ok = await app.evaluate(({ Menu, BrowserWindow }, l) => {
    const find = (menu) => {
      for (const it of menu?.items || []) {
        if (it.label === l) return it;
        const sub = find(it.submenu);
        if (sub) return sub;
      }
      return null;
    };
    const item = find(Menu.getApplicationMenu());
    if (!item) return false;
    item.click(undefined, BrowserWindow.getAllWindows()[0]);
    return true;
  }, label);
  if (!ok) throw new Error(`menu item not found: ${label}`);
}

/** File ▸ Open… with dialog.showOpenDialog stubbed at the dialog boundary only. */
export async function openViaDialog(app, paths) {
  await app.evaluate(({ dialog }, ps) => {
    globalThis.__qrOrigShowOpenDialog ??= dialog.showOpenDialog;
    dialog.showOpenDialog = async () => ({ canceled: false, filePaths: ps });
  }, paths);
  try {
    return await nextResults(app, () => clickMenu(app, 'Open…'), { via: 'qr:open-files' });
  } finally {
    await app.evaluate(({ dialog }) => { if (globalThis.__qrOrigShowOpenDialog) dialog.showOpenDialog = globalThis.__qrOrigShowOpenDialog; });
  }
}

/** Dispatches a real drop event in the renderer with Files built from the files' bytes. */
export async function dropFiles(app, page, paths) {
  const files = paths.map((p) => ({ name: path.basename(p), b64: fs.readFileSync(p).toString('base64'), type: mimeFor(p) }));
  // The renderer decodes two files at a time, so main logs them in completion order; return
  // them in drop order (the order the renderer shows them in).
  const order = files.map((f) => f.name);
  const results = await nextResults(app, () => page.evaluate((fl) => {
    const dt = new DataTransfer();
    for (const f of fl) {
      const bin = atob(f.b64);
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      dt.items.add(new File([u8], f.name, { type: f.type }));
    }
    const target = document.querySelector('[data-testid="drop-zone"]') || document.body;
    const opts = { bubbles: true, cancelable: true, dataTransfer: dt };
    target.dispatchEvent(new DragEvent('dragenter', opts));
    target.dispatchEvent(new DragEvent('dragover', opts));
    target.dispatchEvent(new DragEvent('drop', opts));
  }, files), { via: 'qr:decode-image', count: paths.length });
  return [...results].sort((a, b) => order.indexOf(a.source?.name) - order.indexOf(b.source?.name));
}
export function mimeFor(p) {
  const ext = path.extname(p).toLowerCase();
  return {
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
    '.bmp': 'image/bmp', '.tif': 'image/tiff', '.tiff': 'image/tiff', '.heic': 'image/heic', '.avif': 'image/avif',
    '.ico': 'image/x-icon', '.pdf': 'application/pdf', '.svg': 'image/svg+xml',
  }[ext] || 'application/octet-stream';
}

// ------------------------------------------------------------------ system clipboard
const JXA_SAVE = `
ObjC.import('AppKit'); ObjC.import('Foundation');
function run() {
  const pb = $.NSPasteboard.generalPasteboard;
  const items = pb.pasteboardItems; const out = [];
  for (let i = 0; i < items.count; i++) {
    const it = items.objectAtIndex(i); const types = it.types; const o = {};
    for (let j = 0; j < types.count; j++) {
      const t = types.objectAtIndex(j).js; const d = it.dataForType(t);
      if (d && !d.isNil()) o[t] = d.base64EncodedStringWithOptions(0).js;
    }
    out.push(o);
  }
  return JSON.stringify(out);
}`;
// Pasteboard writes from a short-lived osascript are NOT complete when writeObjects returns:
// items reach the pasteboard server asynchronously, and anything not yet delivered when the
// writer exits is silently lost (observed: 3 file URLs written, 1 or 2 left on the clipboard,
// ~half the time). So each writer reports "written" on stdout and then stays alive; the harness
// confirms from a SEPARATE process (JXA_PROBE) that the server holds exactly what was written,
// and only then terminates the writer.
const JXA_STAY = `
  $.NSFileHandle.fileHandleWithStandardOutput.writeData($('written\\n').dataUsingEncoding($.NSUTF8StringEncoding));
  for (;;) delay(0.05);`;
const JXA_RESTORE = `
ObjC.import('AppKit'); ObjC.import('Foundation');
function run() {
  const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
  const json = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js;
  const saved = JSON.parse(json); const pb = $.NSPasteboard.generalPasteboard; pb.clearContents;
  const arr = $.NSMutableArray.alloc.init;
  for (const o of saved) {
    const it = $.NSPasteboardItem.alloc.init;
    for (const t of Object.keys(o)) it.setDataForType($.NSData.alloc.initWithBase64EncodedStringOptions(o[t], 0), t);
    arr.addObject(it);
  }
  if (arr.count && !pb.writeObjects(arr)) throw new Error('pasteboard write failed');${JXA_STAY}
}`;
const JXA_FILES = `
ObjC.import('AppKit');
function run(argv) {
  const pb = $.NSPasteboard.generalPasteboard; pb.clearContents;
  if (!pb.writeObjects($(argv.map((p) => $.NSURL.fileURLWithPath(p))))) throw new Error('pasteboard write failed');${JXA_STAY}
}`;
/** What the pasteboard server holds: per item, {types: {type: byteLength}, url: public.file-url}. */
const JXA_PROBE = `
ObjC.import('AppKit');
function run() {
  const items = $.NSPasteboard.generalPasteboard.pasteboardItems; const out = [];
  for (let i = 0; i < items.count; i++) {
    const it = items.objectAtIndex(i); const types = it.types; const o = { types: {}, url: null };
    for (let j = 0; j < types.count; j++) {
      const t = types.objectAtIndex(j).js; const d = it.dataForType(t);
      o.types[t] = d && !d.isNil() ? Number(d.length) : -1;
    }
    const u = it.stringForType('public.file-url');
    if (u && !u.isNil()) o.url = u.js;
    out.push(o);
  }
  return JSON.stringify(out);
}`;

async function probePasteboard() {
  const { stdout } = await execFileP('/usr/bin/osascript', ['-l', 'JavaScript', '-e', JXA_PROBE], { maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(stdout);
}

/** Runs a JXA writer, waits until a separate reader sees `isComplete(items)`, then ends the writer. */
function writePasteboard(script, args, stdin, isComplete, what) {
  return new Promise((resolve, reject) => {
    const p = spawn('/usr/bin/osascript', ['-l', 'JavaScript', '-e', script, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    let written = false;
    let settled = false;
    const finish = (e) => {
      if (settled) return;
      settled = true;
      p.kill('SIGTERM');
      if (e) reject(e); else resolve();
    };
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', finish);
    p.on('exit', (code) => finish(new Error(`${what}: writer exited early (${code}): ${err}`)));
    p.stdout.on('data', async (d) => {
      out += d;
      if (written || !out.includes('written\n')) return;
      written = true;
      const t0 = Date.now();
      let last;
      while (!settled && Date.now() - t0 < 10_000) {
        try {
          last = await probePasteboard();
          if (isComplete(last)) return finish();
        } catch (e) { last = e.message; }
        await sleep(50);
      }
      finish(new Error(`${what}: pasteboard never held the written items: ${JSON.stringify(last)}`));
    });
    p.stdin.end(stdin);
  });
}

/** Saves the whole general pasteboard (all items, all types) in memory — never to disk. */
export async function saveClipboard() {
  const { stdout } = await execFileP('/usr/bin/osascript', ['-l', 'JavaScript', '-e', JXA_SAVE], { maxBuffer: 512 * 1024 * 1024 });
  return stdout.trim();
}

export function restoreClipboard(saved) {
  const want = JSON.parse(saved || '[]');
  const complete = (items) => items.length === want.length && want.every((o, i) => Object.entries(o)
    .every(([t, b64]) => items[i].types[t] === Buffer.from(b64, 'base64').length));
  return writePasteboard(JXA_RESTORE, [], saved || '[]', complete, 'clipboard restore');
}

/** Puts file URLs on the clipboard exactly like Finder ▸ Copy (all items delivered before it returns). */
export function clipboardSetFiles(paths) {
  const complete = (items) => items.length === paths.length && items.every((it, i) => {
    try { return it.url !== null && fileURLToPath(it.url) === paths[i]; } catch { return false; }
  });
  return writePasteboard(JXA_FILES, paths, '', complete, 'clipboardSetFiles');
}

/** Writes an image to the REAL system clipboard from the app's main process. */
export async function clipboardSetImage(app, file) {
  const b64 = fs.readFileSync(file).toString('base64');
  const ext = path.extname(file).toLowerCase();
  await app.evaluate(async ({ clipboard, ClipboardItem, nativeImage }, { b64: data, ext: e }) => {
    let bytes = Buffer.from(data, 'base64');
    if (e !== '.png') bytes = nativeImage.createFromBuffer(bytes).toPNG(); // harness-only conversion
    await clipboard.write([new ClipboardItem({ 'image/png': new Blob([bytes], { type: 'image/png' }) })]);
  }, { b64, ext });
}

export async function clipboardSetText(app, text) {
  await app.evaluate(({ clipboard }, t) => clipboard.writeText(t), text);
}

/** Real paste: Meta+V into the window (Playwright maps it to the Chromium 'paste' editing command). */
export async function pasteKeys(app, page) {
  await page.bringToFront().catch(() => {});
  return nextResults(app, () => page.keyboard.press('Meta+V'));
}

// ------------------------------------------------------------------ theme / screenshots
export async function setTheme(app, page, theme) {
  await app.evaluate(({ nativeTheme }, t) => { nativeTheme.themeSource = t; }, theme);
  if (theme !== 'system') {
    await page.waitForFunction((t) => matchMedia('(prefers-color-scheme: dark)').matches === (t === 'dark'), theme, { timeout: 5000 });
  }
  await settle(page, 150);
}

export async function screenshot(page, file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  await page.screenshot({ path: file });
  return file;
}

/** Pretty one-line summary of a ScanResult for logs. */
export function summarize(r) {
  return {
    source: r.source, ok: r.ok, error: r.error,
    image: r.image ? { format: r.image.format, width: r.image.width, height: r.image.height, pages: r.image.pages } : undefined,
    codes: r.codes.map((c) => ({ symbology: c.symbology, text: c.text, page: c.page, pass: c.pass })),
    text: r.text,
  };
}

/** Kills stray dev Electron processes started from this project (safety net). */
export async function killStray() {
  try { await execFileP('/usr/bin/pkill', ['-f', `${electronPath()} ${ROOT}`]); } catch { /* none */ }
}

// ------------------------------------------------------------------ disk canary
/** The canary plus its base64 forms at all three alignments (inner part, so any offset matches). */
export function canaryNeedles(canary) {
  return [canary, ...[0, 1, 2].map((k) => Buffer.from(`${'xx'.slice(0, k)}${canary}`).toString('base64').slice(4, -4))];
}

/** Where decoded content could leak to: ~/Library/{Application Support,Caches,Saved Application State,Preferences}, $TMPDIR. */
export function canaryDirs() {
  const home = os.homedir();
  return [path.join(home, 'Library/Application Support'), path.join(home, 'Library/Caches'),
    fs.realpathSync(os.tmpdir()), path.join(home, 'Library/Saved Application State'), path.join(home, 'Library/Preferences')];
}

/** Greps files under `dirs` modified after `newerThan` (a marker file) for any needle. → {hits, scanned, dirs} */
export async function findOnDisk(needles, dirs, { newerThan, exclude = [] } = {}) {
  dirs = [...new Set(dirs.filter((d) => d && fs.existsSync(d)))];
  const hits = [];
  let scanned = 0;
  for (const d of dirs) {
    let list = '';
    try {
      ({ stdout: list } = await execFileP('/usr/bin/find', [d, '-type', 'f', '-newer', newerThan, '-size', '-200M'], { maxBuffer: 64 * 1024 * 1024 }));
    } catch (e) { list = e.stdout || ''; }
    const filesNew = list.split('\n').filter((f) => f && !exclude.some((x) => f.startsWith(x)));
    scanned += filesNew.length;
    for (let i = 0; i < filesNew.length; i += 200) {
      const chunk = filesNew.slice(i, i + 200);
      for (const n of needles) {
        try {
          const { stdout } = await execFileP('/usr/bin/grep', ['-l', '-F', '-a', '--', n, ...chunk], { maxBuffer: 16 * 1024 * 1024 });
          hits.push(...stdout.split('\n').filter(Boolean));
        } catch (e) { if (e.code !== 1 && e.stdout) hits.push(...e.stdout.split('\n').filter(Boolean)); }
      }
    }
  }
  return { hits: [...new Set(hits)], scanned, dirs };
}

// ------------------------------------------------------------------ cross-file serialisation
// `node --test` runs test files in parallel processes; several Electron instances launching
// at once (and sharing the system clipboard / window focus) time out or interfere. Each e2e
// file calls `serialize()` at top level: it takes an exclusive lock for the file's lifetime.
const LOCK = path.join(os.tmpdir(), 'qr-reader-e2e.lock');
const lockOwner = () => { try { return fs.readFileSync(path.join(LOCK, 'owner'), 'utf8'); } catch { return null; } };
export function serialize() {
  return async function acquire() {
    const t0 = Date.now();
    // Unique per acquisition: release() must only ever remove OUR lock. (It used to rm the dir
    // unconditionally, and it also ran again from the 'exit' handler after after() had already
    // released, deleting the NEXT file's lock, so two packaged test files ran at once.)
    const me = `${process.pid}:${crypto.randomBytes(8).toString('hex')}`;
    for (;;) {
      try {
        fs.mkdirSync(LOCK);
      } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        const owner = lockOwner();
        const pid = owner ? Number(owner.split(':')[0]) : 0; // null = owner is still being written
        let alive = true;
        if (pid) { try { process.kill(pid, 0); } catch (err) { alive = err.code === 'EPERM'; } }
        // Stale (owner dead, or held > 15 min): remove it only if it is still that same owner.
        if ((!alive || Date.now() - t0 > 15 * 60_000) && owner && lockOwner() === owner) {
          fs.rmSync(LOCK, { recursive: true, force: true });
        } else if (!owner) {
          // Owner never written (its process died right after mkdir): stale after 10 s.
          try { if (Date.now() - fs.statSync(LOCK).mtimeMs > 10_000 && !lockOwner()) fs.rmSync(LOCK, { recursive: true, force: true }); } catch { /* gone */ }
        }
        await sleep(250);
        continue;
      }
      fs.writeFileSync(path.join(LOCK, 'owner.tmp'), me);
      fs.renameSync(path.join(LOCK, 'owner.tmp'), path.join(LOCK, 'owner')); // readers never see a partial owner
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        process.removeListener('exit', release);
        if (lockOwner() === me) { try { fs.rmSync(LOCK, { recursive: true, force: true }); } catch { /* gone */ } }
      };
      process.once('exit', release);
      return release;
    }
  };
}

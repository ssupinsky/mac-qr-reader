// Clipboard paths against the REAL system clipboard (saved before, restored after).
// All clipboard-touching e2e tests live in this one file so they never run in parallel.
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as h from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); });
after(() => release?.());

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MARK = 'electron application/osclipboard;format="local.qr-reader.sensitive"';
const pbcopy = (t) => execFileSync('/usr/bin/pbcopy', { input: t });
const pbpaste = () => execFileSync('/usr/bin/pbpaste').toString();

let saved = null;
before(async () => { saved = await h.saveClipboard(); });
after(async () => { if (saved !== null) await h.restoreClipboard(saved); });

describe('paste', () => {
  let ctx;
  before(async () => { ctx = await h.launch(); });
  after(async () => { await ctx?.close(); });

  test('image on the system clipboard + Meta+V', async () => {
    await h.clipboardSetImage(ctx.app, h.fixture('wifi.png'));
    const r = await h.pasteKeys(ctx.app, ctx.page);
    assert.equal(r.length, 1);
    assert.equal(r[0].source.kind, 'paste');
    assert.equal(r[0].codes[0].text, 'WIFI:T:WPA;S:My\\;Net\\,work;P:p\\:a\\\\ss\\"word;H:false;;');
  });

  test('Finder-copied files (multiple) + Meta+V', async () => {
    await h.clipboardSetFiles([h.fixture('url.png'), h.fixture('gif-anim.gif'), h.fixture('random.bin')]);
    const r = await h.pasteKeys(ctx.app, ctx.page);
    assert.deepEqual(r.map((x) => [x.source.kind, x.source.name, x.ok]),
      [['paste', 'url.png', true], ['paste', 'gif-anim.gif', true], ['paste', 'random.bin', false]]);
    assert.equal(r[1].codes[0].text, 'code on third GIF frame');
  });

  test('plain text + Meta+V → text result (not decoded)', async () => {
    await h.clipboardSetText(ctx.app, 'https://example.org/pasted');
    const r = await h.pasteKeys(ctx.app, ctx.page);
    assert.deepEqual(r.map((x) => [x.source.kind, x.ok, x.text]), [['text', true, 'https://example.org/pasted']]);
  });

  test('empty clipboard → clipboard_empty error', async () => {
    await ctx.app.evaluate(({ clipboard }) => clipboard.clear());
    const r = await ctx.page.evaluate(() => window.qr.pasteFromClipboard());
    assert.equal(r[0].ok, false);
    assert.equal(r[0].error.code, 'clipboard_empty');
  });
});

describe('copy', () => {
  let ctx;
  before(async () => { ctx = await h.launch({ env: { QR_TEST_SENSITIVE_CLEAR_MS: '1500' } }); });
  after(async () => { await ctx?.close(); });

  test('sensitive copy carries concealed markers and is auto-cleared', async () => {
    await ctx.page.evaluate(() => window.qr.copyText('hunter2-secret', { sensitive: true }));
    const types = await ctx.app.evaluate(async ({ clipboard }, m) => ({
      mark: await clipboard.has(m),
      concealed: await clipboard.has('electron application/osclipboard;format="org.nspasteboard.ConcealedType"'),
      transient: await clipboard.has('electron application/osclipboard;format="org.nspasteboard.TransientType"'),
    }), MARK);
    assert.deepEqual(types, { mark: true, concealed: true, transient: true });
    assert.equal(pbpaste(), 'hunter2-secret');
    await sleep(2500);
    assert.equal(pbpaste(), '');
  });

  test('auto-clear never wipes a newer clipboard', async () => {
    await ctx.page.evaluate(() => window.qr.copyText('second-secret', { sensitive: true }));
    pbcopy('user copied something else');
    await sleep(2500);
    assert.equal(pbpaste(), 'user copied something else');
  });

  test('plain copy is not cleared', async () => {
    await ctx.page.evaluate(() => window.qr.copyText('plain value'));
    await sleep(2500);
    assert.equal(pbpaste(), 'plain value');
    assert.equal(await ctx.app.evaluate(({ clipboard }, m) => clipboard.has(m), MARK), false);
  });

  test('quitting clears a pending sensitive copy, promptly', async () => {
    const c2 = await h.launch(); // default 60 s timeout
    await c2.page.evaluate(() => window.qr.copyText('quit-secret', { sensitive: true }));
    assert.equal(pbpaste(), 'quit-secret');
    const t0 = Date.now();
    await c2.close();
    assert.ok(Date.now() - t0 < 5000, 'quit took too long');
    assert.equal(pbpaste(), '');
  });
});

describe('auto-scan on focus', () => {
  let ctx;
  const focus = () => ctx.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].emit('focus'));
  const seq = () => ctx.app.evaluate(() => globalThis.__qrTestSeq);
  before(async () => {
    pbcopy('just text');
    ctx = await h.launch({ autoScan: true });
  });
  after(async () => { await ctx?.close(); });

  test('scans a new clipboard image once; ignores text and unchanged content', async () => {
    let s0 = await seq();
    await focus();
    await sleep(800);
    assert.equal(await seq(), s0, 'text on the clipboard must not be read/scanned');

    await h.clipboardSetImage(ctx.app, h.fixture('otpauth.png'));
    const r = await h.nextResults(ctx.app, focus, { via: 'push' });
    assert.equal(r[0].source.kind, 'clipboard-auto');
    assert.match(r[0].codes[0].text, /^otpauth:\/\/totp\//);

    s0 = await seq();
    await focus();
    await sleep(800);
    assert.equal(await seq(), s0, 'unchanged clipboard must not be rescanned');
  });

  test('Finder-copied image files are scanned; non-images and code-less images are not pushed', async () => {
    await h.clipboardSetFiles([h.fixture('mailto.png')]);
    const r = await h.nextResults(ctx.app, focus, { via: 'push' });
    assert.equal(r[0].source.name, 'mailto.png');
    const s0 = await seq();
    await h.clipboardSetFiles([h.fixture('not-image.txt')]);
    await focus();
    await sleep(800);
    await h.clipboardSetImage(ctx.app, h.fixture('no-code.png'));
    await focus();
    await sleep(1500);
    assert.equal(await seq(), s0);
  });

  test('disabled setting → no scan', async () => {
    await ctx.page.evaluate(() => window.qr.setSetting('autoScanClipboard', false));
    await h.clipboardSetImage(ctx.app, h.fixture('tel.png'));
    const s0 = await seq();
    await focus();
    await sleep(1000);
    assert.equal(await seq(), s0);
  });
});

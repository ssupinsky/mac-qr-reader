// The PACKAGED app end to end (build/QR Reader (Test).app): asar-loaded code, packaged resource
// paths, helper hash check + sandbox-exec from Contents/Resources, real input paths, and the
// renderer/session hardening in the packaged context.
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as h from '../e2e/harness.mjs';
import * as p from './harness.mjs';

const acquire = h.serialize();
let release;
let saved = null;
before(async () => {
  release = await acquire();
  await p.testBundle();
  saved = await h.saveClipboard();
});
after(async () => {
  if (saved !== null) await h.restoreClipboard(saved);
  release?.();
});

describe('packaged test variant', { timeout: 300_000 }, () => {
  let ctx, R;
  const ignored = h.tmpDir('qr-ignored-');
  before(async () => {
    // Dev-only env vars must be ignored by the packaged app.
    ctx = await p.launchPackaged({ env: { QR_TEST_HOOKS: '1', QR_DEV_USER_DATA: ignored } });
    R = p.resourcesOf(p.TEST_APP);
  });
  after(async () => { await ctx?.close(); fs.rmSync(ignored, { recursive: true, force: true }); });

  test('runs from the bundle: asar code, packaged paths, own userData, no test hooks', async () => {
    const m = await ctx.app.evaluate(({ app }) => ({
      packaged: app.isPackaged, appPath: app.getAppPath(), resources: process.resourcesPath,
      userData: app.getPath('userData'), exe: process.execPath, argv: process.argv.slice(1),
    }));
    assert.equal(ctx.hooksBefore, 'undefined', 'QR_TEST_HOOKS must be ignored when packaged');
    assert.equal(m.packaged, true);
    assert.equal(m.appPath, path.join(R, 'app.asar'));
    assert.equal(m.resources, R);
    assert.equal(m.exe, p.exeOf(fs.realpathSync(p.TEST_APP)));
    assert.equal(m.userData, p.USER_DATA, 'QR_DEV_USER_DATA must be ignored when packaged');
    assert.deepEqual(fs.readdirSync(ignored), []);
    assert.deepEqual(m.argv, ['--inspect=0', '--remote-debugging-port=0']);
  });

  test('Open With (LaunchServices `open -a`): every fixture decodes as the manifest expects; helper is sandboxed from Contents/Resources', async () => {
    const fixtures = h.manifest();
    const { result: results, children } = await p.watchChildren(ctx.pid, () => p.openWithLS(ctx, fixtures.map((f) => h.fixture(f.file))));
    assert.equal(results.length, fixtures.length);
    const byName = new Map(results.map((r) => [r.source.name, r]));
    for (const fx of fixtures) {
      assert.equal(byName.get(fx.file)?.source.kind, 'open-with', fx.file);
      h.checkAgainstManifest(fx, byName.get(fx.file));
    }
    assert.ok(!JSON.stringify(results).includes(h.FIXTURES), 'no filesystem paths reach the renderer');

    const decoders = children.filter((c) => c.commands.some((cmd) => /qr-decode/.test(cmd)));
    assert.ok(decoders.length > 0, `no decoder child seen; children: ${JSON.stringify(children)}`);
    for (const c of decoders) {
      for (const cmd of c.commands) {
        if (cmd.startsWith('/usr/bin/sandbox-exec')) {
          assert.ok(cmd.startsWith(`/usr/bin/sandbox-exec -f ${R}/qr-decode.sb -D HELPER=${R}/bin/qr-decode -D HELPER_DIR=${R}/bin ${R}/bin/qr-decode --preview-max `), cmd);
        } else {
          assert.ok(cmd.startsWith(`${R}/bin/qr-decode --preview-max `), `helper must be the bundle's: ${cmd}`);
        }
      }
    }
    const checked = decoders.filter((c) => typeof c.sandboxed === 'number' && c.sandboxed >= 0);
    assert.ok(checked.length > 0, 'sandbox_check reached a live helper');
    for (const c of checked) assert.equal(c.sandboxed, 1, `helper pid ${c.pid} is not sandboxed`);
  });

  test('drop: real File bytes through the renderer, results shown in the UI', async () => {
    const names = ['multi-3.png', 'heic.heic', 'two-page.pdf', 'image.svg'];
    const got = await h.dropFiles(ctx.app, ctx.page, names.map(h.fixture));
    const r = names.map((n) => got.find((x) => x.source.name === n)); // decodes run concurrently
    assert.deepEqual(r.map((x) => [x.source.kind, x.source.name, x.ok, x.error?.code]),
      [['drop', 'multi-3.png', true, undefined], ['drop', 'heic.heic', true, undefined],
        ['drop', 'two-page.pdf', true, undefined], ['drop', 'image.svg', false, 'unsupported_format']]);
    assert.deepEqual(r[0].codes.map((c) => c.text), ['https://example.com/one', 'SECOND code', 'WIFI:T:WPA;S:Third;P:secret;;']);
    assert.equal(r[2].codes[0].text, 'https://example.com/pdf-page-2');
    await h.waitFor(() => ctx.page.evaluate(() => {
      const t = document.querySelector('[data-testid="results"]')?.textContent || '';
      return t.includes('example.com') && document.querySelectorAll('[data-testid="code"]').length > 0;
    }), 10_000, 'decoded codes rendered');
  });

  test('paste (Meta+V): image on the REAL system clipboard', async () => {
    await h.clipboardSetImage(ctx.app, h.fixture('wifi.png'));
    const r = await h.pasteKeys(ctx.app, ctx.page);
    assert.equal(r.length, 1);
    assert.equal(r[0].ok, true);
    assert.equal(r[0].source.kind, 'paste');
    assert.equal(r[0].codes[0].text, 'WIFI:T:WPA;S:My\\;Net\\,work;P:p\\:a\\\\ss\\"word;H:false;;');
  });

  test('paste (Meta+V): Finder-style file URLs on the clipboard', async () => {
    await h.clipboardSetFiles([h.fixture('url.png'), h.fixture('gif-anim.gif')]);
    const r = await h.pasteKeys(ctx.app, ctx.page);
    assert.deepEqual(r.map((x) => [x.source.kind, x.source.name, x.ok]), [['paste', 'url.png', true], ['paste', 'gif-anim.gif', true]]);
    assert.equal(r[0].codes[0].text, 'https://example.com/path/to/page?query=1&b=two#frag');
    assert.equal(r[1].codes[0].text, 'code on third GIF frame');
  });

  test('renderer: no Node, only window.qr; webPreferences locked down', async () => {
    assert.equal(ctx.page.url(), 'app://qr/index.html');
    const r = await ctx.page.evaluate(() => ({
      require: typeof window.require, process: typeof window.process, module: typeof window.module,
      buffer: typeof window.Buffer, electron: typeof window.electron, ipc: typeof window.ipcRenderer,
      qrKeys: Object.keys(window.qr).sort(), frozen: Object.isFrozen(window.qr),
    }));
    assert.deepEqual([r.require, r.process, r.module, r.buffer, r.electron, r.ipc], Array(6).fill('undefined'));
    assert.deepEqual(r.qrKeys, ['copyText', 'decodeImage', 'getSettings', 'onCommand', 'onScanResults',
      'openExternal', 'openFiles', 'pasteFromClipboard', 'saveText', 'setSetting']);
    assert.ok(r.frozen);
    const wp = await ctx.app.evaluate(({ BrowserWindow }) => {
      const w = BrowserWindow.getAllWindows()[0];
      w.webContents.openDevTools({ mode: 'detach' }); // devTools:false when packaged → no-op
      return { ...w.webContents.getLastWebPreferences(), persistent: w.webContents.session.isPersistent() };
    });
    await new Promise((res) => setTimeout(res, 500));
    assert.equal(await ctx.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].webContents.isDevToolsOpened()), false);
    for (const [k, v] of Object.entries({ sandbox: true, contextIsolation: true, nodeIntegration: false, nodeIntegrationInWorker: false,
      webviewTag: false, webSecurity: true, allowRunningInsecureContent: false, persistent: false })) {
      assert.equal(wp[k], v, k);
    }
  });

  test('network is blocked (renderer fetch/img/WebSocket, both sessions) and CSP is served', async () => {
    const r = await ctx.page.evaluate(async () => {
      const out = {};
      try { await fetch('https://example.com/'); out.fetch = 'ok'; } catch (e) { out.fetch = e.name; }
      out.img = await new Promise((res) => { const i = new Image(); i.onload = () => res('loaded'); i.onerror = () => res('error'); i.src = 'https://example.com/x.png'; });
      try { const ws = new WebSocket('wss://example.com/'); out.ws = await new Promise((res) => { ws.onopen = () => res('open'); ws.onerror = () => res('error'); }); } catch (e) { out.ws = e.name; }
      return out;
    });
    assert.equal(r.fetch, 'TypeError');
    assert.equal(r.img, 'error');
    assert.notEqual(r.ws, 'open');
    const m = await ctx.app.evaluate(async ({ BrowserWindow, session }) => {
      const res = {};
      const s0 = BrowserWindow.getAllWindows()[0].webContents.session;
      for (const [k, s] of [['partition', s0], ['default', session.defaultSession]]) {
        try { await s.fetch('https://example.com/'); res[k] = 'ok'; } catch (e) { res[k] = String(e.message); }
      }
      const idx = await s0.fetch('app://qr/index.html');
      res.csp = idx.headers.get('content-security-policy');
      res.main = (await s0.fetch('app://qr/../main/main.js')).status;
      return res;
    });
    assert.match(m.partition, /ERR_BLOCKED_BY_CLIENT/);
    assert.match(m.default, /ERR_BLOCKED_BY_CLIENT/);
    assert.match(m.csp, /default-src 'none'.*require-trusted-types-for 'script'/);
    assert.equal(m.main, 404);
  });
});

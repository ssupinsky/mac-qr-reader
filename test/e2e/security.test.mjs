// Security assertions against the real app (dev Electron binary, same webPreferences/session
// code as the packaged build).
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as h from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); });
after(() => release?.());

describe('renderer & session hardening', () => {
  let ctx;
  before(async () => { ctx = await h.launch(); });
  after(async () => { await ctx?.close(); });

  test('loads from app://qr with no Node in the renderer', async () => {
    assert.equal(ctx.page.url(), 'app://qr/index.html');
    const r = await ctx.page.evaluate(() => ({
      require: typeof window.require, process: typeof window.process, module: typeof window.module,
      buffer: typeof window.Buffer, electron: typeof window.electron, ipc: typeof window.ipcRenderer,
      qrKeys: Object.keys(window.qr).sort(), frozen: Object.isFrozen(window.qr),
    }));
    assert.equal(r.require, 'undefined');
    assert.equal(r.process, 'undefined');
    assert.equal(r.module, 'undefined');
    assert.equal(r.buffer, 'undefined');
    assert.equal(r.electron, 'undefined');
    assert.equal(r.ipc, 'undefined');
    assert.deepEqual(r.qrKeys, ['copyText', 'decodeImage', 'getSettings', 'onCommand', 'onScanResults',
      'openExternal', 'openFiles', 'pasteFromClipboard', 'saveText', 'setSetting']);
    assert.ok(r.frozen);
  });

  test('webPreferences are locked down', async () => {
    const p = await ctx.app.evaluate(({ BrowserWindow }) => {
      const w = BrowserWindow.getAllWindows()[0];
      const wp = w.webContents.getLastWebPreferences();
      return { ...wp, persistent: w.webContents.session.isPersistent(), spell: w.webContents.session.isSpellCheckerEnabled() };
    });
    assert.equal(p.sandbox, true);
    assert.equal(p.contextIsolation, true);
    assert.equal(p.nodeIntegration, false);
    assert.equal(p.webviewTag, false);
    assert.equal(p.webSecurity, true);
    assert.equal(p.spell, false);
    assert.equal(p.nodeIntegrationInWorker, false);
    assert.equal(p.allowRunningInsecureContent, false);
    assert.equal(p.persistent, false);
  });

  test('CSP response header + Trusted Types: inline script, eval, innerHTML all blocked', async () => {
    const r = await ctx.page.evaluate(() => {
      const out = {};
      try {
        const s = document.createElement('script');
        s.textContent = 'window.__inline = 1';
        document.body.appendChild(s);
        out.inlineRan = window.__inline === 1;
      } catch (e) { out.inlineRan = false; out.inlineErr = e.name; }
      try { eval('1'); out.eval = 'allowed'; } catch (e) { out.eval = e.name; }
      try { document.body.insertAdjacentHTML('beforeend', '<b>x</b>'); out.html = 'allowed'; } catch (e) { out.html = e.name; }
      try { const d = document.createElement('div'); d.innerHTML = '<img src=x onerror=alert(1)>'; out.innerHTML = 'allowed'; } catch (e) { out.innerHTML = e.name; }
      try { trustedTypes.createPolicy('x', { createHTML: (s) => s }); out.policy = 'allowed'; } catch (e) { out.policy = e.name; }
      return out;
    });
    assert.equal(r.inlineRan, false);
    // (eval is not asserted here: Playwright's CDP Runtime.evaluate context is exempt from
    // CSP's eval check, so it would not reflect page behaviour.)
    assert.equal(r.html, 'TypeError');
    assert.equal(r.innerHTML, 'TypeError');
    assert.notEqual(r.policy, 'allowed');
    const csp = await ctx.app.evaluate(async ({ BrowserWindow }) => {
      const res = await BrowserWindow.getAllWindows()[0].webContents.session.fetch('app://qr/index.html');
      return { status: res.status, csp: res.headers.get('content-security-policy'), nosniff: res.headers.get('x-content-type-options') };
    });
    assert.equal(csp.status, 200);
    assert.match(csp.csp, /default-src 'none'/);
    assert.match(csp.csp, /require-trusted-types-for 'script'/);
    assert.equal(csp.nosniff, 'nosniff');
  });

  test('protocol handler serves only the static map', async () => {
    const r = await ctx.app.evaluate(async ({ BrowserWindow }) => {
      const s = BrowserWindow.getAllWindows()[0].webContents.session;
      const st = async (u) => { try { return (await s.fetch(u)).status; } catch (e) { return String(e.message).slice(0, 60); } };
      return {
        traversal: await st('app://qr/../../main/main.js'),
        encoded: await st('app://qr/%2e%2e/main/main.js'),
        main: await st('app://qr/../main/main.js'),
        dat: await st('app://qr/parsers/data/public_suffix_list.dat'),
        otherHost: await st('app://evil/index.html'),
      };
    });
    assert.equal(r.traversal, 404);
    assert.equal(r.encoded, 404);
    assert.equal(r.main, 404);
    assert.equal(r.dat, 404);
    assert.notEqual(r.otherHost, 200);
  });

  test('network is blocked (renderer fetch, img, WebSocket; main session fetch)', async () => {
    const r = await ctx.page.evaluate(async () => {
      const out = {};
      try { await fetch('https://example.com/'); out.fetch = 'ok'; } catch (e) { out.fetch = e.name; }
      try { await fetch('app://qr/index.html'); out.self = 'ok'; } catch (e) { out.self = e.name; }
      out.img = await new Promise((res) => { const i = new Image(); i.onload = () => res('loaded'); i.onerror = () => res('error'); i.src = 'https://example.com/x.png'; });
      try { const ws = new WebSocket('wss://example.com/'); out.ws = await new Promise((res) => { ws.onopen = () => res('open'); ws.onerror = () => res('error'); }); } catch (e) { out.ws = e.name; }
      return out;
    });
    assert.equal(r.fetch, 'TypeError');
    assert.equal(r.self, 'TypeError'); // connect-src 'none' covers self too
    assert.equal(r.img, 'error');
    assert.notEqual(r.ws, 'open');
    const m = await ctx.app.evaluate(async ({ BrowserWindow, session }) => {
      const res = {};
      for (const [k, s] of [['partition', BrowserWindow.getAllWindows()[0].webContents.session], ['default', session.defaultSession]]) {
        try { await s.fetch('https://example.com/'); res[k] = 'ok'; } catch (e) { res[k] = String(e.message); }
      }
      return res;
    });
    assert.match(m.partition, /ERR_BLOCKED_BY_CLIENT/);
    assert.match(m.default, /ERR_BLOCKED_BY_CLIENT/);
  });

  test('window.open and navigation are blocked', async () => {
    const w = await ctx.page.evaluate(() => window.open('https://example.com/') === null);
    assert.ok(w);
    await ctx.page.evaluate(() => { location.href = 'https://example.com/'; });
    await new Promise((r) => setTimeout(r, 500));
    await ctx.page.evaluate(() => { location.href = 'file:///etc/hosts'; });
    await new Promise((r) => setTimeout(r, 500));
    await ctx.page.evaluate(() => { const a = document.createElement('a'); a.href = 'https://example.com/'; a.target = '_blank'; document.body.append(a); a.click(); a.remove(); });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(ctx.page.url(), 'app://qr/index.html');
    const n = await ctx.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length);
    assert.equal(n, 1);
  });

  test('permission requests are denied', async () => {
    const r = await ctx.page.evaluate(async () => {
      const out = {};
      out.notification = await Notification.requestPermission();
      try { await navigator.mediaDevices.getUserMedia({ video: true }); out.camera = 'granted'; } catch (e) { out.camera = e.name; }
      try { await navigator.mediaDevices.getDisplayMedia({ video: true }); out.screen = 'granted'; } catch (e) { out.screen = e.name; }
      out.geo = await new Promise((res) => navigator.geolocation.getCurrentPosition(() => res('granted'), (e) => res(`denied:${e.code}`)));
      try { await navigator.clipboard.readText(); out.clipboard = 'granted'; } catch (e) { out.clipboard = e.name; }
      return out;
    });
    assert.equal(r.notification, 'denied');
    assert.notEqual(r.camera, 'granted');
    assert.notEqual(r.screen, 'granted');
    assert.match(r.geo, /^denied/);
    assert.notEqual(r.clipboard, 'granted');
  });

  test('IPC from a different window/frame is rejected', async () => {
    await ctx.app.evaluate(({ BrowserWindow }, preload) => {
      const main = BrowserWindow.getAllWindows().find((x) => x.isVisible());
      const w = new BrowserWindow({ show: false, webPreferences: { preload, session: main.webContents.session, sandbox: true, contextIsolation: true } });
      globalThis.__otherWin = w;
      w.loadURL('app://qr/index.html');
    }, `${h.ROOT}/src/preload/preload.js`);
    const other = await h.waitFor(() => ctx.app.windows().find((p) => p !== ctx.page), 10_000, 'second window');
    await other.waitForFunction(() => typeof window.qr === 'object');
    const r = await other.evaluate(async () => {
      try { await window.qr.getSettings(); return 'allowed'; } catch (e) { return String(e.message); }
    });
    assert.match(r, /forbidden/);
    await ctx.app.evaluate(() => { globalThis.__otherWin.destroy(); delete globalThis.__otherWin; });
  });

  test('IPC arguments are validated', async () => {
    const r = await ctx.page.evaluate(async () => {
      const t = async (f) => { try { await f(); return 'ok'; } catch (e) { return e.name || 'Error'; } };
      return {
        notBytes: await t(() => window.qr.decodeImage('abc', { source: 'drop' })),
        badKey: await t(() => window.qr.setSetting('evil', true)),
        badValue: await t(() => window.qr.setSetting('autoScanClipboard', 'yes')),
        badSave: await t(() => window.qr.saveText({ kind: 'exe', text: 'x' })),
        hugeCopy: await t(() => window.qr.copyText('x'.repeat(2 * 1024 * 1024))),
      };
    });
    for (const [k, v] of Object.entries(r)) assert.notEqual(v, 'ok', k);
  });

  test('settings round-trip and menu command delivery', async () => {
    const s0 = await ctx.page.evaluate(() => window.qr.getSettings());
    assert.deepEqual(s0, { autoScanClipboard: false });
    await ctx.page.evaluate(() => { window.__cmds = []; window.qr.onCommand((c) => window.__cmds.push(c)); });
    const s1 = await ctx.page.evaluate(() => window.qr.setSetting('autoScanClipboard', true));
    assert.equal(s1.autoScanClipboard, true);
    const checked = await ctx.app.evaluate(({ Menu }) => Menu.getApplicationMenu().getMenuItemById('auto-scan').checked);
    assert.equal(checked, true);
    await ctx.page.evaluate(() => window.qr.setSetting('autoScanClipboard', false));
    for (const label of ['Clear', 'Copy Primary Result']) await h.clickMenu(ctx.app, label);
    const cmds = await h.waitFor(() => ctx.page.evaluate(() => (window.__cmds.length >= 4 ? window.__cmds : null)), 5000, 'commands');
    assert.deepEqual(cmds, ['settings-changed', 'settings-changed', 'clear', 'copy-primary']);
    const menus = await ctx.app.evaluate(({ Menu }) => Menu.getApplicationMenu().items.map((i) => i.label));
    assert.deepEqual(menus.slice(1), ['File', 'Edit', 'View', 'Window', 'Help']);
  });
});

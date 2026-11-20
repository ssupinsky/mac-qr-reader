#!/usr/bin/env node
// Agent-facing real-app harness. Launches the REAL app (dev Electron binary + project dir)
// via Playwright `_electron`, feeds inputs through the real input paths, and writes
// screenshots + summary.json to verify-output/. See AGENTS.md.
//
//   node scripts/verify.mjs shots                  empty state + fixtures via every input path, light + dark
//   node scripts/verify.mjs scan <file...>         Finder "Open With" path; prints ScanResults + analysis
//   node scripts/verify.mjs open <file...>         File ▸ Open… (dialog stubbed at the boundary only)
//   node scripts/verify.mjs drop <file...>         renderer drop event with real File bytes
//   node scripts/verify.mjs paste-image <file>     image → REAL system clipboard, then Meta+V
//   node scripts/verify.mjs paste-files <file...>  Finder-style file URLs → clipboard, then Meta+V
//   node scripts/verify.mjs paste-text <text>      text → clipboard, then Meta+V
//   node scripts/verify.mjs eval '<js>'            evaluate JS in the renderer (prefix "main:" for main process)
//   node scripts/verify.mjs canary                 scan a unique canary, quit, grep disk for it (must be absent)
// Options: --theme light|dark (default light), --out <dir> (default verify-output), --keep-open <ms>
// The user's clipboard is saved (in memory) before and restored after clipboard commands.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import * as h from '../test/e2e/harness.mjs';

const argv = process.argv.slice(2);
const opt = (name, d) => { const i = argv.indexOf(`--${name}`); if (i < 0) return d; const v = argv[i + 1]; argv.splice(i, 2); return v; };
const theme = opt('theme', 'light');
const OUT = path.resolve(h.ROOT, opt('out', 'verify-output'));
const keepOpen = Number(opt('keep-open', 0));
const [cmd, ...rest] = argv;
fs.mkdirSync(OUT, { recursive: true });

const summary = { command: cmd, args: rest, startedAt: new Date().toISOString(), steps: [], ok: true };
const step = (s) => { summary.steps.push(s); console.log(JSON.stringify(s, null, 2)); };
const abs = (f) => path.resolve(process.cwd(), f);
const slug = (s) => s.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60);

let analyzePayload = null;
try { ({ analyzePayload } = await import(pathToFileURL(path.join(h.ROOT, 'src/renderer/parsers/index.js')).href)); } catch { /* parsers optional */ }

function describe(results) {
  return results.map((r) => {
    const s = h.summarize(r);
    if (analyzePayload) {
      const payloads = r.source.kind === 'text' ? [{ text: r.text, bytesBase64: null, bytesKind: null, symbology: 'text' }] : r.codes;
      s.analysis = payloads.map((c) => {
        try {
          const a = analyzePayload(c);
          return { type: a.type, title: a.title, summary: a.summary, format: a.data?.format, warnings: a.warnings, actions: a.actions.map((x) => `${x.kind}:${x.label}`) };
        } catch (e) { return { error: String(e) }; }
      });
    }
    return s;
  });
}

async function shot(page, name) {
  await h.settle(page);
  const f = await h.screenshot(page, path.join(OUT, `${slug(name)}.png`));
  return path.relative(h.ROOT, f);
}

async function loadVia(ctx, how, files) {
  const { app, page } = ctx;
  switch (how) {
    case 'open-with': return h.openWith(app, files);
    case 'open': return h.openViaDialog(app, files);
    case 'drop': return h.dropFiles(app, page, files);
    case 'paste-image': await h.clipboardSetImage(app, files[0]); return h.pasteKeys(app, page);
    case 'paste-files': await h.clipboardSetFiles(files); return h.pasteKeys(app, page);
    default: throw new Error(`unknown input path ${how}`);
  }
}

async function withApp(fn, { clipboard = false, launchOpts } = {}) {
  const saved = clipboard ? await h.saveClipboard().catch(() => null) : null;
  const ctx = await h.launch(launchOpts);
  const consoleLines = [];
  ctx.page.on('console', (m) => consoleLines.push(`${m.type()}: ${m.text()}`));
  ctx.page.on('pageerror', (e) => consoleLines.push(`pageerror: ${e.message}`));
  try {
    await h.setTheme(ctx.app, ctx.page, theme);
    await fn(ctx);
    if (keepOpen) await new Promise((r) => setTimeout(r, keepOpen));
  } catch (e) {
    summary.ok = false;
    summary.error = String(e?.stack || e);
    console.error(e);
    try { summary.failureShot = await shot(ctx.page, `${cmd}-failure`); } catch { /* ignore */ }
  } finally {
    summary.console = consoleLines.slice(-50);
    await ctx.close();
    if (saved !== null) await h.restoreClipboard(saved).catch((e) => console.error('clipboard restore failed:', e.message));
    else if (clipboard) console.error('note: clipboard could not be saved; it was not restored');
  }
}

async function single(how, files) {
  await withApp(async (ctx) => {
    const results = await loadVia(ctx, how, files);
    step({ input: how, files: files.map((f) => path.basename(f)), results: describe(results), screenshot: await shot(ctx.page, `${how}-${path.basename(files[0] || 'x')}-${theme}`) });
  }, { clipboard: how.startsWith('paste') });
}

const commands = {
  async shots() {
    const plan = [
      ['open-with', ['url.png']],
      ['open', ['wifi.png', 'otpauth.png']],
      ['drop', ['multi-3.png']],
      ['paste-image', ['vcard.png']],
      ['paste-files', ['two-page.pdf', 'not-image.txt']],
      ['drop', ['bidi-zero-width.png']],
      ['open-with', ['url-idn.png', 'epc.png', 'no-code.png']],
    ];
    await withApp(async (ctx) => {
      for (const t of ['light', 'dark']) {
        await h.setTheme(ctx.app, ctx.page, t);
        step({ input: 'empty', theme: t, screenshot: await shot(ctx.page, `00-empty-${t}`) });
      }
      let n = 1;
      for (const [how, names] of plan) {
        const files = names.map(h.fixture);
        await h.setTheme(ctx.app, ctx.page, 'light');
        const results = await loadVia(ctx, how, files);
        const shots = {};
        for (const t of ['light', 'dark']) {
          await h.setTheme(ctx.app, ctx.page, t);
          shots[t] = await shot(ctx.page, `${String(n).padStart(2, '0')}-${how}-${names[0]}-${t}`);
        }
        step({ input: how, files: names, results: describe(results), screenshots: shots });
        n++;
      }
      await h.setTheme(ctx.app, ctx.page, 'system');
    }, { clipboard: true });
  },
  scan: () => single('open-with', rest.map(abs)),
  'open-with': () => single('open-with', rest.map(abs)),
  open: () => single('open', rest.map(abs)),
  drop: () => single('drop', rest.map(abs)),
  'paste-image': () => single('paste-image', [abs(rest[0])]),
  'paste-files': () => single('paste-files', rest.map(abs)),
  async 'paste-text'() {
    await withApp(async (ctx) => {
      await h.clipboardSetText(ctx.app, rest.join(' '));
      const results = await h.pasteKeys(ctx.app, ctx.page);
      step({ input: 'paste-text', results: describe(results), screenshot: await shot(ctx.page, `paste-text-${theme}`) });
    }, { clipboard: true });
  },
  async eval() {
    const code = rest.join(' ');
    await withApp(async (ctx) => {
      let value;
      if (code.startsWith('main:')) {
        // eslint-disable-next-line no-new-func
        value = await ctx.app.evaluate(new Function('electron', `return (async () => { const { app, BrowserWindow, clipboard, session, dialog, shell, nativeTheme, Menu } = electron; return (${code.slice(5)}); })()`));
      } else {
        value = await ctx.page.evaluate(`(async () => (${code}))()`);
      }
      step({ eval: code, value, screenshot: await shot(ctx.page, `eval-${theme}`) });
    });
  },
  async canary() {
    const canary = `QRCANARY${crypto.randomBytes(9).toString('hex').toUpperCase()}`;
    const imgDir = path.join(OUT, 'canary');
    fs.mkdirSync(imgDir, { recursive: true });
    const img = await h.makeQr(`https://example.com/${canary}`, path.join(imgDir, 'canary.png'));
    const marker = path.join(h.tmpDir('qr-canary-'), 'start');
    fs.writeFileSync(marker, '');
    await new Promise((r) => setTimeout(r, 1100)); // mtime granularity
    let userData;
    await withApp(async (ctx) => {
      userData = ctx.userData;
      const results = await h.openWith(ctx.app, [img]);
      const found = results.some((r) => r.codes.some((c) => (c.text || '').includes(canary)));
      if (!found) throw new Error('canary was not decoded');
      // exercise the renderer too (analysis, display) before quitting
      await h.settle(ctx.page, 500);
      step({ input: 'canary scan', decoded: found });
    });
    await new Promise((r) => setTimeout(r, 1000));
    const home = os.homedir();
    const { hits: uniq, scanned, dirs } = await h.findOnDisk(h.canaryNeedles(canary),
      [userData, path.join(home, 'Library/Application Support/QR Reader'), ...h.canaryDirs()], { newerThan: marker, exclude: [imgDir] });
    step({ canary, dirs, filesScanned: scanned, hits: uniq, pass: uniq.length === 0 });
    fs.rmSync(path.dirname(marker), { recursive: true, force: true });
    if (userData && userData.startsWith(fs.realpathSync(os.tmpdir()))) fs.rmSync(userData, { recursive: true, force: true });
    if (uniq.length) summary.ok = false;
  },
};

if (!commands[cmd]) {
  console.error(fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 17).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
  process.exit(2);
}
await commands[cmd]();
summary.finishedAt = new Date().toISOString();
fs.writeFileSync(path.join(OUT, 'summary.json'), JSON.stringify(summary, null, 2));
console.log(`\n${summary.ok ? 'OK' : 'FAILED'} — screenshots and summary.json in ${path.relative(process.cwd(), OUT) || '.'}`);
process.exit(summary.ok ? 0 : 1);

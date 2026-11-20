// Launch helpers for test/e2e-packaged: drives the PACKAGED app, i.e. build/QR Reader (Test).app
// (asar + integrity, fuses, Contents/Resources helper + hash check, sandbox-exec, hardened
// runtime). The test variant differs from build/QR Reader.app only in the inspect fuse and an
// asar-baked marker that lets main accept Playwright's two switches (docs/SECURITY.md §6.6).
// No test hooks: QR_TEST_HOOKS is ignored when packaged. Inputs go through the real paths
// (renderer drop, system clipboard + Meta+V, LaunchServices `open -a`); results are observed by
// wrapping the IPC handlers / push channel from the test side via the inspector (installRecorder),
// so test/e2e/harness.mjs's nextResults/dropFiles/pasteKeys work unchanged.

import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { APP_NAME, appPath, ensureTestVariant, verifyApp } from '../../scripts/build-app.mjs';
import * as h from '../e2e/harness.mjs';

const execFileP = promisify(execFile);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const TEST_APP = appPath('test');
export const PROD_APP = appPath('production');
export const USER_DATA = path.join(os.homedir(), 'Library/Application Support/QR Reader (Test)');
export const exeOf = (bundle) => path.join(bundle, 'Contents/MacOS', APP_NAME);
export const resourcesOf = (bundle) => path.join(fs.realpathSync(bundle), 'Contents/Resources');

let ensured;
/** Builds build/QR Reader (Test).app if its inputs changed (stamp) or it fails verification. */
export function testBundle() {
  ensured ??= ensureTestVariant({ log: (m) => process.stderr.write(`${m}\n`) });
  return ensured;
}

/** The production bundle must exist and verify (fuse wire, no test marker, signature, helper). */
export async function prodBundle() {
  if (!fs.existsSync(PROD_APP)) throw new Error(`${PROD_APP} missing — run ./start.sh --no-open first`);
  return { app: PROD_APP, ...(await verifyApp(PROD_APP)) };
}

/** process.env without anything main refuses or that could steer Electron (the bundle must not need it). */
export function cleanEnv(extra = {}) {
  const env = { ...process.env, ...extra };
  for (const k of Object.keys(env)) {
    if ((k.startsWith('ELECTRON_') || k === 'NODE_OPTIONS' || k.startsWith('DYLD_')) && !(k in extra)) delete env[k];
  }
  return env;
}

/** PIDs whose executable path is exactly the bundle's exe or lives inside the bundle (helpers). */
export async function bundlePids(bundle) {
  const { stdout } = await execFileP('/bin/ps', ['-axo', 'pid=,comm=']);
  const inside = `${bundle}/Contents/`;
  return stdout.split('\n').map((l) => l.match(/^\s*(\d+) (.*)$/)).filter(Boolean)
    .filter((m) => m[2] === exeOf(bundle) || m[2].startsWith(inside)).map((m) => Number(m[1]));
}

export async function killBundle(bundle) {
  for (let i = 0; i < 20; i++) {
    const pids = await bundlePids(bundle);
    if (!pids.length) return;
    for (const p of pids) { try { process.kill(p, i < 10 ? 'SIGTERM' : 'SIGKILL'); } catch { /* gone */ } }
    await sleep(250);
  }
}

export function resetUserData(settings = { autoScanClipboard: false }) {
  fs.rmSync(USER_DATA, { recursive: true, force: true });
  fs.mkdirSync(USER_DATA, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(USER_DATA, 'settings.json'), JSON.stringify(settings));
}

/**
 * Wraps the result-returning ipcMain handlers and the window's push channel so each ScanResult[]
 * lands in globalThis.__qrTestLog ({seq, via, results}) — the shape test/e2e/harness.mjs reads.
 */
export async function installRecorder(app) {
  const ok = await app.evaluate(({ ipcMain, BrowserWindow }) => {
    if (globalThis.__qrTestLog) return 'already';
    const handlers = ipcMain._invokeHandlers; // Electron internal (lib/browser/ipc-main-impl.ts)
    if (!(handlers instanceof Map)) return 'no _invokeHandlers';
    globalThis.__qrTestLog = [];
    globalThis.__qrTestSeq = 0;
    const rec = (via, r) => {
      if (r == null) return;
      globalThis.__qrTestLog.push({ seq: ++globalThis.__qrTestSeq, via, at: Date.now(), results: Array.isArray(r) ? r : [r] });
    };
    for (const ch of ['qr:decode-image', 'qr:paste-from-clipboard', 'qr:open-files']) {
      const orig = handlers.get(ch);
      if (!orig) return `no handler ${ch}`;
      handlers.set(ch, async (...a) => { const r = await orig(...a); rec(ch, r); return r; });
    }
    const wc = BrowserWindow.getAllWindows()[0].webContents;
    const send = wc.send.bind(wc);
    wc.send = (ch, ...a) => { if (ch === 'qr:scan-results') rec('push', a[0]); return send(ch, ...a); };
    return 'ok';
  });
  if (ok !== 'ok') throw new Error(`installRecorder: ${ok}`);
}

/**
 * `_electron.launch({executablePath})` with Playwright 1.64's attach race handled.
 *
 * Without an executablePath Playwright injects `-r loader.js`, which holds back the app's
 * 'ready' until it has attached. A packaged bundle cannot take `-r`, so the app creates its
 * window and navigates to app://qr/index.html while Playwright is still connecting. If
 * Playwright's auto-attach lands after the browser committed that navigation but before the
 * renderer's frame tree shows it, Page.getFrameTree reports url "" (the initial empty page),
 * the real Page.frameNavigated has already been sent (before Page.enable), and Playwright
 * waits forever for "the first non-initial navigation" — launch times out although the app
 * is fully up (observed in ~1 of 10 launches; protocol log
 * shows getFrameTree url "" after the commit). Normal launches take < 3 s, so a launch that saw
 * "DevTools listening" and then stalls for 15 s is this race: kill that instance (it never
 * got a test), and launch again (at most 3 attempts). Any other failure is thrown as-is.
 */
async function launchAttached(bundle, env, settings) {
  const { _electron } = await h.playwright();
  for (let attempt = 1; ; attempt++) {
    await killBundle(bundle);
    resetUserData(settings);
    try {
      return await _electron.launch({ executablePath: exeOf(bundle), env: cleanEnv(env), cwd: '/', timeout: 15_000, colorScheme: null });
    } catch (e) {
      const attachRace = e?.name === 'TimeoutError' && /DevTools listening on ws:/.test(e.message) && /<ws connected> ws:\/\/[^\n]*devtools\/browser/.test(e.message);
      if (!attachRace || attempt >= 3) throw e;
      process.stderr.write(`launchPackaged: Playwright attach race on ${path.basename(bundle)} (page attached mid-navigation); relaunching\n`);
    }
  }
}

/**
 * Launches a packaged bundle with Playwright exactly as `_electron.launch({executablePath})`
 * does (args `--inspect=0 --remote-debugging-port=0`, nothing else). Fresh userData each time.
 */
export async function launchPackaged({ bundle = TEST_APP, env = {}, settings, record = true } = {}) {
  const app = await launchAttached(bundle, env, settings);
  const proc = app.process();
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await Promise.race([app.close().catch(() => {}), sleep(8000)]);
    if (proc && proc.exitCode === null) { try { proc.kill('SIGKILL'); } catch { /* gone */ } }
    await killBundle(bundle);
  };
  try {
    const page = await app.firstWindow();
    await page.waitForLoadState('load');
    await page.waitForFunction(() => typeof window.qr === 'object' && window.qr !== null);
    await h.waitFor(() => app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().some((w) => w.isVisible())), 10_000, 'window visible');
    const hooksBefore = await app.evaluate(() => typeof globalThis.__qrTestLog);
    if (record) await installRecorder(app);
    return { app, page, pid: proc.pid, bundle, hooksBefore, close };
  } catch (e) {
    await close();
    throw e;
  }
}

/** Finder-equivalent "Open With": LaunchServices delivers the files to the running bundle. */
export async function openWithLS(ctx, files, { timeoutMs = 60_000 } = {}) {
  const seq0 = await ctx.app.evaluate(() => globalThis.__qrTestSeq || 0);
  await execFileP('/usr/bin/open', ['-a', ctx.bundle, ...files]);
  return h.waitFor(async () => {
    const log = await ctx.app.evaluate(() => globalThis.__qrTestLog || []);
    const got = log.filter((b) => b.seq > seq0 && b.via === 'push').flatMap((b) => b.results);
    return got.length >= files.length ? got : null;
  }, timeoutMs, `open -a results (${files.length})`);
}

const JXA_SANDBOX_CHECK = `function run(argv) {
  ObjC.bindFunction('sandbox_check', ['int', ['int', 'void *', 'int']]);
  return argv.map((p) => $.sandbox_check(Number(p), null, 0)).join(' ');
}`;
/** sandbox_check(pid, NULL, 0): 1 = sandboxed, 0 = not, -1 = no such process. */
export async function sandboxCheck(pid) {
  const { stdout } = await execFileP('/usr/bin/osascript', ['-l', 'JavaScript', '-e', JXA_SANDBOX_CHECK, String(pid)]);
  return Number(stdout.trim());
}

/**
 * Polls `ps` for child processes of the app's main process while `action` runs. Each new child
 * is recorded with its command line, and the decoder helper is checked with sandbox_check while
 * it is still alive. → {result, children: [{pid, command, sandboxed?}]}
 */
export async function watchChildren(mainPid, action) {
  const seen = new Map();
  const checks = [];
  let stop = false;
  const poll = (async () => {
    while (!stop) {
      const { stdout } = await execFileP('/bin/ps', ['-axo', 'pid=,ppid=,command=']);
      for (const l of stdout.split('\n')) {
        const m = l.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
        // "(name)" / "<defunct>" = exited, not yet reaped (zombie): no command line left to check.
        if (!m || Number(m[2]) !== mainPid || /^\(.*\)$|^<defunct>$/.test(m[3].trim())) continue;
        const pid = Number(m[1]);
        const c = seen.get(pid) ?? { pid, commands: [] };
        if (!c.commands.includes(m[3])) c.commands.push(m[3]);
        seen.set(pid, c);
        if (/\/bin\/qr-decode /.test(m[3]) && !m[3].startsWith('/usr/bin/sandbox-exec') && c.sandboxed === undefined) {
          c.sandboxed = null;
          checks.push(sandboxCheck(pid).then((v) => { c.sandboxed = v; }, () => {}));
        }
      }
      await sleep(15);
    }
  })();
  try {
    const result = await action();
    await sleep(100);
    return { result, children: [...seen.values()] };
  } finally {
    stop = true;
    await poll;
    await Promise.all(checks);
  }
}

/** Runs the bundle's exe directly with args; resolves {alive, code, signal, out} after `ms`. */
export function runExe(bundle, args, { ms = 8000, env = {} } = {}) {
  return new Promise((resolve) => {
    const p = spawn(exeOf(bundle), args, { env: cleanEnv(env), cwd: '/', stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; p.kill('SIGKILL'); resolve({ alive: true, out }); } }, ms);
    p.on('exit', (code, signal) => { if (!done) { done = true; clearTimeout(t); resolve({ alive: false, code, signal, out }); } });
  });
}

/** Copies a bundle into a private temp dir (ditto keeps symlinks/xattrs). → path of the copy. */
export function copyBundle(bundle) {
  const dir = h.tmpDir('qr-packaged-copy-');
  const out = path.join(dir, path.basename(bundle));
  return execFileP('/usr/bin/ditto', [bundle, out]).then(() => out);
}

const LSREGISTER = '/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister';
/** Removes a copied bundle and its LaunchServices registration. */
export async function removeCopy(copy) {
  await killBundle(copy);
  try { await execFileP(LSREGISTER, ['-u', copy]); } catch { /* not registered */ }
  fs.rmSync(path.dirname(copy), { recursive: true, force: true });
}

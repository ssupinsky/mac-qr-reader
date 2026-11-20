'use strict';
// QR Reader — main process entry. See docs/ARCHITECTURE.md and docs/SECURITY.md.

const fs = require('node:fs');
const path = require('node:path');
const { app, BrowserWindow, nativeTheme } = require('electron');
const security = require('./security');
const paths = require('./paths');

// --- before anything else -------------------------------------------------------
security.refuseDebugSwitches();
app.setName('QR Reader');
{
  const devDir = !app.isPackaged && process.env.QR_DEV_USER_DATA;
  // The packaged test variant keeps its own userData so it never touches (or locks) the real app's.
  const name = security.isTestVariant() ? 'QR Reader (Test)' : 'QR Reader';
  app.setPath('userData', devDir && path.isAbsolute(devDir) ? devDir : path.join(app.getPath('appData'), name));
}
if (!app.requestSingleInstanceLock()) {
  app.exit(0);
  return;
}
security.appSwitches();
security.registerScheme();
security.lockDownWebContents();

const settings = require('./settings');
const ipc = require('./ipc');
const menu = require('./menu');
const files = require('./files');
const clip = require('./clipboard');
const decoder = require('./decoder');
const testhooks = require('./testhooks');

let win = null;
let rendererReady = false;
const pendingPushes = []; // ScanResult[] batches waiting for the renderer
const pendingPaths = []; // files from open-file / argv / second-instance
let pathTimer = null;

// --- file intake ------------------------------------------------------------------
function queuePaths(list, kind = 'open-with') {
  for (const p of list) if (typeof p === 'string' && path.isAbsolute(p)) pendingPaths.push({ p, kind });
  if (!app.isReady()) return;
  clearTimeout(pathTimer);
  // Finder sends one open-file event per file; batch them.
  pathTimer = setTimeout(flushPaths, 120);
}

async function flushPaths() {
  if (!pendingPaths.length) return;
  if (!win) createWindow();
  const batch = pendingPaths.splice(0);
  const kind = batch[0].kind;
  const results = await files.scanPaths(batch.map((b) => b.p), kind);
  push(results);
}

function push(results) {
  if (!results || !results.length) return;
  testhooks.record('push', results);
  if (!win || win.isDestroyed() || !rendererReady) { pendingPushes.push(results); return; }
  win.webContents.send('qr:scan-results', results);
}

function sendCommand(cmd) {
  if (win && !win.isDestroyed() && rendererReady) win.webContents.send('qr:command', cmd);
}

/** Dev only: file paths passed on the command line (after the app dir). */
function argvFiles(argv) {
  if (app.isPackaged) return [];
  const rest = argv.slice(1).filter((a) => !a.startsWith('-'));
  if (process.defaultApp && rest.length) rest.shift(); // the app directory / entry script
  return rest.map((a) => path.resolve(a)).filter((a) => {
    try { return fs.statSync(a).isFile(); } catch { return false; }
  });
}

app.on('open-file', (e, p) => { e.preventDefault(); queuePaths([p], 'open-with'); });

app.on('second-instance', (_e, argv) => {
  queuePaths(argvFiles(argv), 'open-with');
  if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
});

// --- window -----------------------------------------------------------------------
function createWindow() {
  rendererReady = false;
  win = new BrowserWindow({
    width: 1100, height: 720, minWidth: 720, minHeight: 480,
    show: false,
    title: 'QR Reader',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 18 },
    vibrancy: 'under-window',
    visualEffectState: 'followWindow',
    backgroundColor: '#00000000',
    transparent: false,
    webPreferences: {
      session: ses,
      preload: paths.preloadPath(),
      sandbox: true, contextIsolation: true,
      nodeIntegration: false, nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false,
      webviewTag: false, webSecurity: true, allowRunningInsecureContent: false,
      experimentalFeatures: false, spellcheck: false, navigateOnDragDrop: false,
      safeDialogs: true, enableWebSQL: false, v8CacheOptions: 'none',
      devTools: !app.isPackaged,
    },
  });
  const wc = win.webContents;
  win.once('ready-to-show', () => win.show());
  wc.on('did-finish-load', () => {
    rendererReady = true;
    for (const batch of pendingPushes.splice(0)) wc.send('qr:scan-results', batch);
  });
  wc.on('render-process-gone', () => { rendererReady = false; });
  win.on('focus', onFocus);
  win.on('closed', () => { win = null; rendererReady = false; });
  wc.loadURL(security.INDEX_URL);
  return win;
}

let focusTimer = null;
function onFocus() {
  if (!settings.get().autoScanClipboard) return;
  clearTimeout(focusTimer);
  focusTimer = setTimeout(async () => {
    const results = await clip.autoScan();
    if (results) push(results);
  }, 150);
}

// --- lifecycle ----------------------------------------------------------------------
let ses;
app.whenReady().then(() => {
  settings.load();
  ses = security.createSession();
  ipc.register(() => win);
  menu.build({ send: sendCommand, getWindow: () => win });
  settings.onChange((s) => { menu.syncAutoScan(s.autoScanClipboard); sendCommand('settings-changed'); });
  app.setAboutPanelOptions({
    applicationName: 'QR Reader',
    applicationVersion: app.getVersion(),
    copyright: 'Personal, offline QR reader',
  });
  nativeTheme.themeSource = 'system';
  decoder.ensureDecoder(); // start the sandboxed self-test early
  createWindow();
  queuePaths(argvFiles(process.argv), 'open-with');
  if (pendingPaths.length) { clearTimeout(pathTimer); pathTimer = setTimeout(flushPaths, 0); }
});

app.on('activate', () => { if (app.isReady() && !win) createWindow(); });
app.on('window-all-closed', () => app.quit());

// Quit promptly (one Cmd+Q / SIGTERM). Only when a sensitive copy may still be on the
// clipboard do we delay quitting, bounded to 400 ms, to clear it (marker check, no read).
let cleanedUp = false;
app.on('before-quit', (e) => {
  if (cleanedUp || !clip.hasPendingSensitive()) return;
  e.preventDefault();
  cleanedUp = true;
  const hard = setTimeout(() => app.exit(0), 1500);
  Promise.race([clip.clearSensitive(), new Promise((r) => setTimeout(r, 400))])
    .finally(() => { clearTimeout(hard); app.quit(); });
});
for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(sig, () => app.quit());

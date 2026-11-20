'use strict';
// Session, app:// protocol, CSP, permissions, network block, navigation/window lockdown,
// startup switch guard. Implements docs/SECURITY.md §5.

const fs = require('node:fs');
const path = require('node:path');
const { app, protocol, session } = require('electron');
const paths = require('./paths');

const ORIGIN = 'app://qr';
const INDEX_URL = `${ORIGIN}/index.html`;
const PARTITION = 'qr-mem'; // no "persist:" → in-memory

const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data: blob:",
  "font-src 'self'", "connect-src 'none'", "media-src 'none'", "object-src 'none'", "frame-src 'none'",
  "child-src 'none'", "worker-src 'none'", "manifest-src 'none'", "form-action 'none'",
  "frame-ancestors 'none'", "base-uri 'none'", "require-trusted-types-for 'script'", "trusted-types 'none'",
].join('; ');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

const BAD_SWITCHES = ['remote-debugging-port', 'remote-debugging-pipe', 'inspect', 'inspect-brk', 'inspect-port',
  'js-flags', 'proxy-server', 'proxy-pac-url', 'host-rules', 'host-resolver-rules', 'ignore-certificate-errors',
  'user-data-dir', 'disable-web-security', 'remote-allow-origins', 'load-extension', 'enable-logging', 'log-file'];

// Electron env vars (docs/api/environment-variables, v45) that turn on logging of internals
// (Chromium logging may include URLs/page data), crash stack dumps, ASAR read logs, or change
// how the app loads. RunAsNode / NODE_OPTIONS are also blocked by fuses; refused anyway.
const BAD_ENV = ['ELECTRON_ENABLE_LOGGING', 'ELECTRON_LOG_FILE', 'ELECTRON_ENABLE_STACK_DUMPING',
  'ELECTRON_LOG_ASAR_READS', 'ELECTRON_NO_ASAR', 'ELECTRON_RUN_AS_NODE', 'ELECTRON_OVERRIDE_DIST_PATH',
  'ELECTRON_DEFAULT_ERROR_MODE', 'NODE_OPTIONS'];
const badEnv = () => Object.keys(process.env).some((k) => BAD_ENV.includes(k) || k.startsWith('ELECTRON_DEBUG'));

// Test variant only (`build-app.mjs --test-variant`, docs/SECURITY.md §6.6): exactly the switches
// Playwright's _electron.launch passes. Decided solely by a marker file inside app.asar (covered by
// the embedded ASAR integrity check); never by env vars or argv. The production bundle has no marker.
const TEST_VARIANT_ARGS = ['--inspect=0', '--remote-debugging-port=0'];
let testVariant;
function isTestVariant() {
  if (testVariant === undefined) {
    testVariant = false;
    if (app.isPackaged) {
      try {
        testVariant = JSON.parse(fs.readFileSync(path.join(__dirname, 'test-variant.json'), 'utf8')).variant === 'test';
      } catch { /* no marker: production */ }
    }
  }
  return testVariant;
}

/** Packaged build only: refuse debug/injection switches (fuses don't cover Chromium switches) and env vars. */
function refuseDebugSwitches() {
  if (!app.isPackaged) return;
  const allowed = isTestVariant() ? TEST_VARIANT_ARGS : [];
  const badSwitch = (s) => app.commandLine.hasSwitch(s) && !allowed.includes(`--${s}=${app.commandLine.getSwitchValue(s)}`);
  if (BAD_SWITCHES.some(badSwitch) || process.argv.slice(1).some((a) => a.startsWith('-') && !allowed.includes(a))
      || badEnv()) {
    app.exit(1);
    process.exit(1);
  }
}

/** Must run before 'ready'. */
function registerScheme() {
  protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true } }]);
}

/** Static map URL path → {abs, mime}, built once from the bundled renderer directory. */
function buildFileMap() {
  const root = paths.rendererDir();
  const map = new Map();
  const walk = (dir, rel) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ent.name.startsWith('.')) continue;
      const abs = path.join(dir, ent.name);
      const r = `${rel}/${ent.name}`;
      if (ent.isDirectory()) walk(abs, r);
      else if (ent.isFile() && MIME[path.extname(ent.name).toLowerCase()]) {
        map.set(r, { abs, mime: MIME[path.extname(ent.name).toLowerCase()] });
      }
    }
  };
  walk(root, '');
  return map;
}

const SECURITY_HEADERS = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
};

function hardenSession(s) {
  s.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  s.setPermissionCheckHandler(() => false);
  s.setDevicePermissionHandler(() => false);
  s.setDisplayMediaRequestHandler((_req, cb) => cb(null));
  s.setSpellCheckerEnabled(false);
  s.setProxy({ mode: 'direct' }).catch(() => {});
  s.webRequest.onBeforeRequest((d, cb) => cb({ cancel: !d.url.startsWith(`${ORIGIN}/`) }));
  s.on('will-download', (e) => e.preventDefault());
}

/** After 'ready': creates the in-memory session with the app:// handler. */
function createSession() {
  const files = buildFileMap();
  const ses = session.fromPartition(PARTITION);
  for (const s of [ses, session.defaultSession]) hardenSession(s);
  ses.protocol.handle('app', (req) => {
    let u;
    try { u = new URL(req.url); } catch { return new Response('Bad request', { status: 400 }); }
    const f = req.method === 'GET' && u.host === 'qr' && files.get(u.pathname);
    if (!f) return new Response('Not found', { status: 404, headers: SECURITY_HEADERS });
    return new Response(fs.readFileSync(f.abs), { headers: { 'content-type': f.mime, ...SECURITY_HEADERS } });
  });
  return ses;
}

/** Global lockdown for every webContents (incl. any created later). */
function lockDownWebContents() {
  app.on('web-contents-created', (_e, wc) => {
    wc.on('will-navigate', (e) => e.preventDefault());
    wc.on('will-frame-navigate', (e) => { if (!(e.isMainFrame && e.url === INDEX_URL)) e.preventDefault(); });
    wc.on('will-redirect', (e) => e.preventDefault());
    wc.on('will-attach-webview', (e) => e.preventDefault());
    wc.setWindowOpenHandler(() => ({ action: 'deny' }));
  });
}

function appSwitches() {
  app.commandLine.appendSwitch('disable-background-networking');
  app.commandLine.appendSwitch('no-proxy-server');
  app.enableSandbox();
}

module.exports = {
  ORIGIN, INDEX_URL, PARTITION, CSP,
  refuseDebugSwitches, isTestVariant, registerScheme, createSession, lockDownWebContents, appSwitches,
};

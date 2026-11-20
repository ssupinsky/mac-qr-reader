#!/usr/bin/env node
// One-stop, idempotent setup (docs/SECURITY.md §3–§7). Every stage is skipped when its
// hash stamp (build/.stamps/<stage>.json) still matches its inputs and outputs.
//   1 environment  macOS/arm64, node, swiftc, refuse env vars that redirect Electron downloads
//   2 npm          package.json pins + lockfile allowlist, then `npm ci` (scripts disabled)
//   3 electron     pinned-SHA-256 zip → /usr/bin/ditto → node_modules/electron/dist (no install.js)
//   4 helper       native/build.sh, then a self-test under sandbox-exec
//   5 icon         native/make-icon.swift → build/icon.icns
//   6 app          scripts/build-app.mjs → build/QR Reader.app
//   7 verify       codesign --deep --strict, entitlements, fuses, asar integrity, packaged helper self-test
// Flags: --dev-only (stages 1–4: what `npm run dev` / tests need), --force (ignore stamps).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { APP_INPUTS, APP_NAME, buildApp, verifyApp } from './build-app.mjs';
import { ROOT, SetupError, bold, dim, green, red, yellow, hashInputs, helperSelfTest, run, sha256File } from './lib/util.mjs';

const ELECTRON = {
  version: '45.2.3',
  zip: 'electron-v45.2.3-darwin-arm64.zip',
  sha256: '4d7c429064087a47b855d9bd06c76ead4819b7f02b385de232d4a5c37ecef55f', // docs/SECURITY.md §4.1
  base: 'https://github.com/electron/electron/releases/download/v45.2.3',
};
const PINS = { electron: '45.2.3', 'playwright-core': '1.64.1' };
const REGISTRY = 'https://registry.npmjs.org/';
const SELF_TEST_TEXT = 'qr-reader-setup-self-test';
const FORBIDDEN_ENV = [
  /^ELECTRON_MIRROR$/i, /^ELECTRON_CUSTOM_/i, /^ELECTRON_OVERRIDE_DIST_PATH$/i, /^ELECTRON_INSTALL_(PLATFORM|ARCH)$/i,
  /^ELECTRON_GET_USE_PROXY$/i, /^ELECTRON_SKIP_BINARY_DOWNLOAD$/i, /^npm_config_electron_/i, /^npm_package_config_electron_/i,
  /^electron_use_remote_checksums$/i, /^electron_config_cache$/i, /^force_no_cache$/i, /^npm_config_(platform|arch)$/i,
  /^NODE_OPTIONS$/, /^DYLD_/,
];

const args = new Set(process.argv.slice(2));
const FORCE = args.has('--force');
const DEV_ONLY = args.has('--dev-only');
const STAMPS = path.join(ROOT, 'build/.stamps');
const rel = (p) => path.relative(ROOT, p);
const t0 = performance.now();

// ---------- stage runner + stamps ----------
async function stage(name, fn) {
  const s = performance.now();
  const note = await fn();
  const ms = performance.now() - s;
  console.log(`${green('✓')} ${name.padEnd(9)} ${note ?? ''} ${dim(`${ms < 1000 ? `${ms.toFixed(0)} ms` : `${(ms / 1000).toFixed(1)} s`}`)}`);
}
const stampFile = (n) => path.join(STAMPS, `${n}.json`);
function readStamp(n) { try { return JSON.parse(fs.readFileSync(stampFile(n), 'utf8')); } catch { return null; } }
function writeStamp(n, inputs, outputs = []) {
  fs.mkdirSync(STAMPS, { recursive: true });
  const o = Object.fromEntries(outputs.map((f) => [f, sha256File(path.join(ROOT, f))]));
  fs.writeFileSync(stampFile(n), JSON.stringify({ inputs, outputs: o, at: new Date().toISOString() }, null, 2) + '\n');
}
function fresh(n, inputs) {
  if (FORCE) return false;
  const s = readStamp(n);
  if (!s || s.inputs !== inputs) return false;
  return Object.entries(s.outputs ?? {}).every(([f, h]) => {
    try { return sha256File(path.join(ROOT, f)) === h; } catch { return false; }
  });
}

// ---------- 1. environment ----------
function checkEnvironment() {
  if (process.platform !== 'darwin') throw new SetupError('QR Reader only builds on macOS.');
  if (process.arch !== 'arm64') throw new SetupError(`Apple-silicon (arm64) node required, got ${process.arch}.`, 'Do not run under Rosetta.');
  const macos = run('/usr/bin/sw_vers', ['-productVersion']).trim();
  if (Number(macos.split('.')[0]) < 14) throw new SetupError(`macOS 14 or newer required (found ${macos}).`);
  const [maj, min] = process.versions.node.split('.').map(Number);
  if (maj < 22 || (maj === 22 && min < 12)) {
    throw new SetupError(`Node >= 22.12 required (running ${process.version}).`, 'Use ./start.sh (it picks fnm + .node-version), or `fnm install 24.18.0`.');
  }
  const bad = Object.keys(process.env).filter((k) => FORBIDDEN_ENV.some((re) => re.test(k)));
  if (bad.length) {
    throw new SetupError(`refusing to run with ${bad.join(', ')} set (they can redirect or alter the Electron binary / inject code).`,
      `Unset them, e.g.: unset ${bad.join(' ')}`);
  }
  const swiftc = (process.env.PATH ?? '').split(':').some((d) => d && fs.existsSync(path.join(d, 'swiftc')));
  if (!swiftc) throw new SetupError('swiftc not found.', 'Install the Command Line Tools: xcode-select --install');
  return dim(`macOS ${macos} arm64, node ${process.versions.node}`);
}

// ---------- 2. npm ----------
function checkLockfile() {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  if (pkg.dependencies && Object.keys(pkg.dependencies).length) throw new SetupError('package.json must have zero runtime dependencies.');
  const dev = pkg.devDependencies ?? {};
  if (JSON.stringify(Object.entries(dev).sort()) !== JSON.stringify(Object.entries(PINS).sort())) {
    throw new SetupError(`devDependencies must be exactly ${JSON.stringify(PINS)}.`, 'See README "Updating Electron safely".');
  }
  for (const k of Object.keys(pkg.scripts ?? {})) {
    if (/^(pre|post)|^(install|prepare|prepublish|prepack|postpack)$/.test(k)) throw new SetupError(`lifecycle script "${k}" not allowed in package.json`);
  }
  const lock = JSON.parse(fs.readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));
  const allow = JSON.parse(fs.readFileSync(path.join(ROOT, 'scripts/lockfile-allowlist.json'), 'utf8'));
  if (lock.lockfileVersion !== 3) throw new SetupError('package-lock.json must be lockfileVersion 3');
  const problems = [];
  const seen = new Set();
  for (const [p, e] of Object.entries(lock.packages ?? {})) {
    if (p === '') continue;
    seen.add(p);
    const a = allow[p];
    if (!a) { problems.push(`${p}: not in allowlist`); continue; }
    if (e.version !== a.version || e.integrity !== a.integrity) problems.push(`${p}: ${e.version} ${e.integrity} ≠ vetted ${a.version}`);
    if (!e.resolved?.startsWith(REGISTRY)) problems.push(`${p}: resolved from ${e.resolved}`);
    if (e.hasInstallScript) problems.push(`${p}: has install scripts`);
    if (e.link) problems.push(`${p}: link entries not allowed`);
  }
  for (const p of Object.keys(allow)) if (!seen.has(p)) problems.push(`${p}: missing from lockfile`);
  if (problems.length) {
    throw new SetupError(`package-lock.json does not match the vetted allowlist:\n  ${problems.join('\n  ')}`,
      'Dependencies change only via the procedure in docs/SECURITY.md §3.5 / README.');
  }
  return seen.size;
}

function npmCli() {
  const cli = path.join(path.dirname(process.execPath), '..', 'lib/node_modules/npm/bin/npm-cli.js');
  return fs.existsSync(cli) ? [process.execPath, [cli]] : ['npm', []];
}

function installDeps() {
  const n = checkLockfile();
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const inputs = hashInputs(ROOT, ['package-lock.json', '.npmrc']) + process.versions.node +
    JSON.stringify([pkg.dependencies, pkg.devDependencies, pkg.engines]); // script edits don't reinstall
  if (fresh('npm', inputs) && fs.existsSync(path.join(ROOT, 'node_modules/.package-lock.json'))) {
    return dim(`${n} vetted packages, up to date`);
  }
  const [cmd, pre] = npmCli();
  const r = spawnSync(cmd, [...pre, 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=error'],
    { cwd: ROOT, encoding: 'utf8', env: process.env });
  if (r.status !== 0) throw new SetupError(`npm ci failed:\n${(r.stderr || r.stdout || r.error?.message || '').trim()}`, 'Check access to https://registry.npmjs.org.');
  const ev = JSON.parse(fs.readFileSync(path.join(ROOT, 'node_modules/electron/package.json'), 'utf8')).version;
  if (ev !== ELECTRON.version) throw new SetupError(`installed electron ${ev}, expected ${ELECTRON.version}`);
  writeStamp('npm', inputs);
  return `npm ci: ${n} vetted packages installed`;
}

// ---------- 3. electron binary ----------
const DIST = path.join(ROOT, 'node_modules/electron/dist');
const MARKER = path.join(DIST, '.verified-sha256');
const MANIFEST = path.join(DIST, '.verified-manifest.json'); // per-file SHA-256 recorded at extraction
const PATH_TXT = 'Electron.app/Contents/MacOS/Electron';

function readOr(f, d = null) { try { return fs.readFileSync(f, 'utf8'); } catch { return d; } }

/** {relPath: sha256 | "link:<target>"} for every file under `dir` except our dot-markers (~0.2 s). */
function manifestOf(dir) {
  const out = {};
  const walk = (rel) => {
    for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (!rel && (r === '.verified-sha256' || r === '.verified-manifest.json')) continue;
      const abs = path.join(dir, r);
      if (e.isSymbolicLink()) out[r] = `link:${fs.readlinkSync(abs)}`;
      else if (e.isDirectory()) walk(r);
      else if (e.isFile()) out[r] = `${fs.statSync(abs).mode & 0o111 ? 'x' : '-'}${sha256File(abs)}`;
      else out[r] = 'special';
    }
  };
  walk('');
  return Object.fromEntries(Object.entries(out).sort(([x], [y]) => (x < y ? -1 : 1)));
}

/** Fast path: dist is exactly what we extracted from the pinned zip (every file re-hashed). */
function distVerified() {
  if (readOr(path.join(DIST, 'version'))?.trim() !== ELECTRON.version) return false;
  if (readOr(path.join(ROOT, 'node_modules/electron/path.txt')) !== PATH_TXT || readOr(MARKER) !== ELECTRON.sha256) return false;
  let rec;
  try { rec = JSON.parse(fs.readFileSync(MANIFEST, 'utf8')); } catch { return false; }
  if (rec?.zipSha256 !== ELECTRON.sha256 || !rec.files) return false;
  try { return JSON.stringify(manifestOf(DIST)) === JSON.stringify(rec.files); } catch { return false; }
}

function ghAuthenticated() {
  const v = spawnSync('gh', ['--version'], { encoding: 'utf8' });
  if (v.error || v.status !== 0) return false;
  return spawnSync('gh', ['auth', 'status'], { encoding: 'utf8' }).status === 0;
}

async function installElectron() {
  const sums = JSON.parse(fs.readFileSync(path.join(ROOT, 'node_modules/electron/checksums.json'), 'utf8'));
  if (sums[ELECTRON.zip] !== ELECTRON.sha256) throw new SetupError(`electron/checksums.json disagrees with the pinned SHA-256 for ${ELECTRON.zip}`);
  if (!FORCE && distVerified()) return dim(`${ELECTRON.version} verified (all dist files re-hashed)`);
  // Same cache location @electron/get uses: ~/Library/Caches/electron/<sha256(url dir)>/<zip>
  const cacheDir = path.join(os.homedir(), 'Library/Caches/electron', crypto.createHash('sha256').update(ELECTRON.base).digest('hex'));
  const cached = path.join(cacheDir, ELECTRON.zip);
  // Everything below works on a copy in a private (0700) temp dir: the file that is hashed is
  // the file that is verified and extracted (no swap between check and use via the cache).
  const priv = fs.mkdtempSync(path.join(os.tmpdir(), 'qr-electron-'));
  try {
    const zip = path.join(priv, ELECTRON.zip);
    let downloaded = false;
    if (fs.existsSync(cached)) {
      fs.copyFileSync(cached, zip);
    } else {
      console.log(dim(`  downloading ${ELECTRON.base}/${ELECTRON.zip} (116 MiB)…`));
      const r = spawnSync('/usr/bin/curl', ['--proto', '=https', '--proto-redir', '=https', '--tlsv1.2', '-fL', '--retry', '2',
        '--progress-bar', '-o', zip, `${ELECTRON.base}/${ELECTRON.zip}`], { stdio: ['ignore', 'inherit', 'inherit'] });
      if (r.status !== 0) throw new SetupError('Electron download failed.', 'Check that github.com is reachable.');
      downloaded = true;
    }
    const h = sha256File(zip);
    if (h !== ELECTRON.sha256) {
      if (!downloaded) fs.rmSync(cached, { force: true });
      throw new SetupError(`${downloaded ? 'downloaded' : 'cached'} ${ELECTRON.zip} has SHA-256 ${h}, pinned ${ELECTRON.sha256} — deleted it; re-run to download again.`);
    }
    if (downloaded) { // populate the cache for next time (the cache copy is never trusted without re-hashing)
      fs.mkdirSync(cacheDir, { recursive: true });
      const t = path.join(cacheDir, `.${ELECTRON.zip}.${process.pid}`);
      fs.copyFileSync(zip, t);
      fs.renameSync(t, cached);
    }
    const extra = [];
    // Independent cross-checks (online). A mismatch is fatal; being offline is not.
    const shas = spawnSync('/usr/bin/curl', ['--proto', '=https', '--proto-redir', '=https', '-fsSL', '--max-time', '15', `${ELECTRON.base}/SHASUMS256.txt`], { encoding: 'utf8' });
    if (shas.status === 0) {
      const line = shas.stdout.split('\n').find((l) => l.endsWith(` *${ELECTRON.zip}`));
      if (!line?.startsWith(ELECTRON.sha256)) throw new SetupError(`GitHub SHASUMS256.txt disagrees with the pinned hash: ${line}`);
      extra.push('SHASUMS256.txt');
    } else extra.push(yellow('SHASUMS256.txt skipped (offline)'));
    // GitHub artifact attestation: required when gh is installed and logged in; otherwise a warning.
    if (ghAuthenticated()) {
      const gh = spawnSync('gh', ['attestation', 'verify', zip, '--repo', 'electron/electron'], { encoding: 'utf8' });
      if (gh.status !== 0) {
        throw new SetupError(`gh attestation verify failed for ${ELECTRON.zip}: ${(gh.stderr || gh.stdout || gh.error?.message || '').trim().split('\n')[0]}`,
          'gh is installed and authenticated, so the attestation is required. Check network access to GitHub, or log out of gh to skip it (not recommended).');
      }
      extra.push('GitHub attestation');
    } else {
      extra.push(yellow('attestation skipped (gh not installed or not authenticated)'));
    }

    fs.rmSync(DIST, { recursive: true, force: true });
    fs.mkdirSync(DIST, { recursive: true });
    run('/usr/bin/ditto', ['-x', '-k', zip, DIST]);
    if (readOr(path.join(DIST, 'version'))?.trim() !== ELECTRON.version) throw new SetupError('extracted Electron has an unexpected version');
    fs.writeFileSync(path.join(ROOT, 'node_modules/electron/path.txt'), PATH_TXT);
    fs.writeFileSync(MANIFEST, JSON.stringify({ zipSha256: ELECTRON.sha256, files: manifestOf(DIST) }) + '\n');
    fs.writeFileSync(MARKER, ELECTRON.sha256);
    return `${ELECTRON.version} ${downloaded ? 'downloaded' : 'from cache'}, SHA-256 pinned ✓, ${extra.join(', ')}`;
  } finally {
    fs.rmSync(priv, { recursive: true, force: true });
  }
}

// ---------- 4. helper ----------
const HELPER = 'build/bin/qr-decode';
const GEN = 'build/bin/gen-fixtures';
const SELF_TEST_PNG = 'build/.stamps/self-test.png';

async function buildHelper() {
  const inputs = hashInputs(ROOT, ['native/qr-decode.swift', 'native/gen-fixtures.swift', 'native/build.sh']);
  let note = dim('up to date');
  if (!fresh('helper', inputs) || !fs.existsSync(path.join(ROOT, SELF_TEST_PNG))) {
    run('/bin/sh', [path.join(ROOT, 'native/build.sh')], { cwd: ROOT });
    fs.mkdirSync(STAMPS, { recursive: true });
    run(path.join(ROOT, GEN), ['one', SELF_TEST_TEXT, path.join(ROOT, SELF_TEST_PNG)]);
    writeStamp('helper', inputs, [HELPER, GEN, SELF_TEST_PNG]);
    note = 'built qr-decode + gen-fixtures';
  }
  const st = await helperSelfTest(path.join(ROOT, HELPER), path.join(ROOT, 'native/qr-decode.sb'), path.join(ROOT, SELF_TEST_PNG), SELF_TEST_TEXT);
  if (st.noise) console.log(yellow(`  warning: helper wrote non-JSON to stdout: ${st.noise}`));
  return `${note}; sandboxed self-test ✓`;
}

// ---------- 5. icon ----------
function buildIcon() {
  const inputs = hashInputs(ROOT, ['native/make-icon.swift']);
  if (fresh('icon', inputs)) return dim('up to date');
  const bin = path.join(ROOT, 'build/bin/make-icon');
  const set = path.join(ROOT, 'build/icon.iconset');
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  run('swiftc', ['-O', '-target', 'arm64-apple-macos14', '-o', bin, path.join(ROOT, 'native/make-icon.swift')]);
  fs.rmSync(set, { recursive: true, force: true });
  run(bin, [set]);
  run('/usr/bin/iconutil', ['-c', 'icns', '-o', path.join(ROOT, 'build/icon.icns'), set]);
  fs.rmSync(set, { recursive: true, force: true });
  writeStamp('icon', inputs, ['build/icon.icns']);
  return 'rendered build/icon.icns';
}

// ---------- 6/7. app + verify ----------
const APP = path.join(ROOT, 'build', `${APP_NAME}.app`);

function buildBundle() {
  const inputs = hashInputs(ROOT, APP_INPUTS);
  if (fresh('app', inputs) && fs.existsSync(APP)) return dim(`${rel(APP)} up to date`);
  fs.rmSync(stampFile('app'), { force: true });
  buildApp({ log: console.log });
  writeStamp('app', inputs);
  return `built ${rel(APP)}`;
}

async function verifyBundle() {
  const opts = { selfTestImage: path.join(ROOT, SELF_TEST_PNG), selfTestText: SELF_TEST_TEXT };
  let v;
  try {
    v = await verifyApp(APP, opts);
  } catch (e) {
    // A stale or tampered bundle is rebuilt once from verified inputs, then must pass.
    console.log(yellow(`  ${e.message} — rebuilding`));
    fs.rmSync(stampFile('app'), { force: true });
    buildBundle();
    v = await verifyApp(APP, opts);
  }
  return `codesign --deep --strict ✓, hardened runtime ✓, fuses ${v.wire} ✓, asar integrity ✓ (${v.asarFiles} files), packaged helper ✓`;
}

// ---------- main ----------
try {
  console.log(bold(`QR Reader setup${DEV_ONLY ? ' (dev)' : ''}`));
  await stage('env', checkEnvironment);
  await stage('npm', installDeps);
  await stage('electron', installElectron);
  await stage('helper', buildHelper);
  if (!DEV_ONLY) {
    await stage('icon', buildIcon);
    await stage('app', buildBundle);
    await stage('verify', verifyBundle);
  }
  console.log(dim(`done in ${((performance.now() - t0) / 1000).toFixed(1)} s`));
} catch (e) {
  console.error(`${red('✗ setup failed:')} ${e.message}`);
  if (e.hint) console.error(`  ${e.hint}`);
  if (!(e instanceof SetupError)) console.error(e.stack);
  process.exit(1);
}

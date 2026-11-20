#!/usr/bin/env node
// Assembles build/QR Reader.app from the verified Electron.app (docs/SECURITY.md §6.3):
// copy (ditto) → rename → Info.plist → app.asar (+ integrity) → helper + profile → icon →
// fuses → hardened-runtime ad-hoc signature → verification.
//   node scripts/build-app.mjs            build (unconditionally) and verify
//   node scripts/build-app.mjs --verify   only verify the existing bundle
//   node scripts/build-app.mjs --smoke    verify, then launch the fused app briefly (quit QR Reader first)
//   node scripts/build-app.mjs --test-variant [--verify]
//        build/verify build/QR Reader (Test).app for test/e2e-packaged (see TEST_VARIANT below)
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { packAsar, readAsarFile, verifyAsar } from './lib/asar.mjs';
import { flipFuses, readFuses } from './lib/fuses.mjs';
import { ROOT, SetupError, run, sha256File, hashInputs, helperSelfTest, dim, green, red } from './lib/util.mjs';

export const APP_NAME = 'QR Reader';
export const BUNDLE_ID = 'local.qr-reader';
export const MIN_MACOS = '14.0';

// Fuse wire after flipping (index order of scripts/lib/fuses.mjs FUSES).
export const FUSE_CONFIG = {
  RunAsNode: false,
  EnableCookieEncryption: true,
  EnableNodeOptionsEnvironmentVariable: false,
  EnableNodeCliInspectArguments: false,
  EnableEmbeddedAsarIntegrityValidation: true,
  OnlyLoadAppFromAsar: true,
  LoadBrowserProcessSpecificV8Snapshot: false,
  GrantFileProtocolExtraPrivileges: false,
  WasmTrapHandlers: true,
};
export const EXPECTED_WIRE = '010011001';
// Generated into app.asar only (never into the repo): SHA-256 of the signed helper and its sandbox
// profile, checked by src/main/paths.js before the helper is used (docs/SECURITY.md §7.2).
export const HELPER_HASHES = 'src/main/helper-hashes.json';
// Test variant (`--test-variant`, used only by test/e2e-packaged): identical to the production
// bundle except (1) the EnableNodeCliInspectArguments fuse stays on and (2) app.asar contains
// TEST_MARKER, which tells src/main/security.js to accept exactly the two switches Playwright
// passes (`--inspect=0 --remote-debugging-port=0`). The marker is covered by the embedded ASAR
// integrity check, so it cannot be added to the production bundle without breaking its header
// hash; the production bundle is verified to contain no marker. Separate name, bundle id and
// userData dir so it never collides with the installed app.
export const TEST_MARKER = 'src/main/test-variant.json';
export const VARIANTS = Object.freeze({
  production: { name: APP_NAME, bundleId: BUNDLE_ID, fuses: FUSE_CONFIG, wire: EXPECTED_WIRE, marker: false, stamp: 'app' },
  test: {
    name: `${APP_NAME} (Test)`, bundleId: `${BUNDLE_ID}.test`,
    fuses: { ...FUSE_CONFIG, EnableNodeCliInspectArguments: true }, wire: '010111001', marker: true, stamp: 'app-test',
  },
});
export const appPath = (variant = 'production', root = ROOT) => path.join(root, 'build', `${VARIANTS[variant].name}.app`);
const ENTITLEMENTS = ['com.apple.security.cs.allow-jit', 'com.apple.security.cs.disable-library-validation'];

/** Everything the bundle is built from (setup.mjs hashes these for the rebuild stamp). */
export const APP_INPUTS = [
  'src', 'package.json', 'build/bin/qr-decode', 'native/qr-decode.sb', 'build/icon.icns',
  'scripts/build-app.mjs', 'scripts/lib/asar.mjs', 'scripts/lib/fuses.mjs', 'scripts/entitlements.plist',
  'node_modules/electron/dist/.verified-sha256',
];

// Only these file types from src/ go into app.asar (no tests, docs, sources of generated data).
const ASAR_EXT = new Set(['.js', '.mjs', '.cjs', '.html', '.css', '.json', '.svg', '.png', '.woff2']);

// Image + PDF types the helper accepts (ARCHITECTURE.md "Formats"); role Viewer, rank Alternate
// → listed in Finder's "Open With" without becoming the default app.
const DOC_TYPES = [
  { CFBundleTypeName: 'Image', CFBundleTypeRole: 'Viewer', LSHandlerRank: 'Alternate',
    LSItemContentTypes: ['public.png', 'public.jpeg', 'com.compuserve.gif', 'public.tiff', 'com.microsoft.bmp',
      'org.webmproject.webp', 'com.microsoft.ico', 'public.heic', 'public.heif', 'public.avif'] },
  { CFBundleTypeName: 'PDF Document', CFBundleTypeRole: 'Viewer', LSHandlerRank: 'Alternate',
    LSItemContentTypes: ['com.adobe.pdf'] },
];

// Keys from Electron's Info.plist we drop: TCC usage strings for devices we never use (without
// them macOS kills the process instead of prompting) and the ATS arbitrary-loads exception.
const DROP_KEYS = ['NSAudioCaptureUsageDescription', 'NSBluetoothAlwaysUsageDescription',
  'NSBluetoothPeripheralUsageDescription', 'NSCameraUsageDescription', 'NSMicrophoneUsageDescription',
  'NSAppTransportSecurity', 'ElectronAsarIntegrity'];

// codesign -d prints to stderr; return both streams.
function codesignOut(args) {
  const r = spawnSync('/usr/bin/codesign', args, { encoding: 'utf8' });
  if (r.status !== 0) throw new SetupError(`codesign ${args.join(' ')} failed: ${r.stderr}`);
  return `${r.stdout}\n${r.stderr}`;
}

const plist = (file) => JSON.parse(run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file]));
const plutil = (file, ...args) => run('/usr/bin/plutil', [...args, file]);

function listSrc(root) {
  const out = [];
  const walk = (rel) => {
    for (const ent of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
      const r = `${rel}/${ent.name}`;
      if (ent.name.startsWith('.')) continue;
      if (ent.isSymbolicLink()) throw new SetupError(`symlink in ${r} is not allowed in the app bundle`);
      if (ent.isDirectory()) walk(r);
      else if (r === TEST_MARKER) throw new SetupError(`${r} must not exist in the source tree (build-app.mjs generates it for the test variant only)`);
      else if (ASAR_EXT.has(path.extname(ent.name)) && !/\.test\.[cm]?js$/.test(ent.name) && r !== HELPER_HASHES) out.push(r);
    }
  };
  walk('src');
  return out.sort();
}

export function buildApp({ root = ROOT, log = console.log, variant = 'production' } = {}) {
  const V = VARIANTS[variant];
  if (!V) throw new SetupError(`unknown variant ${variant}`);
  const dist = path.join(root, 'node_modules/electron/dist/Electron.app');
  const helperSrc = path.join(root, 'build/bin/qr-decode');
  const profileSrc = path.join(root, 'native/qr-decode.sb');
  const icon = path.join(root, 'build/icon.icns');
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const [f, what] of [[dist, 'Electron.app (run setup)'], [helperSrc, 'helper (native/build.sh)'],
    [profileSrc, 'sandbox profile'], [icon, 'icon (run setup)'], [path.join(root, pkg.main), `main entry ${pkg.main}`]]) {
    if (!fs.existsSync(f)) throw new SetupError(`missing ${what}: ${path.relative(root, f)}`);
  }

  const out = appPath(variant, root);
  const tmp = path.join(root, 'build', `.${V.name}.app.tmp`);
  fs.rmSync(tmp, { recursive: true, force: true });
  run('/usr/bin/ditto', [dist, tmp]); // preserves the framework symlinks
  const C = path.join(tmp, 'Contents');
  const R = path.join(C, 'Resources');

  // executable + Info.plist
  fs.renameSync(path.join(C, 'MacOS/Electron'), path.join(C, 'MacOS', APP_NAME));
  fs.rmSync(path.join(R, 'default_app.asar'));
  fs.rmSync(path.join(R, 'electron.icns'));
  fs.copyFileSync(icon, path.join(R, 'icon.icns'));
  const info = path.join(C, 'Info.plist');
  const have = plist(info);
  for (const k of DROP_KEYS) if (k in have) plutil(info, '-remove', k);
  const set = {
    CFBundleName: V.name, CFBundleDisplayName: V.name, CFBundleExecutable: APP_NAME,
    CFBundleIdentifier: V.bundleId, CFBundleIconFile: 'icon.icns',
    CFBundleShortVersionString: pkg.version, CFBundleVersion: pkg.version,
    LSMinimumSystemVersion: MIN_MACOS, LSApplicationCategoryType: 'public.app-category.utilities',
    NSHumanReadableCopyright: 'Personal build. Electron © OpenJS Foundation and contributors.',
  };
  for (const [k, v] of Object.entries(set)) plutil(info, '-replace', k, '-string', v);
  plutil(info, '-replace', 'NSHighResolutionCapable', '-bool', 'YES');
  plutil(info, '-replace', 'CFBundleDocumentTypes', '-json', JSON.stringify(DOC_TYPES));

  // Helper apps keep Electron's "Electron Helper (…).app" names: Electron looks them up by
  // ELECTRON_PRODUCT_NAME first (shell/app/electron_main_delegate_mac.mm). Only ids change.
  for (const [dir, suffix] of [['Electron Helper.app', ''], ['Electron Helper (GPU).app', '.gpu'],
    ['Electron Helper (Renderer).app', '.renderer'], ['Electron Helper (Plugin).app', '.plugin']]) {
    plutil(path.join(C, 'Frameworks', dir, 'Contents/Info.plist'), '-replace', 'CFBundleIdentifier', '-string', `${V.bundleId}.helper${suffix}`);
  }

  // native helper (outside the asar so it can be exec'd) + its sandbox profile
  fs.mkdirSync(path.join(R, 'bin'));
  const helper = path.join(R, 'bin/qr-decode');
  fs.copyFileSync(helperSrc, helper);
  fs.chmodSync(helper, 0o755);
  fs.copyFileSync(profileSrc, path.join(R, 'qr-decode.sb'));
  fs.chmodSync(path.join(R, 'qr-decode.sb'), 0o644);

  // sign the helper now (signing rewrites the binary), so the hash below is of the final file
  run('/usr/bin/codesign', ['--force', '--sign', '-', '--options', 'runtime', '--identifier', `${V.bundleId}.qr-decode`, helper]);
  const helperHashes = { 'bin/qr-decode': sha256File(helper), 'qr-decode.sb': sha256File(path.join(R, 'qr-decode.sb')) };

  // app.asar: src/** + minimal package.json
  const files = listSrc(root);
  const entries = files.map((f) => ({ name: f, data: fs.readFileSync(path.join(root, f)) }));
  const minimalPkg = { name: pkg.name, productName: APP_NAME, version: pkg.version, private: true, main: pkg.main };
  entries.push({ name: HELPER_HASHES, data: Buffer.from(JSON.stringify(helperHashes, null, 2) + '\n') });
  entries.push({ name: 'package.json', data: Buffer.from(JSON.stringify(minimalPkg, null, 2) + '\n') });
  if (V.marker) entries.push({ name: TEST_MARKER, data: Buffer.from(JSON.stringify({ variant: 'test' }) + '\n') });
  const { headerHash, size } = packAsar(path.join(R, 'app.asar'), entries);
  plutil(info, '-replace', 'ElectronAsarIntegrity', '-json',
    JSON.stringify({ 'Resources/app.asar': { algorithm: 'SHA256', hash: headerHash } }));
  log(dim(`    app.asar: ${entries.length} files, ${(size / 1024).toFixed(0)} KiB, header ${headerHash.slice(0, 12)}…`));

  // fuses
  const wire = flipFuses(tmp, V.fuses);
  if (wire !== V.wire) throw new SetupError(`unexpected fuse wire ${wire}`);

  // sign the bundle (helper was signed above; --deep does not reach Resources/bin); signing is last.
  run('/usr/bin/codesign', ['--force', '--deep', '--sign', '-', '--options', 'runtime',
    '--entitlements', path.join(root, 'scripts/entitlements.plist'), tmp]);

  fs.rmSync(out, { recursive: true, force: true });
  fs.renameSync(tmp, out);
  return out;
}

/** Verifies signature, entitlements, fuses, ASAR integrity, plist hygiene and packaged helper. */
export async function verifyApp(app, { root = ROOT, selfTestImage, selfTestText, variant = 'production' } = {}) {
  const V = VARIANTS[variant];
  const C = path.join(app, 'Contents'), R = path.join(C, 'Resources');
  const fail = (m) => { throw new SetupError(`bundle verification failed: ${m}`, 'Re-run ./start.sh (it rebuilds), or `rm -rf build` and retry.'); };
  if (!fs.existsSync(app)) fail('bundle missing');

  // 1. signature (whole bundle, strict) + hardened runtime + exact entitlements
  try { run('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]); } catch (e) { fail(`codesign: ${e.message}`); }
  for (const target of [app, path.join(R, 'bin/qr-decode')]) {
    const d = codesignOut(['-dv', target]);
    if (!/flags=0x\w+\([^)]*runtime[^)]*\)/.test(d)) fail(`${path.basename(target)} lacks hardened runtime`);
  }
  const ent = codesignOut(['-d', '--entitlements', '-', '--xml', app]);
  const keys = [...ent.matchAll(/<key>([^<]+)<\/key>/g)].map((m) => m[1]).sort();
  if (keys.join() !== [...ENTITLEMENTS].sort().join()) fail(`unexpected entitlements: ${keys.join(', ') || '(none)'}`);

  // 2. fuses
  const wire = readFuses(app);
  if (wire !== V.wire) fail(`fuse wire ${wire}, expected ${V.wire}`);

  // 3. ASAR integrity: Info.plist hash == header hash, every file matches its embedded hash
  const info = plist(path.join(C, 'Info.plist'));
  const integ = info.ElectronAsarIntegrity ?? {};
  if (Object.keys(integ).join() !== 'Resources/app.asar') fail(`ElectronAsarIntegrity keys: ${Object.keys(integ).join()}`);
  const a = verifyAsar(path.join(R, 'app.asar'));
  if (a.problems.length) fail(`app.asar: ${a.problems.join('; ')}`);
  if (integ['Resources/app.asar'].algorithm !== 'SHA256' || integ['Resources/app.asar'].hash !== a.headerHash) {
    fail('app.asar header hash does not match Info.plist');
  }

  // 4. plist + layout hygiene
  if (info.CFBundleExecutable !== APP_NAME || info.CFBundleIdentifier !== V.bundleId || info.CFBundleName !== V.name) fail('bundle name/id');
  let hasMarker = true;
  try { readAsarFile(path.join(R, 'app.asar'), TEST_MARKER); } catch { hasMarker = false; }
  if (hasMarker !== V.marker) fail(V.marker ? `test marker ${TEST_MARKER} missing` : `${TEST_MARKER} must not be in the production app.asar`);
  const usage = Object.keys(info).filter((k) => /UsageDescription$/.test(k) || k === 'NSAppTransportSecurity');
  if (usage.length) fail(`unexpected Info.plist keys: ${usage.join(', ')}`);
  for (const bad of ['default_app.asar', 'app', 'app.asar.unpacked']) {
    if (fs.existsSync(path.join(R, bad))) fail(`unexpected Resources/${bad}`);
  }

  // 5. packaged helper matches the build and works under its sandbox profile
  if (fs.existsSync(path.join(root, 'native/qr-decode.sb')) &&
      sha256File(path.join(R, 'qr-decode.sb')) !== sha256File(path.join(root, 'native/qr-decode.sb'))) {
    fail('packaged sandbox profile differs from native/qr-decode.sb');
  }
  let hh;
  try { hh = JSON.parse(readAsarFile(path.join(R, 'app.asar'), HELPER_HASHES).toString('utf8')); } catch (e) { fail(`helper hashes: ${e.message}`); }
  for (const [f, h] of Object.entries({ 'bin/qr-decode': hh['bin/qr-decode'], 'qr-decode.sb': hh['qr-decode.sb'] })) {
    if (typeof h !== 'string' || sha256File(path.join(R, f)) !== h) fail(`Resources/${f} does not match ${HELPER_HASHES} in app.asar`);
  }
  if (selfTestImage) await helperSelfTest(path.join(R, 'bin/qr-decode'), path.join(R, 'qr-decode.sb'), selfTestImage, selfTestText);
  return { wire, asarFiles: a.files, headerHash: a.headerHash };
}

/** Launch the fused binary: must stay up ~3 s normally and exit non-zero on debug switches. */
export async function smokeTest(app) {
  const exe = path.join(app, 'Contents/MacOS', APP_NAME);
  const launch = (args, ms) => new Promise((resolve) => {
    const p = spawn(exe, args, { stdio: 'ignore' });
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; p.kill('SIGTERM'); resolve({ alive: true }); } }, ms);
    p.on('exit', (code, signal) => { if (!done) { done = true; clearTimeout(t); resolve({ alive: false, code, signal }); } });
  });
  const results = {};
  results.normal = await launch([], 3000);
  for (const sw of ['--remote-debugging-port=0', '--inspect=0']) {
    await new Promise((r) => setTimeout(r, 800));
    results[sw] = await launch([sw], 5000);
  }
  return results;
}

/**
 * Test variant for test/e2e-packaged: rebuilds build/QR Reader (Test).app only when APP_INPUTS
 * changed since its stamp (build/.stamps/app-test.json) or it fails verification. → bundle path.
 */
export async function ensureTestVariant({ root = ROOT, log = console.log, force = false } = {}) {
  const app = appPath('test', root);
  const stamp = path.join(root, 'build/.stamps', `${VARIANTS.test.stamp}.json`);
  const inputs = hashInputs(root, APP_INPUTS);
  let have = null;
  try { have = JSON.parse(fs.readFileSync(stamp, 'utf8')).inputs; } catch { /* none */ }
  if (!force && have === inputs && fs.existsSync(app)) {
    try { await verifyApp(app, { root, variant: 'test' }); return app; } catch (e) { log(dim(`    ${e.message} — rebuilding`)); }
  }
  fs.rmSync(stamp, { force: true });
  log(`Building ${path.relative(root, app)}…`);
  buildApp({ root, log, variant: 'test' });
  await verifyApp(app, { root, variant: 'test' });
  fs.mkdirSync(path.dirname(stamp), { recursive: true });
  fs.writeFileSync(stamp, JSON.stringify({ inputs, at: new Date().toISOString() }, null, 2) + '\n');
  return app;
}

async function main() {
  const args = process.argv.slice(2);
  const variant = args.includes('--test-variant') ? 'test' : 'production';
  const app = appPath(variant);
  try {
    if (!args.includes('--verify') && !args.includes('--smoke')) {
      if (variant === 'test') await ensureTestVariant({ force: true });
      else { console.log(`Building ${path.relative(ROOT, app)}…`); buildApp(); }
    }
    const v = await verifyApp(app, { variant });
    console.log(green(`✓ ${path.relative(ROOT, app)}: signature, entitlements, fuses ${v.wire}, asar integrity (${v.asarFiles} files)`));
    if (args.includes('--smoke')) {
      if (variant === 'test') throw new SetupError('--smoke applies to the production bundle only');
      const r = await smokeTest(app);
      const ok = r.normal.alive && !r['--remote-debugging-port=0'].alive && r['--remote-debugging-port=0'].code !== 0 &&
        !r['--inspect=0'].alive && r['--inspect=0'].code !== 0;
      console.log(JSON.stringify(r));
      console.log(ok ? green('✓ smoke test passed') : red('✗ smoke test failed'));
      if (!ok) process.exitCode = 1;
    }
  } catch (e) {
    console.error(red(`✗ ${e.message}`));
    if (e.hint) console.error(e.hint);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();

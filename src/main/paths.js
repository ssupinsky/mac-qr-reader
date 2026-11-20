'use strict';
// Resource paths for dev (unpackaged Electron.app + project dir) vs packaged
// (build/QR Reader.app). See docs/ARCHITECTURE.md "Runtime paths".

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { app } = require('electron');

const SRC_DIR = path.resolve(__dirname, '..'); // .../src (inside app.asar when packaged)
const PROJECT_DIR = path.resolve(SRC_DIR, '..'); // dev only: repo root

const isPackaged = () => app.isPackaged;

const rendererDir = () => path.join(SRC_DIR, 'renderer');
const preloadPath = () => path.join(SRC_DIR, 'preload', 'preload.js');

function helperCandidates() {
  if (isPackaged()) {
    const res = process.resourcesPath;
    return {
      helper: [path.join(res, 'bin', 'qr-decode')],
      profile: [path.join(res, 'qr-decode.sb'), path.join(res, 'bin', 'qr-decode.sb')],
    };
  }
  return {
    helper: [path.join(PROJECT_DIR, 'build', 'bin', 'qr-decode')],
    profile: [path.join(PROJECT_DIR, 'native', 'qr-decode.sb')],
  };
}

function firstRealFile(list) {
  for (const p of list) {
    try {
      const real = fs.realpathSync(p);
      if (fs.statSync(real).isFile()) return real;
    } catch { /* try next */ }
  }
  return null;
}

/** → { helper, helperDir, profile } with canonical paths, or { error } if missing. */
function resolveHelper() {
  const c = helperCandidates();
  const helper = firstRealFile(c.helper);
  const profile = firstRealFile(c.profile);
  if (!helper) return { error: `decoder helper not found (expected ${c.helper[0]})` };
  if (!profile) return { error: `sandbox profile not found (expected ${c.profile[0]})` };
  try {
    fs.accessSync(helper, fs.constants.X_OK);
  } catch {
    return { error: 'decoder helper is not executable' };
  }
  const loc = { helper, helperDir: path.dirname(helper), profile };
  const bad = verifyHelper(loc);
  return bad ? { error: bad } : loc;
}

const sha256 = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

/**
 * Packaged build: the helper and its sandbox profile must match the SHA-256s that
 * scripts/build-app.mjs wrote into app.asar (src/main/helper-hashes.json, covered by the
 * embedded ASAR integrity check). → null if OK, else an error message (fail closed).
 * Dev runs (unpackaged) use the freshly built build/bin/qr-decode + native/qr-decode.sb
 * directly; there is no recorded hash to compare against, so the check is skipped.
 */
function verifyHelper(loc, record = path.join(__dirname, 'helper-hashes.json')) {
  if (!isPackaged()) return null;
  let want;
  try {
    want = JSON.parse(fs.readFileSync(record, 'utf8')); // inside app.asar when packaged
    if (!want || typeof want !== 'object') throw new Error('bad record');
  } catch {
    return 'helper integrity record missing from the app bundle';
  }
  try {
    if (typeof want['bin/qr-decode'] !== 'string' || sha256(loc.helper) !== want['bin/qr-decode']) {
      return 'decoder helper does not match the app bundle (modified?)';
    }
    if (typeof want['qr-decode.sb'] !== 'string' || sha256(loc.profile) !== want['qr-decode.sb']) {
      return 'sandbox profile does not match the app bundle (modified?)';
    }
  } catch {
    return 'could not read the decoder helper';
  }
  return null;
}

module.exports = { SRC_DIR, PROJECT_DIR, isPackaged, rendererDir, preloadPath, resolveHelper, verifyHelper };

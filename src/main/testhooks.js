'use strict';
// Dev-only observation hook for scripts/verify.mjs and test/e2e (Playwright reads
// globalThis.__qrTestLog via electronApp.evaluate). Active only when the app is NOT
// packaged AND QR_TEST_HOOKS=1; otherwise record() is a no-op and nothing is retained.

const { app } = require('electron');

const MAX_BATCHES = 50;
const enabled = !app.isPackaged && process.env.QR_TEST_HOOKS === '1';
if (enabled) { globalThis.__qrTestLog = []; globalThis.__qrTestSeq = 0; }

/** @param {string} via  e.g. 'qr:open-files', 'push' */
function record(via, results) {
  if (!enabled || !Array.isArray(results)) return;
  const log = globalThis.__qrTestLog;
  log.push({ seq: ++globalThis.__qrTestSeq, via, at: Date.now(), results });
  if (log.length > MAX_BATCHES) log.splice(0, log.length - MAX_BATCHES);
}

module.exports = { record, enabled };

// "Nothing decoded is ever written to disk": runs `verify.mjs canary` (scan a unique canary,
// quit, grep userData, ~/Library/{Application Support,Caches,Preferences,Saved Application
// State} and $TMPDIR for it and its base64).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import * as h from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); });
after(() => release?.());

test('canary payload never reaches the disk', { timeout: 300_000 }, async () => {
  const out = h.tmpDir('qr-canary-out-');
  try {
    const code = await new Promise((res) => {
      execFile(process.execPath, [path.join(h.ROOT, 'scripts/verify.mjs'), 'canary', '--out', out],
        { cwd: h.ROOT, maxBuffer: 64 * 1024 * 1024 }, (err) => res(err ? err.code : 0));
    });
    const summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json'), 'utf8'));
    const res = summary.steps.find((s) => 'hits' in s);
    assert.ok(summary.steps.some((s) => s.decoded === true), 'canary was decoded');
    assert.ok(res && res.filesScanned >= 0);
    assert.deepEqual(res.hits, []);
    assert.equal(code, 0);
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

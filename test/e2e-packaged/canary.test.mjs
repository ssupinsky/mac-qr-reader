// "Nothing decoded is ever written to disk", for the packaged app: scan a unique canary via
// Open With and via paste, quit, then grep the bundle's userData dir, ~/Library/{Application
// Support,Caches,Saved Application State,Preferences}, $TMPDIR and the bundle itself.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as h from '../e2e/harness.mjs';
import * as p from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); await p.testBundle(); });
after(() => release?.());

test('canary payload never reaches the disk (packaged)', { timeout: 300_000 }, async () => {
  const canary = `QRCANARY${crypto.randomBytes(9).toString('hex').toUpperCase()}`;
  const imgDir = h.tmpDir('qr-canary-img-');
  const markerDir = h.tmpDir('qr-canary-');
  const marker = path.join(markerDir, 'start');
  const saved = await h.saveClipboard();
  try {
    const img = await h.makeQr(`https://example.com/${canary}`, path.join(imgDir, 'canary.png'));
    const img2 = await h.makeQr(`WIFI:T:WPA;S:${canary};P:${canary};;`, path.join(imgDir, 'canary2.png'));
    fs.writeFileSync(marker, '');
    await new Promise((r) => setTimeout(r, 1100)); // mtime granularity
    const ctx = await p.launchPackaged();
    try {
      const r1 = await p.openWithLS(ctx, [img]);
      assert.ok(r1[0].codes.some((c) => c.text.includes(canary)), 'canary decoded (open-with)');
      await h.clipboardSetImage(ctx.app, img2);
      const r2 = await h.pasteKeys(ctx.app, ctx.page);
      assert.ok(r2[0].codes.some((c) => c.text.includes(canary)), 'canary decoded (paste)');
      await h.waitFor(() => ctx.page.evaluate((c) => document.body.textContent.includes(c), canary), 10_000, 'canary rendered');
      await h.settle(ctx.page, 500);
    } finally {
      await h.restoreClipboard(saved);
      await ctx.close();
    }
    await new Promise((r) => setTimeout(r, 1000));
    assert.ok(fs.existsSync(p.USER_DATA), 'the packaged userData dir exists');
    const { hits, scanned, dirs } = await h.findOnDisk(h.canaryNeedles(canary),
      [p.USER_DATA, ...h.canaryDirs(), p.TEST_APP], { newerThan: marker, exclude: [imgDir] });
    assert.ok(dirs.includes(p.USER_DATA));
    assert.ok(scanned >= 0);
    assert.deepEqual(hits, []);
  } finally {
    fs.rmSync(imgDir, { recursive: true, force: true });
    fs.rmSync(markerDir, { recursive: true, force: true });
  }
});

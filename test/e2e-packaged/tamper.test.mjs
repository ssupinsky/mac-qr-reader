// Tampering with a COPY of the test variant (in a temp dir): a modified helper or sandbox profile
// must switch the decoder off (decoder_unavailable in the UI, no helper ever spawned), and a
// modified app.asar must stop the app at launch (embedded ASAR integrity).
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as h from '../e2e/harness.mjs';
import * as p from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); await p.testBundle(); });
after(() => release?.());

async function expectDecoderOff(copy, why) {
  const ctx = await p.launchPackaged({ bundle: copy });
  try {
    const { result: r, children } = await p.watchChildren(ctx.pid, () => h.dropFiles(ctx.app, ctx.page, [h.fixture('url.png')]));
    assert.equal(r.length, 1);
    assert.equal(r[0].ok, false);
    assert.equal(r[0].error.code, 'decoder_unavailable');
    assert.match(r[0].error.message, why);
    assert.deepEqual(children.filter((c) => c.commands.some((cmd) => /qr-decode/.test(cmd))), [], 'no helper may run');
    await h.waitFor(() => ctx.page.evaluate(() => document.querySelector('[data-testid="error"]')?.textContent.includes('The scanner is switched off')),
      10_000, 'decoder_unavailable state shown');
    // pasted text still works without the decoder
    const saved = await h.saveClipboard();
    try {
      await h.clipboardSetText(ctx.app, 'plain pasted text');
      const t = await h.pasteKeys(ctx.app, ctx.page);
      assert.equal(t[0].ok, true);
    } finally { await h.restoreClipboard(saved); }
  } finally {
    await ctx.close();
  }
}

describe('tampered copies of the packaged app', { timeout: 300_000 }, () => {
  test('modified sandbox profile → decoder_unavailable', async () => {
    const copy = await p.copyBundle(p.TEST_APP);
    try {
      fs.appendFileSync(path.join(copy, 'Contents/Resources/qr-decode.sb'), '\n(allow network*)\n');
      await expectDecoderOff(copy, /sandbox profile does not match/);
    } finally { await p.removeCopy(copy); }
  });

  test('modified helper binary → decoder_unavailable', async () => {
    const copy = await p.copyBundle(p.TEST_APP);
    try {
      fs.appendFileSync(path.join(copy, 'Contents/Resources/bin/qr-decode'), Buffer.from([0]));
      await expectDecoderOff(copy, /decoder helper does not match/);
    } finally { await p.removeCopy(copy); }
  });

  test('helper replaced by a symlink to the dev build → decoder_unavailable', async () => {
    const copy = await p.copyBundle(p.TEST_APP);
    try {
      const helper = path.join(copy, 'Contents/Resources/bin/qr-decode');
      fs.rmSync(helper);
      fs.symlinkSync(path.join(h.ROOT, 'build/bin/qr-decode'), helper);
      await expectDecoderOff(copy, /decoder helper does not match/);
    } finally { await p.removeCopy(copy); }
  });

  test('one byte of app.asar changed → the app does not start', async () => {
    const copy = await p.copyBundle(p.TEST_APP);
    try {
      const asar = path.join(copy, 'Contents/Resources/app.asar');
      const buf = fs.readFileSync(asar);
      const at = buf.indexOf(Buffer.from("security.refuseDebugSwitches();"));
      assert.ok(at > 0);
      buf[at] = 'S'.charCodeAt(0);
      fs.writeFileSync(asar, buf);
      const r = await p.runExe(copy, [], { ms: 10_000 });
      assert.equal(r.alive, false, 'tampered app kept running');
      assert.ok(r.code !== 0 || r.signal, `exit ${r.code} ${r.signal}`);
      assert.match(r.out, /Integrity|integrity/);
      assert.deepEqual(await p.bundlePids(copy), []);
    } finally { await p.removeCopy(copy); }
  });
});

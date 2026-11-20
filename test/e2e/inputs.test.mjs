// Every non-clipboard input path against the real app: Finder "Open With" (open-file),
// File ▸ Open… (dialog stubbed at the boundary), renderer drop events, argv files,
// single-instance forwarding, and the fail-closed decoder.
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import * as h from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); });
after(() => release?.());

describe('input paths', () => {
  let ctx;
  before(async () => { ctx = await h.launch(); });
  after(async () => { await ctx?.close(); });

  test('Finder "Open With": every fixture decodes as the manifest expects', async () => {
    const fixtures = h.manifest();
    const results = await h.openWith(ctx.app, fixtures.map((f) => h.fixture(f.file)));
    assert.equal(results.length, fixtures.length);
    fixtures.forEach((fx, i) => h.checkAgainstManifest(fx, results[i]));
    for (const r of results) {
      assert.equal(r.source.kind, 'open-with');
      assert.match(r.id, /^[0-9a-f]{24}$/);
      assert.ok(!JSON.stringify(r).includes(h.FIXTURES), 'no filesystem paths reach the renderer');
    }
    // the renderer received the same batch
    await h.settle(ctx.page);
  });

  test('File ▸ Open… with multiple files (incl. an error) and cancel', async () => {
    const files = ['url.png', 'two-page.pdf', 'image.svg'].map(h.fixture);
    const r = await h.openViaDialog(ctx.app, files);
    assert.deepEqual(r.map((x) => [x.source.kind, x.source.name, x.ok]), [['file', 'url.png', true], ['file', 'two-page.pdf', true], ['file', 'image.svg', false]]);
    assert.equal(r[1].codes[0].text, 'https://example.com/pdf-page-2');
    assert.equal(r[1].codes[0].page, 1);
    assert.equal(r[2].error.code, 'unsupported_format');
    // cancel → []
    await ctx.app.evaluate(({ dialog }) => { globalThis.__o = dialog.showOpenDialog; dialog.showOpenDialog = async () => ({ canceled: true, filePaths: [] }); });
    const none = await ctx.page.evaluate(() => window.qr.openFiles());
    await ctx.app.evaluate(({ dialog }) => { dialog.showOpenDialog = globalThis.__o; });
    assert.deepEqual(none, []);
  });

  test('drop: multiple files with real bytes, errors reported per file', async () => {
    const files = ['multi-3.png', 'webp.webp', 'empty.bin', 'not-image.txt'].map(h.fixture);
    const r = await h.dropFiles(ctx.app, ctx.page, files);
    assert.deepEqual(r.map((x) => [x.source.kind, x.source.name, x.ok, x.error?.code]),
      [['drop', 'multi-3.png', true, undefined], ['drop', 'webp.webp', true, undefined],
        ['drop', 'empty.bin', false, 'empty_input'], ['drop', 'not-image.txt', false, 'unsupported_format']]);
    assert.deepEqual(r[0].codes.map((c) => c.text), ['https://example.com/one', 'SECOND code', 'WIFI:T:WPA;S:Third;P:secret;;']);
  });

  test('directories and missing files yield error results', async () => {
    const r = await h.openWith(ctx.app, [h.FIXTURES, path.join(h.FIXTURES, 'does-not-exist.png')]);
    assert.deepEqual(r.map((x) => x.ok), [false, false]);
    assert.equal(r[0].error.code, 'unsupported_format');
    assert.equal(r[1].error.code, 'read_error');
  });

  test('single-instance lock: a second launch forwards its files and exits', async () => {
    const seq0 = await ctx.app.evaluate(() => globalThis.__qrTestSeq);
    const env = { ...process.env, QR_DEV_USER_DATA: ctx.userData };
    for (const k of Object.keys(env)) if (k.startsWith('ELECTRON_')) delete env[k];
    const p = spawn(h.electronPath(), [h.ROOT, h.fixture('tel.png')], { env, stdio: 'ignore' });
    const code = await new Promise((res) => { const t = setTimeout(() => { p.kill('SIGKILL'); res('timeout'); }, 20_000); p.on('exit', (c) => { clearTimeout(t); res(c); }); });
    assert.equal(code, 0);
    const r = await h.waitFor(async () => {
      const log = await ctx.app.evaluate(() => globalThis.__qrTestLog);
      return log.find((b) => b.seq > seq0 && b.via === 'push')?.results;
    }, 20_000, 'forwarded file');
    assert.equal(r[0].source.name, 'tel.png');
    assert.equal(r[0].codes[0].text, 'tel:+1-555-123-4567');
  });
});

describe('argv files (dev)', () => {
  test('files passed on the command line are scanned at startup', async () => {
    const ctx = await h.launch({ files: [h.fixture('geo.png'), h.fixture('aztec.png')] });
    try {
      const r = await h.waitFor(async () => {
        const log = await ctx.app.evaluate(() => globalThis.__qrTestLog);
        return log.find((b) => b.via === 'push')?.results;
      }, 20_000, 'argv results');
      assert.deepEqual(r.map((x) => [x.source.kind, x.source.name, x.codes[0]?.symbology]), [['open-with', 'geo.png', 'QR'], ['open-with', 'aztec.png', 'Aztec']]);
    } finally { await ctx.close(); }
  });
});

describe('fail-closed decoder', () => {
  // Launch a copy of the app whose helper/profile is missing or broken: scans must fail with
  // decoder_unavailable and the helper must never run unsandboxed.
  function makeCopy(variant) {
    const dir = h.tmpDir('qr-copy-');
    fs.cpSync(path.join(h.ROOT, 'src'), path.join(dir, 'src'), { recursive: true });
    fs.copyFileSync(path.join(h.ROOT, 'package.json'), path.join(dir, 'package.json'));
    if (variant === 'broken-profile') {
      fs.mkdirSync(path.join(dir, 'build/bin'), { recursive: true });
      fs.copyFileSync(path.join(h.ROOT, 'build/bin/qr-decode'), path.join(dir, 'build/bin/qr-decode'));
      fs.chmodSync(path.join(dir, 'build/bin/qr-decode'), 0o755);
      fs.mkdirSync(path.join(dir, 'native'));
      fs.writeFileSync(path.join(dir, 'native/qr-decode.sb'), '(version 1)\n(deny default)\n');
    }
    return dir;
  }
  for (const variant of ['missing-helper', 'broken-profile']) {
    test(variant, async () => {
      const dir = makeCopy(variant);
      const ctx = await h.launch({ appDir: dir });
      try {
        const r = await h.openWith(ctx.app, [h.fixture('url.png')]);
        assert.equal(r[0].ok, false);
        assert.equal(r[0].error.code, 'decoder_unavailable');
        assert.match(r[0].error.message, /never decoded outside the sandbox/);
      } finally {
        await ctx.close();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

// Runs the native qr-decode helper against the generated fixtures (test/fixtures/manifest.json).
//   fnm exec --using=24.18.0 node --test test/native/
// Prereqs: native/build.sh (builds build/bin/qr-decode + gen-fixtures and regenerates fixtures).
// If native/qr-decode.sb exists, the fixture suite is repeated under sandbox-exec.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const helper = path.join(root, 'build/bin/qr-decode');
const genFixtures = path.join(root, 'build/bin/gen-fixtures');
const fixturesDir = path.join(root, 'test/fixtures');
const manifestPath = path.join(fixturesDir, 'manifest.json');
const sandboxProfile = path.join(root, 'native/qr-decode.sb');

function ensureBuilt() {
  if (!existsSync(helper) || !existsSync(genFixtures) || !existsSync(manifestPath)) {
    execFileSync(path.join(root, 'native/build.sh'), ['--fixtures'], { cwd: root, stdio: 'inherit' });
  }
}

/** Run the helper with `input` on stdin. Resolves {code, stdout, stderr, ms, json}. */
function run(input, args = [], { sandbox = false, timeoutMs = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const cmd = sandbox ? '/usr/bin/sandbox-exec' : helper;
    const real = realpathSync(helper);
    // The profile expects symlink-resolved paths (see docs/SECURITY.md); cwd '/' mirrors the app.
    const argv = sandbox ? ['-f', sandboxProfile, '-D', `HELPER=${real}`, '-D', `HELPER_DIR=${path.dirname(real)}`, real, ...args] : args;
    const t0 = performance.now();
    const child = spawn(cmd, argv, { stdio: ['pipe', 'pipe', 'pipe'], cwd: sandbox ? '/' : undefined });
    const out = [];
    const err = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.stdin.on('error', () => {}); // EPIPE when the helper stops reading early (too_large)
    child.on('error', reject);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString('utf8');
      const r = { code, signal, stdout, stderr: Buffer.concat(err).toString('utf8'), ms: performance.now() - t0 };
      try { r.json = JSON.parse(stdout); } catch { r.json = undefined; }
      resolve(r);
    });
    child.stdin.end(input);
  });
}

function assertWellFormed(r, label) {
  assert.equal(r.signal, null, `${label}: killed by ${r.signal}\n${r.stderr}`);
  assert.equal(r.code, 0, `${label}: exit ${r.code}\n${r.stderr}`);
  assert.ok(r.stdout.endsWith('\n') && r.stdout.indexOf('\n') === r.stdout.length - 1, `${label}: stdout must be one line`);
  assert.ok(r.json && typeof r.json.ok === 'boolean', `${label}: invalid JSON: ${r.stdout.slice(0, 200)}`);
  if (!r.json.ok) {
    assert.ok(['unsupported_format', 'empty_input', 'too_large', 'decode_error', 'invalid_arguments'].includes(r.json.error?.code),
      `${label}: unexpected error ${JSON.stringify(r.json.error)}`);
  }
}

const magic = {
  'image/png': [0x89, 0x50, 0x4e, 0x47],
  'image/jpeg': [0xff, 0xd8, 0xff],
};

function checkResult(fx, r, previewMax = 1600) {
  const e = fx.expect;
  const j = r.json;
  assertWellFormed(r, fx.file);
  if (e.anyResult) return;
  assert.equal(j.ok, e.ok, `${fx.file}: ok=${j.ok} ${JSON.stringify(j.error)}`);
  if (!e.ok) {
    assert.equal(j.error.code, e.error, `${fx.file}: error code`);
    assert.equal(typeof j.error.message, 'string');
    return;
  }
  if (e.format) assert.equal(j.format, e.format, `${fx.file}: format`);
  if (e.width) assert.equal(j.width, e.width, `${fx.file}: width`);
  if (e.height) assert.equal(j.height, e.height, `${fx.file}: height`);
  if (e.pages) assert.equal(j.pages, e.pages, `${fx.file}: pages`);

  // preview
  const p = j.preview;
  assert.ok(p && typeof p.base64 === 'string', `${fx.file}: preview missing`);
  const buf = Buffer.from(p.base64, 'base64');
  const m = magic[p.mime];
  assert.ok(m, `${fx.file}: unexpected preview mime ${p.mime}`);
  assert.deepEqual([...buf.subarray(0, m.length)], m, `${fx.file}: preview bytes don't match mime`);
  assert.ok(Math.max(p.width, p.height) <= previewMax, `${fx.file}: preview too big`);
  assert.equal(p.page, e.previewPage ?? 0, `${fx.file}: preview page`);
  if (p.page === 0) {
    assert.ok(Math.abs(p.width / p.height - j.width / j.height) < 0.02, `${fx.file}: preview aspect differs from raster`);
  }

  if (e.exactCount) {
    assert.equal(j.codes.length, e.codes.length,
      `${fx.file}: expected ${e.codes.length} codes, got ${JSON.stringify(j.codes.map((c) => [c.symbology, c.text, c.pass]))}`);
  }
  for (const c of j.codes) {
    for (const k of ['x', 'y', 'w', 'h']) assert.ok(c.bounds[k] >= 0 && c.bounds[k] <= 1, `${fx.file}: bounds.${k}`);
    assert.equal(c.corners.length, 4);
    for (const [x, y] of c.corners) {
      assert.ok(x >= c.bounds.x - 0.01 && x <= c.bounds.x + c.bounds.w + 0.01, `${fx.file}: corner x outside bounds`);
      assert.ok(y >= c.bounds.y - 0.01 && y <= c.bounds.y + c.bounds.h + 0.01, `${fx.file}: corner y outside bounds`);
    }
    assert.ok(['original', 'inverted', 'enhanced', 'upscaled', 'tile'].includes(c.pass));
    assert.ok(c.confidence >= 0 && c.confidence <= 1);
    if (c.symbology === 'QR') {
      assert.ok(c.qr && Number.isInteger(c.qr.version) && /^[LMQH]$/.test(c.qr.ecLevel) && Number.isInteger(c.qr.maskPattern),
        `${fx.file}: qr descriptor ${JSON.stringify(c.qr)}`);
    }
  }
  for (const want of e.codes) {
    const got = j.codes.find((c) => c.symbology === want.symbology && c.text === want.text);
    assert.ok(got, `${fx.file}: missing ${want.symbology} ${JSON.stringify(want.text)}; got ${JSON.stringify(j.codes.map((c) => [c.symbology, c.text]))}`);
    if (want.page !== undefined) assert.equal(got.page, want.page, `${fx.file}: page`);
    if (want.symbology === 'QR') {
      assert.equal(got.bytesKind, 'payload', `${fx.file}: bytesKind`);
      assert.equal(Buffer.from(got.bytesBase64, 'base64').toString('utf8'), want.text, `${fx.file}: payload bytes != text`);
    }
    if (want.bounds) {
      const b = want.bounds;
      const cx = got.bounds.x + got.bounds.w / 2;
      const cy = got.bounds.y + got.bounds.h / 2;
      const tol = 0.02;
      assert.ok(cx >= b.x - tol && cx <= b.x + b.w + tol && cy >= b.y - tol && cy <= b.y + b.h + tol,
        `${fx.file}: centre (${cx.toFixed(3)},${cy.toFixed(3)}) outside expected ${JSON.stringify(b)}`);
      if (!want.centerOnly) {
        assert.ok(Math.abs(got.bounds.w - b.w) <= Math.max(0.03, b.w * 0.15), `${fx.file}: width ${got.bounds.w} vs ${b.w}`);
        assert.ok(Math.abs(got.bounds.h - b.h) <= Math.max(0.03, b.h * 0.15), `${fx.file}: height ${got.bounds.h} vs ${b.h}`);
      }
    }
  }
}

ensureBuilt();
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const timings = [];

describe('qr-decode fixtures', () => {
  for (const fx of manifest.fixtures) {
    test(fx.file, async () => {
      const input = readFileSync(path.join(fixturesDir, fx.file));
      const r = await run(input);
      timings.push([fx.file, r.ms]);
      checkResult(fx, r);
      assert.ok(r.ms < 5000, `${fx.file}: took ${r.ms.toFixed(0)} ms`);
    });
  }
  test('timings', (t) => {
    const lines = timings.sort((a, b) => b[1] - a[1]).map(([f, ms]) => `${ms.toFixed(0).padStart(6)} ms  ${f}`);
    t.diagnostic('\n' + lines.join('\n'));
  });
});

describe('qr-decode arguments and limits', () => {
  test('--preview-max downsizes the preview', async () => {
    const r = await run(readFileSync(path.join(fixturesDir, 'multi-3.png')), ['--preview-max', '200']);
    assertWellFormed(r, 'preview-max');
    assert.ok(Math.max(r.json.preview.width, r.json.preview.height) <= 200);
    assert.equal(r.json.width, 1600);
    assert.equal(r.json.codes.length, 3);
  });
  test('--max-pages 1 skips page 2 of the PDF', async () => {
    const r = await run(readFileSync(path.join(fixturesDir, 'two-page.pdf')), ['--max-pages', '1']);
    assertWellFormed(r, 'max-pages');
    assert.equal(r.json.pages, 2);
    assert.equal(r.json.codes.length, 0);
  });
  test('every pass maps coordinates back correctly (--debug-pass)', async () => {
    const byFile = Object.fromEntries(manifest.fixtures.map((f) => [f.file, f]));
    for (const [file, pass] of [['text.png', 'original'], ['text.png', 'inverted'], ['text.png', 'enhanced'],
      ['text.png', 'upscaled'], ['low-contrast.png', 'enhanced'], ['tiny-2px.png', 'upscaled'], ['multi-3.png', 'tile'],
      ['screenshot-small-qr.png', 'tile']]) {
      const r = await run(readFileSync(path.join(fixturesDir, file)), ['--debug-pass', pass]);
      checkResult(byFile[file], r);
      assert.ok(r.json.codes.every((c) => c.pass === pass), `${file}/${pass}: ${r.json.codes.map((c) => c.pass)}`);
    }
  });
  test('bad arguments → invalid_arguments', async () => {
    for (const args of [['--nope'], ['--preview-max'], ['--preview-max', 'x'], ['--max-pages', '0'], ['--debug-pass', 'bogus']]) {
      const r = await run(Buffer.from('x'), args);
      assertWellFormed(r, args.join(' '));
      assert.equal(r.json.error.code, 'invalid_arguments');
    }
  });
  test('memory ceiling → too_large (--max-footprint-mb lowers the 1 GiB default)', async () => {
    const r = await run(readFileSync(path.join(fixturesDir, 'multi-3.png')), ['--max-footprint-mb', '16']);
    assertWellFormed(r, 'max-footprint');
    assert.equal(r.json.ok, false);
    assert.equal(r.json.error.code, 'too_large');
  });
  test('peak memory of the 81 MP fixture stays well below the ceiling (24 MP working raster)', async () => {
    // /usr/bin/time -l reports the child's "peak memory footprint" (was ~850 MB with a 50 MP raster).
    const real = realpathSync(helper);
    const r = await new Promise((resolve, reject) => {
      const c = spawn('/usr/bin/time', ['-l', '/usr/bin/sandbox-exec', '-f', sandboxProfile, '-D', `HELPER=${real}`,
        '-D', `HELPER_DIR=${path.dirname(real)}`, real], { cwd: '/', stdio: ['pipe', 'pipe', 'pipe'] });
      const out = []; const err = [];
      c.stdout.on('data', (d) => out.push(d)); c.stderr.on('data', (d) => err.push(d));
      c.on('error', reject);
      c.on('close', () => resolve({ stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }));
      c.stdin.end(readFileSync(path.join(fixturesDir, 'large-81mp.png')));
    });
    assert.equal(JSON.parse(r.stdout).codes.length, 1);
    const m = r.stderr.match(/(\d+)\s+peak memory footprint/);
    assert.ok(m, r.stderr);
    assert.ok(Number(m[1]) < 700 * 1024 * 1024, `peak footprint ${(Number(m[1]) / 1048576).toFixed(0)} MB`);
  });
  test('> 64 MiB → too_large', async () => {
    const big = Buffer.alloc(64 * 1024 * 1024 + 1, 0);
    big.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const r = await run(big);
    assertWellFormed(r, 'too_large');
    assert.equal(r.json.error.code, 'too_large');
  });
});

// Seeded PRNG for reproducible fuzzing.
function rng(seed) {
  let s = seed >>> 0;
  return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } }));
}

describe('qr-decode fuzz (never crashes, always one JSON line)', () => {
  test('truncations, bit flips and random buffers', async () => {
    const rand = rng(0xc0ffee);
    const cases = [];
    const images = manifest.fixtures.filter((f) => f.expect.ok && !f.file.startsWith('large-'));
    for (const fx of images) {
      const buf = readFileSync(path.join(fixturesDir, fx.file));
      for (const frac of [0.03, 0.2, 0.5, 0.9]) cases.push([`${fx.file} cut@${frac}`, buf.subarray(0, Math.max(1, Math.floor(buf.length * frac)))]);
      for (let k = 0; k < 2; k++) {
        const b = Buffer.from(buf);
        const flips = 1 + Math.floor(rand() * 16);
        for (let f = 0; f < flips; f++) { const at = Math.floor(rand() * b.length); b[at] ^= 1 << Math.floor(rand() * 8); }
        cases.push([`${fx.file} flip#${k}`, b]);
      }
    }
    for (let k = 0; k < 20; k++) {
      const len = Math.floor(rand() * 4096);
      const b = Buffer.alloc(len);
      for (let i = 0; i < len; i++) b[i] = Math.floor(rand() * 256);
      // keep some with valid signatures so the decoders themselves get exercised
      const sigs = [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], [0xff, 0xd8, 0xff], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], [0x25, 0x50, 0x44, 0x46, 0x2d], [0x49, 0x49, 0x2a, 0]];
      if (k % 2 === 0 && len > 8) b.set(sigs[k % sigs.length]);
      cases.push([`random#${k}`, b]);
    }
    const failures = [];
    await pool(cases, 6, async ([label, input]) => {
      const r = await run(input);
      try { assertWellFormed(r, label); } catch (e) { failures.push(e.message); }
    });
    assert.deepEqual(failures, [], `${failures.length}/${cases.length} fuzz cases failed`);
  });
});

describe('qr-decode under sandbox-exec', { skip: !existsSync(sandboxProfile) && 'native/qr-decode.sb not present' }, () => {
  for (const fx of manifest.fixtures) {
    test(fx.file, async () => {
      const r = await run(readFileSync(path.join(fixturesDir, fx.file)), [], { sandbox: true });
      checkResult(fx, r);
    });
  }
});

'use strict';
// Runs the native qr-decode helper under sandbox-exec and maps its JSON to ScanResult.
// Rules (docs/SECURITY.md §7.2): canonical paths, cwd '/', minimal env, no shell,
// size cap, timeout + SIGKILL, capped stdout/stderr, parse only the last stdout line,
// never run unsandboxed. A failed self-test makes every scan return
// `decoder_unavailable`.

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const paths = require('./paths');
const { SELF_TEST_TEXT, SELF_TEST_PNG_BASE64 } = require('./selftest-image');

const MAX_INPUT_BYTES = 64 * 1024 * 1024;
const TIMEOUT_MS = 20_000;
const MAX_STDOUT = 32 * 1024 * 1024;
const MAX_STDERR = 64 * 1024;
const MAX_CONCURRENT = 2;
const MAX_CODES = 256;
const MAX_TEXT = 1024 * 1024;
const PREVIEW_MAX = 1600;
const MAX_PAGES = 10;

const ERROR_CODES = new Set(['unsupported_format', 'empty_input', 'too_large', 'decode_error', 'invalid_arguments']);
const FORMATS = new Set(['png', 'jpeg', 'gif', 'tiff', 'bmp', 'webp', 'ico', 'heic', 'heif', 'avif', 'pdf']);
const PASSES = new Set(['original', 'inverted', 'enhanced', 'upscaled', 'tile']);
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

const newId = () => crypto.randomBytes(12).toString('hex');

// ---------------------------------------------------------------- concurrency
let running = 0;
const waiters = [];
async function withSlot(fn) {
  if (running >= MAX_CONCURRENT) await new Promise((r) => waiters.push(r));
  running++;
  try {
    return await fn();
  } finally {
    running--;
    const next = waiters.shift();
    if (next) next();
  }
}

// ---------------------------------------------------------------- spawn
/** Runs the sandboxed helper once. Resolves the parsed JSON object, or an `{ok:false}` object. */
function runHelper(bytes, loc) {
  return new Promise((resolve) => {
    const args = [
      '-f', loc.profile,
      '-D', `HELPER=${loc.helper}`,
      '-D', `HELPER_DIR=${loc.helperDir}`,
      loc.helper, '--preview-max', String(PREVIEW_MAX), '--max-pages', String(MAX_PAGES),
    ];
    let child;
    try {
      child = spawn('/usr/bin/sandbox-exec', args, {
        cwd: '/',
        env: { PATH: '/usr/bin:/bin' },
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
      });
    } catch (e) {
      resolve(fail('decode_error', `could not start decoder: ${e.message}`));
      return;
    }
    const out = [];
    let outLen = 0;
    let errLen = 0;
    let overflow = false;
    let timedOut = false;
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } };
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, TIMEOUT_MS);
    child.stdout.on('data', (d) => {
      outLen += d.length;
      if (outLen > MAX_STDOUT) { overflow = true; child.kill('SIGKILL'); return; }
      out.push(d);
    });
    child.stderr.on('data', (d) => { errLen += d.length; if (errLen > MAX_STDERR) { /* drop */ } });
    child.stdin.on('error', () => {}); // EPIPE when the helper stops reading early
    child.on('error', (e) => done(fail('decode_error', `decoder failed: ${e.message}`)));
    child.on('close', (code, signal) => {
      if (timedOut) return done(fail('timeout', 'Decoding took too long and was stopped.'));
      if (overflow) return done(fail('decode_error', 'Decoder output too large.'));
      const text = Buffer.concat(out).toString('utf8');
      // The JSON is the last line. Frameworks (CoreML E5RT) may print warnings to
      // stdout after it, so take the last line that is a JSON object with a boolean `ok`.
      const lines = text.split('\n').filter((l) => l.startsWith('{'));
      let json;
      for (let i = lines.length - 1; i >= 0 && !json; i--) {
        try {
          const j = JSON.parse(lines[i]);
          if (j && typeof j === 'object' && typeof j.ok === 'boolean') json = j;
        } catch { /* not JSON */ }
      }
      if (!json || typeof json !== 'object' || typeof json.ok !== 'boolean') {
        return done(fail('decode_error', signal ? `Decoder crashed (${signal}).` : `Decoder failed (exit ${code}).`));
      }
      done(json);
    });
    child.stdin.end(Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  });
}

function fail(code, message) {
  return { ok: false, error: { code, message } };
}

// ---------------------------------------------------------------- self-test
let selfTest = null; // Promise<{ok, loc?, message?}>

function runSelfTest() {
  const loc = paths.resolveHelper();
  if (loc.error) return Promise.resolve({ ok: false, message: loc.error });
  const png = Buffer.from(SELF_TEST_PNG_BASE64, 'base64');
  return runHelper(new Uint8Array(png), loc).then((j) => {
    const hit = j.ok && Array.isArray(j.codes) && j.codes.some((c) => c && c.text === SELF_TEST_TEXT);
    if (hit) return { ok: true, loc };
    const why = j.ok ? 'the sandboxed decoder returned no result for a known code' : `${j.error?.code}: ${j.error?.message}`;
    return { ok: false, message: `self-test failed (${why})` };
  });
}

/** Cached self-test; a failed result is retried on the next call. */
function ensureDecoder() {
  if (!selfTest) {
    selfTest = runSelfTest().then((r) => {
      if (!r.ok) selfTest = null;
      return r;
    });
  }
  return selfTest;
}

// ---------------------------------------------------------------- mapping
const num = (v, d = 0) => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const str = (v, max = MAX_TEXT) => (typeof v === 'string' ? v.slice(0, max) : null);

function sanitizeCode(c) {
  if (!c || typeof c !== 'object') return null;
  const b64 = typeof c.bytesBase64 === 'string' && c.bytesBase64.length <= MAX_TEXT * 2 && B64_RE.test(c.bytesBase64)
    ? c.bytesBase64 : null;
  const b = c.bounds && typeof c.bounds === 'object' ? c.bounds : {};
  const corners = Array.isArray(c.corners)
    ? c.corners.slice(0, 4).map((p) => (Array.isArray(p) ? [num(p[0]), num(p[1])] : [0, 0]))
    : [];
  const out = {
    symbology: (str(c.symbology, 64) || 'Unknown').replace(/[^A-Za-z0-9_-]/g, ''),
    text: str(c.text),
    bytesBase64: b64,
    bytesKind: c.bytesKind === 'payload' || c.bytesKind === 'raw' ? c.bytesKind : null,
    bounds: { x: num(b.x), y: num(b.y), w: num(b.w), h: num(b.h) },
    corners,
    page: Math.max(0, Math.floor(num(c.page))),
    confidence: num(c.confidence, 0),
  };
  if (!out.bytesBase64) out.bytesKind = null;
  if (c.qr && typeof c.qr === 'object') {
    out.qr = {
      version: Math.floor(num(c.qr.version)),
      ecLevel: ['L', 'M', 'Q', 'H'].includes(c.qr.ecLevel) ? c.qr.ecLevel : null,
      maskPattern: Math.floor(num(c.qr.maskPattern, -1)),
    };
  }
  if (PASSES.has(c.pass)) out.pass = c.pass;
  return out;
}

/** Helper JSON → ScanResult. */
function toScanResult(json, source) {
  const base = { id: newId(), source, ok: false, codes: [] };
  if (!json.ok) {
    const code = typeof json.error?.code === 'string' && (ERROR_CODES.has(json.error.code) || json.error.code === 'timeout')
      ? json.error.code : 'decode_error';
    return { ...base, error: { code, message: str(json.error?.message, 500) || code } };
  }
  const p = json.preview;
  let image;
  if (p && (p.mime === 'image/png' || p.mime === 'image/jpeg') && typeof p.base64 === 'string' && B64_RE.test(p.base64)) {
    image = {
      previewDataUrl: `data:${p.mime};base64,${p.base64}`,
      width: num(json.width), // decoded raster of page/frame 0
      height: num(json.height),
      format: FORMATS.has(json.format) ? json.format : 'unknown',
      pages: Math.max(1, Math.floor(num(json.pages, 1))),
      previewWidth: num(p.width),
      previewHeight: num(p.height),
      previewPage: Math.max(0, Math.floor(num(p.page))),
    };
  }
  const codes = (Array.isArray(json.codes) ? json.codes : []).slice(0, MAX_CODES).map(sanitizeCode).filter(Boolean);
  return { ...base, ok: true, image, codes };
}

function errorResult(source, code, message) {
  return { id: newId(), source, ok: false, error: { code, message }, codes: [] };
}

/**
 * Decodes image bytes. Never throws; always resolves a ScanResult.
 * @param {Uint8Array} bytes
 * @param {{kind: string, name?: string}} source
 */
async function decode(bytes, source) {
  if (!(bytes instanceof Uint8Array)) return errorResult(source, 'invalid_arguments', 'No image data.');
  if (bytes.byteLength === 0) return errorResult(source, 'empty_input', 'The file is empty.');
  if (bytes.byteLength > MAX_INPUT_BYTES) {
    return errorResult(source, 'too_large', `The file is larger than ${MAX_INPUT_BYTES / 1024 / 1024} MiB.`);
  }
  const st = await ensureDecoder();
  if (!st.ok) {
    return errorResult(source, 'decoder_unavailable',
      `The sandboxed decoder is unavailable: ${st.message}. Run ./start.sh to rebuild it. ` +
      'Images are never decoded outside the sandbox.');
  }
  // Re-check helper + profile hashes before every run (packaged only; ~1 ms), not just at self-test.
  const bad = paths.verifyHelper(st.loc);
  if (bad) {
    selfTest = null;
    return errorResult(source, 'decoder_unavailable', `The sandboxed decoder is unavailable: ${bad}. ` +
      'Reinstall the app (./start.sh). Images are never decoded outside the sandbox.');
  }
  const json = await withSlot(() => runHelper(bytes, st.loc));
  return toScanResult(json, source);
}

module.exports = { decode, ensureDecoder, errorResult, MAX_INPUT_BYTES, newId };

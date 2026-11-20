// Small shared helpers for setup/build scripts (no dependencies).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (c) => (s) => (tty ? `\x1b[${c}m${s}\x1b[0m` : s);
export const dim = paint('2'), bold = paint('1'), red = paint('31'), green = paint('32'), yellow = paint('33');

export class SetupError extends Error {
  constructor(message, hint) { super(message); this.hint = hint; }
}

export const sha256File = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

/** Hash of the given files/directories (paths + contents, recursive, sorted). Missing → "missing". */
export function hashInputs(root, rels) {
  const h = crypto.createHash('sha256');
  const add = (rel) => {
    const abs = path.join(root, rel);
    let st;
    try { st = fs.lstatSync(abs); } catch { h.update(`${rel}\0missing\0`); return; }
    if (st.isDirectory()) {
      for (const n of fs.readdirSync(abs).sort()) if (n !== '.DS_Store') add(path.join(rel, n));
    } else if (st.isSymbolicLink()) {
      h.update(`${rel}\0link\0${fs.readlinkSync(abs)}\0`);
    } else {
      h.update(`${rel}\0${st.mode & 0o111 ? 'x' : '-'}\0`);
      h.update(fs.readFileSync(abs));
      h.update('\0');
    }
  };
  for (const r of rels) add(r);
  return h.digest('hex');
}

/** Run a command (no shell). Returns stdout; throws with stderr on failure. */
export function run(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 << 20, ...opts });
  } catch (e) {
    const detail = [e.stderr, e.stdout].filter(Boolean).join('\n').trim();
    throw new SetupError(`${path.basename(cmd)} ${args.join(' ')} failed${detail ? `:\n${detail}` : ''}`);
  }
}

/** Spawn with input on stdin, capture output. → { code, signal, stdout, stderr } */
export function runWithInput(cmd, args, input, { timeoutMs = 30000, ...opts } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'], ...opts });
    const out = [], err = [];
    const t = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.stdin.on('error', () => {});
    child.on('error', reject);
    child.on('close', (code, signal) => {
      clearTimeout(t);
      resolve({ code, signal, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
    child.stdin.end(input);
  });
}

/** Decode `image` with `helper` under sandbox-exec(`profile`); require a QR with `expectText`. */
export async function helperSelfTest(helper, profile, image, expectText) {
  const h = fs.realpathSync(helper), p = fs.realpathSync(profile);
  const r = await runWithInput('/usr/bin/sandbox-exec',
    ['-f', p, '-D', `HELPER=${h}`, '-D', `HELPER_DIR=${path.dirname(h)}`, h, '--preview-max', '256'],
    fs.readFileSync(image), { cwd: '/', env: { PATH: '/usr/bin:/bin' }, timeoutMs: 20000 });
  // Contract: one JSON line. Tolerate (but report) framework noise on other lines.
  let json;
  const lines = r.stdout.split('\n').filter(Boolean);
  for (const l of lines) { try { json = JSON.parse(l); break; } catch { /* not JSON */ } }
  const noise = lines.length > 1 ? lines.filter((l) => !l.startsWith('{')).join(' ').slice(0, 160) : null;
  const found = json?.ok && json.codes?.some((c) => c.symbology === 'QR' && c.text === expectText);
  if (!found) {
    throw new SetupError(
      `sandboxed decoder self-test FAILED (exit ${r.code}${r.signal ? `, ${r.signal}` : ''}): ` +
        `expected QR "${expectText}", got ${json ? JSON.stringify(json).slice(0, 300) : JSON.stringify(r.stdout.slice(0, 300))}` +
        (r.stderr ? `\nstderr: ${r.stderr.slice(0, 1000)}` : ''),
      'The helper must work under native/qr-decode.sb; never run it unsandboxed. Check recent macOS ' +
        'updates and `/usr/bin/log show --last 2m --predicate \'sender == "Sandbox"\'` for denials.');
  }
  return { noise };
}

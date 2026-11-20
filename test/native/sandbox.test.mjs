// Adversarial checks of native/qr-decode.sb (docs/SECURITY.md §7.3). Small probe programs
// (test/native/probes/) are compiled into build/test-probes/ and run unsandboxed (control:
// every action must succeed, which proves the probe works) and under the profile exactly as
// main runs the helper (every action must fail).
//   fnm exec --using=24.18.0 node --test test/native/sandbox.test.mjs
// Needs: swiftc + cc (Xcode command line tools), /usr/bin/openssl (LibreSSL, part of macOS).
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const probesSrc = path.join(root, 'test/native/probes');
const outDir = path.join(root, 'build/test-probes');
const profile = path.join(root, 'native/qr-decode.sb');

/** Compile `src` to `out` unless `out` is newer. */
function build(out, cmd, args) {
  const src = args.find((a) => a.startsWith(probesSrc));
  if (existsSync(out) && statSync(out).mtimeMs > statSync(src).mtimeMs) return;
  execFileSync(cmd, args, { stdio: 'inherit' });
}

function run(bin, args, { sandbox, input } = {}) {
  return new Promise((resolve, reject) => {
    const real = realpathSync(bin);
    const cmd = sandbox ? '/usr/bin/sandbox-exec' : real;
    const argv = sandbox ? ['-f', realpathSync(profile), '-D', `HELPER=${real}`, '-D', `HELPER_DIR=${path.dirname(real)}`, real, ...args] : args;
    const child = spawn(cmd, argv, { cwd: '/', env: { PATH: '/usr/bin:/bin' }, stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', reject);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() });
    });
    child.stdin.end(input ?? '');
  });
}

const parseReport = (s) => Object.fromEntries(s.trim().split('\n').map((l) => l.split(' ')).filter((p) => p.length === 2));

let server;
let port;
const hits = [];
let aiaProbe;
let sbProbe;
let tmp;

before(async () => {
  mkdirSync(outDir, { recursive: true });
  aiaProbe = path.join(outDir, 'aia-probe');
  sbProbe = path.join(outDir, 'sandbox-probe');
  build(aiaProbe, 'swiftc', ['-O', '-o', aiaProbe, path.join(probesSrc, 'aia-probe.swift')]);
  build(sbProbe, 'cc', ['-O2', '-o', sbProbe, path.join(probesSrc, 'sandbox-probe.c')]);
  tmp = mkdtempSync(path.join(os.tmpdir(), 'qr-sb-test-'));
  server = createServer((req, res) => { hits.push(req.url); res.statusCode = 404; res.end(); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});

after(() => {
  server?.close();
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

/** CA + leaf whose AIA (caIssuers, OCSP) and CRL DP point at the local listener with a unique token. */
function leafWithAia(token) {
  const d = mkdtempSync(path.join(tmp, 'pki-'));
  const ossl = (...a) => execFileSync('/usr/bin/openssl', a, { cwd: d, stdio: ['ignore', 'ignore', 'pipe'] });
  ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=qr-reader test CA');
  ossl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=probe.example');
  const base = `http://127.0.0.1:${port}`;
  writeFileSync(path.join(d, 'ext.cnf'), [
    '[v3]', 'basicConstraints=CA:FALSE', 'keyUsage=digitalSignature', 'extendedKeyUsage=serverAuth',
    'subjectAltName=DNS:probe.example',
    `authorityInfoAccess=caIssuers;URI:${base}/ca-${token}.cer,OCSP;URI:${base}/ocsp-${token}`,
    `crlDistributionPoints=URI:${base}/crl-${token}.crl`, '',
  ].join('\n'));
  ossl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2',
    '-extfile', 'ext.cnf', '-extensions', 'v3', '-outform', 'DER', '-out', 'leaf.der');
  return readFileSync(path.join(d, 'leaf.der'));
}

async function hitsFor(token, waitMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < waitMs) {
    if (hits.some((h) => h.includes(token))) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  return hits.filter((h) => h.includes(token));
}

describe('helper sandbox: no network via trustd (AIA / OCSP / CRL fetch)', () => {
  test('control: unsandboxed, trustd fetches the AIA URL from the local listener', async () => {
    const token = `ctl${randomBytes(6).toString('hex')}`; // unique: trustd caches fetches per URL
    const r = await run(aiaProbe, [], { input: leafWithAia(token) });
    assert.match(r.stdout, /evaluated ok=/, r.stderr);
    const got = await hitsFor(token, 5000);
    assert.ok(got.length > 0, 'control run produced no request — the probe no longer exercises trustd fetching');
  });

  test('sandboxed: no request reaches the listener', async () => {
    const token = `sbx${randomBytes(6).toString('hex')}`;
    const r = await run(aiaProbe, [], { sandbox: true, input: leafWithAia(token) });
    assert.match(r.stdout, /evaluated ok=false/, `probe did not run under the sandbox: ${r.stderr}`);
    const got = await hitsFor(token, 3000);
    assert.deepEqual(got, [], 'trustd fetched a URL on behalf of the sandboxed process');
  });
});

describe('helper sandbox: network, file and daemon access', () => {
  const args = () => [String(port), `/private/tmp/qr-sb-probe-${randomBytes(6).toString('hex')}`,
    realpathSync(os.homedir()), realpathSync(path.join(probesSrc, 'sandbox-probe.c'))];
  const CHECKS = ['tcp-connect-loopback', 'file-create-tmp', 'list-home', 'read-user-file', 'unix-connect-syslog',
    'read-etc-passwd', 'sysctl-process-list', 'notify-post', 'mach-lookup:com.apple.trustd',
    'mach-lookup:com.apple.trustd.agent', 'mach-lookup:com.apple.analyticsd', 'mach-lookup:com.apple.diagnosticd',
    'mach-lookup:com.apple.runningboard'];

  test('control: unsandboxed, every action succeeds', async () => {
    const r = await run(sbProbe, args());
    assert.equal(r.code, 0, r.stderr);
    const rep = parseReport(r.stdout);
    for (const c of CHECKS) assert.equal(rep[c], 'ALLOWED', `control ${c}`);
  });

  test('sandboxed: every action is denied', async () => {
    const before = hits.length;
    const r = await run(sbProbe, args(), { sandbox: true });
    assert.equal(r.code, 0, `probe did not run under the sandbox: ${r.stderr}`);
    const rep = parseReport(r.stdout);
    for (const c of CHECKS) assert.equal(rep[c], 'denied', `sandboxed ${c}`);
    assert.equal(hits.length, before);
  });
});

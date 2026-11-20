// The production bundle stays undrivable (fuse wire, no test marker, debug switches refused), and
// the test variant's allowance is exactly Playwright's two switches — nothing broader.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { readAsarFile } from '../../scripts/lib/asar.mjs';
import { readFuses } from '../../scripts/lib/fuses.mjs';
import { EXPECTED_WIRE, TEST_MARKER, VARIANTS } from '../../scripts/build-app.mjs';
import * as h from '../e2e/harness.mjs';
import * as p from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); await p.testBundle(); });
after(async () => { await p.killBundle(p.TEST_APP); release?.(); });

const hasMarker = (app) => { try { readAsarFile(path.join(app, 'Contents/Resources/app.asar'), TEST_MARKER); return true; } catch { return false; } };

test('production bundle: production fuse wire, no test marker, verifies', async () => {
  const v = await p.prodBundle();
  assert.equal(v.wire, EXPECTED_WIRE);
  assert.equal(readFuses(p.PROD_APP), '010011001');
  assert.equal(readFuses(p.PROD_APP)[3], '0', 'EnableNodeCliInspectArguments off');
  assert.equal(hasMarker(p.PROD_APP), false);
  // the test variant differs in exactly that fuse
  assert.equal(readFuses(p.TEST_APP), VARIANTS.test.wire);
  assert.deepEqual([...readFuses(p.TEST_APP)].map((c, i) => c !== EXPECTED_WIRE[i] && i).filter((i) => i !== false), [3]);
  assert.equal(hasMarker(p.TEST_APP), true);
});

test('production bundle refuses --remote-debugging-port / --inspect (exit 1, no endpoint)', { timeout: 120_000 }, async () => {
  for (const args of [['--remote-debugging-port=0'], ['--inspect=0'], ['--inspect=0', '--remote-debugging-port=0'], ['--inspect-brk=0']]) {
    const r = await p.runExe(p.PROD_APP, args, { ms: 10_000 });
    assert.equal(r.alive, false, `${args} kept running`);
    assert.equal(r.code, 1, `${args}: exit ${r.code} ${r.signal}`);
    assert.doesNotMatch(r.out, /DevTools listening|Debugger listening/, `${args} opened an endpoint`);
  }
});

test('Playwright cannot launch the production bundle', { timeout: 60_000 }, async () => {
  // In a child process: a failed _electron.launch also leaves unhandled rejections inside Playwright.
  const script = `import * as h from ${JSON.stringify(path.join(h.ROOT, 'test/e2e/harness.mjs'))};
    const { _electron } = await h.playwright();
    const a = await _electron.launch({ executablePath: process.argv[1], cwd: '/', timeout: 15000 });
    console.log('LAUNCHED'); await a.close();`;
  const out = await new Promise((res) => execFile(process.execPath, ['--input-type=module', '-e', script, p.exeOf(p.PROD_APP)],
    { env: p.cleanEnv(), timeout: 50_000 }, (err, stdout, stderr) => res({ code: err?.code ?? 0, text: stdout + stderr })));
  assert.notEqual(out.code, 0);
  assert.match(out.text, /Process failed to launch!/);
  assert.doesNotMatch(out.text, /LAUNCHED/);
});

test('test variant: only `--inspect=0 --remote-debugging-port=0` are accepted', { timeout: 120_000 }, async () => {
  for (const [args, env] of [
    // (--inspect-brk is not probed here: with the inspect fuse on, Node pauses before main runs.)
    [['--inspect=9229']], [['--remote-debugging-port=9222']], [['--inspect-port=0']],
    [['--inspect=0', '--remote-debugging-port=0', '--enable-logging']], [['--inspect=0', '--remote-debugging-port=0', '--js-flags=--trace']],
    [['--inspect=0', '--remote-debugging-port=0'], { ELECTRON_ENABLE_LOGGING: '1' }],
  ]) {
    await p.killBundle(p.TEST_APP);
    const r = await p.runExe(p.TEST_APP, args, { ms: 10_000, env });
    assert.equal(r.alive, false, `${args} ${JSON.stringify(env ?? {})} kept running`);
    assert.equal(r.code, 1, `${args}: exit ${r.code} ${r.signal}`);
  }
});

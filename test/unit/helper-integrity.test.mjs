// paths.verifyHelper(): packaged builds refuse a helper / sandbox profile whose SHA-256 differs
// from src/main/helper-hashes.json (generated into app.asar by scripts/build-app.mjs).
// `electron` is injected through require.cache; the record is a temp file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(import.meta.url);
const fakeApp = { isPackaged: true };
const inject = (file, exports) => { require.cache[file] = { id: file, filename: file, loaded: true, exports }; };
inject(require.resolve('electron'), { app: fakeApp });
const paths = require(path.join(root, 'src/main/paths.js'));

const dir = mkdtempSync(path.join(os.tmpdir(), 'qr-integrity-'));
const helper = path.join(dir, 'qr-decode');
const profile = path.join(dir, 'qr-decode.sb');
writeFileSync(helper, 'helper-bytes');
writeFileSync(profile, '(version 1)');
const sha = (s) => createHash('sha256').update(s).digest('hex');
const loc = { helper, helperDir: dir, profile };
const record = path.join(dir, 'helper-hashes.json');
const setRecord = (o) => writeFileSync(record, typeof o === 'string' ? o : JSON.stringify(o));
const verify = (l = loc) => paths.verifyHelper(l, record);
test.after(() => rmSync(dir, { recursive: true, force: true }));

test('matching hashes → ok', () => {
  setRecord({ 'bin/qr-decode': sha('helper-bytes'), 'qr-decode.sb': sha('(version 1)') });
  assert.equal(verify(), null);
});

test('modified helper or profile → error (fail closed)', () => {
  setRecord({ 'bin/qr-decode': sha('helper-bytes'), 'qr-decode.sb': sha('(version 1)') });
  writeFileSync(profile, '(version 1);');
  assert.match(verify(), /sandbox profile does not match/);
  writeFileSync(profile, '(version 1)');
  writeFileSync(helper, 'helper-bytes!');
  assert.match(verify(), /decoder helper does not match/);
  writeFileSync(helper, 'helper-bytes');
});

test('missing or malformed record → error', () => {
  setRecord({});
  assert.match(verify(), /does not match/);
  setRecord('not json');
  assert.match(verify(), /integrity record missing/);
  rmSync(record);
  assert.match(verify(), /integrity record missing/);
});

test('dev (unpackaged) → check skipped', () => {
  fakeApp.isPackaged = false;
  assert.equal(verify({ helper: '/nonexistent', profile: '/nonexistent' }), null);
  fakeApp.isPackaged = true;
});

// openExternal confirm flow + saveText, with dialogs/shell stubbed only at the boundary.
import { describe, test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as h from './harness.mjs';

const acquire = h.serialize();
let release;
before(async () => { release = await acquire(); });
after(() => release?.());

describe('openExternal', () => {
  let ctx;
  before(async () => {
    ctx = await h.launch();
    await ctx.app.evaluate(({ dialog, shell }) => {
      globalThis.__calls = { dialogs: [], opened: [] };
      globalThis.__answer = 0;
      dialog.showMessageBox = async (_w, o) => {
        const opts = o || _w;
        globalThis.__calls.dialogs.push({ type: opts.type, message: opts.message, detail: opts.detail, buttons: opts.buttons, defaultId: opts.defaultId, cancelId: opts.cancelId });
        return { response: opts.type === 'warning' ? globalThis.__answer : 0, checkboxChecked: false };
      };
      shell.openExternal = async (u) => { globalThis.__calls.opened.push(u); };
    });
  });
  after(async () => { await ctx?.close(); });
  beforeEach(async () => { await ctx.app.evaluate(() => { globalThis.__calls = { dialogs: [], opened: [] }; }); });

  const calls = () => ctx.app.evaluate(() => globalThis.__calls);
  const open = (u) => ctx.page.evaluate((x) => window.qr.openExternal(x), u);
  const answer = (n) => ctx.app.evaluate((_e, v) => { globalThis.__answer = v; }, n);

  test('confirmed → opens exactly the normalised URL shown', async () => {
    await answer(1);
    const r = await open('https://Example.com/a?b=1');
    assert.deepEqual(r, { opened: true });
    const c = await calls();
    assert.equal(c.dialogs.length, 1);
    assert.equal(c.dialogs[0].type, 'warning');
    assert.equal(c.dialogs[0].defaultId, 0);
    assert.equal(c.dialogs[0].cancelId, 0);
    assert.match(c.dialogs[0].detail, /^https:\/\/example\.com\/a\?b=1\n/);
    assert.deepEqual(c.opened, ['https://example.com/a?b=1']);
  });

  test('cancelled → not opened', async () => {
    await answer(0);
    assert.deepEqual(await open('https://example.com/'), { opened: false });
    const c = await calls();
    assert.equal(c.dialogs.length, 1);
    assert.deepEqual(c.opened, []);
  });

  test('IDN host is shown as punycode and Unicode (bidi-isolated) in the message, with a warning', async () => {
    await answer(0);
    await open('https://xn--pple-43d.com/login');
    const { dialogs } = await calls();
    assert.match(dialogs[0].message, /Host: \u2066xn--pple-43d\.com\u2069/);
    assert.match(dialogs[0].message, /Host \(Unicode\): \u2066\u0430pple\.com\u2069/);
    assert.match(dialogs[0].message, /Site: \u2066\u0430pple\.com\u2069 \(xn--pple-43d\.com\)/);
    assert.match(dialogs[0].detail, /Internationalized domain name/);
  });

  test('message shows the registrable domain (PSL) and host; no claim about which app opens it', async () => {
    await answer(0);
    await open('https://login.secure.example.co.uk/x');
    const [d] = (await calls()).dialogs;
    assert.match(d.message, /^Open this link\?\n\nSite: \u2066example\.co\.uk\u2069\nHost: \u2066login\.secure\.example\.co\.uk\u2069$/);
    assert.match(d.detail, /Opens with the default app for this link\./);
    assert.doesNotMatch(d.detail, /browser/i);
    assert.doesNotMatch(d.detail, /local network/);
  });

  test('long link: shown truncated with the remaining length, opened exactly', async () => {
    await answer(1);
    const long = `https://example.com/${'a'.repeat(1500)}?q=${'b'.repeat(400)}`;
    assert.deepEqual(await open(long), { opened: true });
    const c = await calls();
    const first = c.dialogs[0].detail.split('\n')[0];
    assert.equal(first, `${long.slice(0, 300)}… (${long.length - 300} more characters)`);
    assert.deepEqual(c.opened, [long]);
  });

  test('loopback / private / link-local / CGNAT hosts get a local-network warning', async () => {
    await answer(0);
    const local = ['http://127.0.0.1:8080/admin', 'http://0x7f.1/', 'http://localhost/', 'http://192.168.1.1/',
      'http://10.0.0.1/', 'http://172.16.5.4/', 'http://169.254.169.254/latest/meta-data/', 'http://100.64.0.1/',
      'http://[::1]/', 'http://[fe80::1]/', 'http://[fd12:3456::1]/', 'http://[::ffff:192.168.0.1]/', 'http://printer.local/'];
    for (const u of local) await open(u);
    await open('https://203.0.113.9/');
    await open('http://[2001:db8::1]/');
    const { dialogs } = await calls();
    assert.equal(dialogs.length, local.length + 2);
    for (let i = 0; i < local.length; i++) {
      assert.match(dialogs[i].detail, /⚠ This link points to this Mac or your local network/, local[i]);
      assert.doesNotMatch(dialogs[i].message, /Site:/, `${local[i]}: an address has no registrable domain`);
    }
    for (const d of dialogs.slice(local.length)) assert.doesNotMatch(d.detail, /local network/);
  });

  test('disallowed schemes / tricks never reach shell.openExternal', async () => {
    await answer(1); // even if the user would click Open
    const bad = ['javascript:alert(1)', 'file:///etc/hosts', 'data:text/html,x', 'app://qr/index.html', 'x-apple-reminder://x',
      'vbscript:x', 'https://user:pw@example.com/', `https://example.com/${String.fromCodePoint(0x202e)}gpj.exe`,
      'https://exa mple.com', `https://example.com/${'a'.repeat(3000)}`, 'notaurl', ''];
    for (const u of bad) {
      assert.deepEqual(await open(u), { opened: false }, u);
    }
    const c = await calls();
    assert.deepEqual(c.opened, []);
    assert.ok(c.dialogs.every((d) => d.type === 'error'), 'only error dialogs for rejected URLs');
  });

  test('mailto / tel are allowed after confirm', async () => {
    await answer(1);
    assert.deepEqual(await open('mailto:someone@example.com?subject=Hi'), { opened: true });
    assert.deepEqual(await open('tel:+15551234567'), { opened: true });
    assert.deepEqual((await calls()).opened, ['mailto:someone@example.com?subject=Hi', 'tel:+15551234567']);
  });
});

describe('saveText', () => {
  let ctx; let dir;
  before(async () => {
    ctx = await h.launch();
    dir = h.tmpDir('qr-save-');
  });
  after(async () => { await ctx?.close(); fs.rmSync(dir, { recursive: true, force: true }); });

  test('writes only after the save dialog; suggested name is sanitised', async () => {
    await ctx.app.evaluate(({ dialog }, d) => {
      globalThis.__saveOpts = [];
      dialog.showSaveDialog = async (_w, o) => { globalThis.__saveOpts.push(o); return { canceled: false, filePath: `${d}/${o.defaultPath.split('/').pop()}` }; };
    }, dir);
    const r = await ctx.page.evaluate(() => window.qr.saveText({ suggestedName: '../../evil/John Doe', kind: 'vcf', text: 'BEGIN:VCARD\r\nEND:VCARD\r\n' }));
    assert.deepEqual(r, { saved: true });
    const opts = await ctx.app.evaluate(() => globalThis.__saveOpts);
    assert.equal(path.basename(opts[0].defaultPath), '....evilJohn Doe.vcf'.replace(/^\.+/, ''));
    const written = fs.readdirSync(dir);
    assert.equal(written.length, 1);
    assert.equal(fs.readFileSync(path.join(dir, written[0]), 'utf8'), 'BEGIN:VCARD\r\nEND:VCARD\r\n');
    const b = await ctx.page.evaluate(() => window.qr.saveText({ suggestedName: 'blob', kind: 'bin', bytesBase64: 'AAEC/w==' }));
    assert.deepEqual(b, { saved: true });
    assert.deepEqual([...fs.readFileSync(path.join(dir, 'blob.bin'))], [0, 1, 2, 255]);
  });

  test('cancel writes nothing', async () => {
    await ctx.app.evaluate(({ dialog }) => { dialog.showSaveDialog = async () => ({ canceled: true }); });
    const before = fs.readdirSync(dir).length;
    assert.deepEqual(await ctx.page.evaluate(() => window.qr.saveText({ kind: 'txt', text: 'x' })), { saved: false });
    assert.equal(fs.readdirSync(dir).length, before);
  });
});

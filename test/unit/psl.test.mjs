// Public Suffix List: official test vectors (tests/test_psl.txt from publicsuffix/list),
// spec vectors (PAYLOADS.md §2.5), the generated data module and the fallback.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { lookup, getRegistrableDomain, getPublicSuffix, pslAvailable } from '../../src/renderer/parsers/psl.js';
import { PSL_SHA256, PSL_VERSION } from '../../src/renderer/parsers/data/psl-rules.js';

const vectorsFile = new URL('./data/test_psl.txt', import.meta.url);
const datFile = new URL('../../src/renderer/parsers/data/public_suffix_list.dat', import.meta.url);

const vectors = [];
for (const line of readFileSync(vectorsFile, 'utf8').split('\n')) {
  const m = /^checkPublicSuffix\((null|'[^']*'),\s*(null|'[^']*')\);/.exec(line.trim());
  if (!m) continue;
  const unq = (s) => (s === 'null' ? null : s.slice(1, -1));
  vectors.push([unq(m[1]), unq(m[2])]);
}

const toAce = (s) => (/[^\x00-\x7f]/.test(s) ? domainToASCII(s) || s : s);

test('official test_psl.txt vectors were loaded', () => {
  assert.ok(vectors.length >= 70, `only ${vectors.length} vectors`);
});

for (const [input, expected] of vectors) {
  test(`test_psl: ${input} → ${expected}`, () => {
    const got = input === null ? lookup(null).registrableDomain : getRegistrableDomain(toAce(input));
    const want = expected === null ? null : toAce(expected).toLowerCase();
    assert.equal(got, want);
  });
}

test('spec vectors (§2.5)', () => {
  assert.equal(getRegistrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(getRegistrableDomain('evil.github.io'), 'evil.github.io');
  assert.equal(getRegistrableDomain('www.city.kawasaki.jp'), 'city.kawasaki.jp');
  assert.equal(getRegistrableDomain('foo.bar.ck'), 'foo.bar.ck');
  assert.equal(getRegistrableDomain('www.ck'), 'www.ck');
  assert.equal(getRegistrableDomain('co.uk'), null);
  assert.equal(lookup('co.uk').isPublicSuffix, true);
});

test('private section separates hosted sites', () => {
  assert.equal(getRegistrableDomain('x.blogspot.com'), 'x.blogspot.com');
  assert.equal(lookup('evil.github.io').section, 'private');
  assert.equal(lookup('www.example.co.uk').section, 'icann');
  assert.equal(getPublicSuffix('foo.pages.dev'), 'pages.dev');
});

test('subdomain, trailing dot, unlisted TLD, invalid input', () => {
  assert.deepEqual(
    { ...lookup('a.b.example.com') },
    { publicSuffix: 'com', registrableDomain: 'example.com', subdomain: 'a.b', isPublicSuffix: false, listed: true, section: 'icann', approximate: false },
  );
  assert.equal(getRegistrableDomain('www.example.com.'), 'example.com.');
  const unlisted = lookup('a.b.example');
  assert.equal(unlisted.registrableDomain, 'b.example');
  assert.equal(unlisted.listed, false);
  assert.equal(lookup('a..com').registrableDomain, null);
  assert.equal(lookup('').registrableDomain, null);
  assert.equal(lookup(undefined).registrableDomain, null);
  assert.equal(getRegistrableDomain('WWW.EXAMPLE.COM'), 'example.com');
});

test('IDN rules are stored in ACE form', () => {
  assert.equal(getRegistrableDomain(domainToASCII('www.食狮.公司.cn')), domainToASCII('食狮.公司.cn'));
});

test('bundled data matches the pinned .dat file', () => {
  assert.ok(pslAvailable());
  const sha = createHash('sha256').update(readFileSync(datFile)).digest('hex');
  assert.equal(sha, PSL_SHA256);
  assert.match(PSL_VERSION, /^\d{4}-\d{2}-\d{2}/);
});

test('psl-rules.js is up to date with the generator (deterministic)', async () => {
  const { generate } = await import('../../scripts/gen-psl.mjs');
  const expected = generate(readFileSync(datFile));
  const actual = readFileSync(new URL('../../src/renderer/parsers/data/psl-rules.js', import.meta.url), 'utf8');
  assert.equal(actual, expected);
  assert.equal(generate(readFileSync(datFile)), expected);
});

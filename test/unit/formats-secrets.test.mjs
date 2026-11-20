// API secrets / credentials (formats/secrets.js): classification, masking, ordering
// against base64, negatives.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, field, action, fuzz } from './_formats-helper.mjs';
import { analyzePayload } from '../../src/renderer/parsers/index.js';
import { findApiSecrets, isApiSecret } from '../../src/renderer/parsers/formats/secrets.js';

const DANGER = /Looks like an API secret\/credential — don't share it/;

function assertSecret(text, { provider, kind, id }) {
  const a = analyzePayload({ text });
  assert.equal(a.type, 'text', text);
  assert.equal(a.data.format, 'api-secret', `${text} → ${a.data.format}`);
  assertWarning(a, 'danger', DANGER);
  assert.equal(a.data.secrets[0].provider, provider);
  if (kind) assert.equal(a.data.secrets[0].kind, kind);
  if (id) assert.equal(a.data.secrets[0].id, id);
  const f = a.fields.find((x) => x.value === text);
  assert.ok(f && f.sensitive && f.mono, 'secret field is sensitive (masked)');
  const c = a.actions.find((x) => x.value === text);
  assert.ok(c && c.sensitive, 'copy is sensitive');
  assert.ok(!JSON.stringify(a.data).includes(text), 'secret value is not in data');
  return a;
}

const STRIPE = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
const AWS_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

test('Stripe secret / restricted / webhook keys', () => {
  const a = assertSecret(STRIPE, { provider: 'Stripe', kind: 'live secret key' });
  assert.equal(a.summary, 'Stripe live secret key (sk_live_…)');
  assert.equal(a.data.secrets[0].mode, 'live');
  assertSecret('rk_live_51H8abcDEFghiJKLmnoPQRstu', { provider: 'Stripe', kind: 'live restricted key' });
  const t = assertSecret('sk_test_4eC39HqLyjWDarjtT1zdp7dc', { provider: 'Stripe', kind: 'test secret key' });
  assertWarning(t, 'info', /test-mode/);
  assertSecret('whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw', { provider: 'Stripe', kind: 'webhook signing secret' });
});

test('AWS access key IDs, with and without a nearby secret access key', () => {
  const id = assertSecret(AWS_ID, { provider: 'AWS', kind: 'access key ID' });
  assertWarning(id, 'caution', /access key ID alone/);
  assertSecret('ASIAY34FZKBOKMUTVV7A', { provider: 'AWS', kind: 'temporary access key ID' });
  const cfg = analyzePayload({ text: `[default]\naws_access_key_id = ${AWS_ID}\naws_secret_access_key = ${AWS_SECRET}\nregion = eu-west-1` });
  assert.equal(cfg.data.format, 'api-secret');
  assert.equal(cfg.data.embedded, true);
  assert.deepEqual(cfg.data.secrets.map((s) => s.id), ['aws-access-key', 'aws-secret-key']);
  assertWarning(cfg, 'danger', /together with its secret access key/);
  assertNoWarning(cfg, 'caution', /alone/);
  assert.ok(field(cfg, 'AWS secret access key').sensitive);
  assert.equal(field(cfg, 'AWS secret access key').value, AWS_SECRET);
  assert.ok(field(cfg, 'Text').sensitive, 'the whole text is masked too');
  assert.ok(cfg.actions.every((x) => x.sensitive), 'every copy is sensitive');
  assert.ok(!JSON.stringify(cfg.data).includes(AWS_SECRET));
  // A far-away 40-char string is not paired; a 40-hex SHA-1 is never a secret key.
  assert.equal(findApiSecrets(`${AWS_ID}${' '.repeat(600)}${AWS_SECRET}`).length, 1);
  assert.equal(findApiSecrets(`${AWS_ID} da39a3ee5e6b4b0d3255bfef95601890afd80709`).length, 1);
});

test('GitHub, GitLab, Slack, Google, OpenAI, Anthropic, npm and others', () => {
  const tail36 = 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
  assertSecret(`ghp_${tail36}`, { provider: 'GitHub', kind: 'personal access token' });
  assertSecret(`gho_${tail36}`, { provider: 'GitHub', kind: 'OAuth token' });
  assertSecret(`ghu_${tail36}`, { provider: 'GitHub', kind: 'user-to-server token' });
  assertSecret(`ghs_${tail36}`, { provider: 'GitHub', kind: 'server-to-server token' });
  assertSecret(`ghr_${tail36}`, { provider: 'GitHub', kind: 'refresh token' });
  assertSecret(`github_pat_11ABCDEFG0123456789abc_${'x1Y2'.repeat(15)}`, { provider: 'GitHub', kind: 'fine-grained personal access token' });
  assertSecret('glpat-x9Yz8WvU7tSr6QpOn5Ml', { provider: 'GitLab' });
  for (const p of 'abpors') assertSecret(`xox${p}-17653672481-19874698323-pdFZKVeTuE8sk7oOcBrzbqgy`, { provider: 'Slack' });
  assertSecret('AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI', { provider: 'Google', kind: 'API key' });
  assertSecret(`sk-ant-api03-${'Ab1_'.repeat(20)}`, { provider: 'Anthropic', kind: 'API key', id: 'anthropic' });
  assertSecret(`sk-ant-admin01-${'Ab1-'.repeat(20)}`, { provider: 'Anthropic', kind: 'admin API key' });
  assertSecret(`sk-proj-${'Zx9_'.repeat(20)}`, { provider: 'OpenAI', kind: 'project API key' });
  assertSecret(`sk-${'aB3'.repeat(16)}`, { provider: 'OpenAI', kind: 'API key' });
  assertSecret(`npm_${'a1B2'.repeat(9)}`, { provider: 'npm', kind: 'access token' });
  assertSecret(`pypi-AgEIcHlwaS5vcmc${'Ab1'.repeat(20)}`, { provider: 'PyPI' });
  assertSecret(`SG.${'aB3_'.repeat(5)}aB.${'cD4-'.repeat(10)}cD4`, { provider: 'SendGrid' });
  assertSecret(`shpat_${'0a1b2c3d'.repeat(4)}`, { provider: 'Shopify', kind: 'access token' });
});

test('runs before base64 (an AWS key ID / Stripe key is valid base64) and catches embedded keys', () => {
  assert.equal(analyze(AWS_ID).parser, 'api-secret');
  assert.equal(analyze(STRIPE).parser, 'api-secret');
  const env = analyzePayload({ text: `STRIPE_SECRET_KEY=${STRIPE}\nDEBUG=1` });
  assert.equal(env.data.format, 'api-secret');
  assert.equal(env.summary, 'Text with a Stripe live secret key');
  assert.equal(action(env, /Copy secret/).value, STRIPE);
  const two = analyzePayload({ text: `gh: ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\nstripe: ${STRIPE}` });
  assert.match(two.summary, /^Text with 2 credentials \(GitHub, Stripe\)$/);
  // JSON keeps its own presentation but flags a value that is an API secret.
  const json = analyzePayload({ text: `{"config":{"stripe":"${STRIPE}"}}` });
  assert.equal(json.type, 'json');
  assertWarning(json, 'danger', DANGER);
  assert.ok(json.fields.some((f) => f.value === STRIPE && f.sensitive));
  assert.ok(json.actions.every((x) => x.sensitive));
  assert.ok(isApiSecret(STRIPE) && !isApiSecret(`x ${STRIPE}`));
});

test('negatives: publishable keys, words, short / wrong-length tokens, prefixes inside words', () => {
  const not = [
    'pk_live_4eC39HqLyjWDarjtT1zdp7dc', // Stripe publishable key: meant to be public
    'sk_live_short1', 'AKIAIOSFODNN7EXAMPL', 'AKIAIOSFODNN7EXAMPLE1', 'XAKIAIOSFODNN7EXAMPLE', 'akiaiosfodnn7example',
    'ghp_short', `ghx_${'a1'.repeat(18)}`, `ghp_${'a'.repeat(36)}`, 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsH', // 38
    'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHIx', // 40
    'sk-abcdefghijklmnopqrstuvwxyzabcdefghij', // no digits: a word-ish run, not a key
    'sk-1234', 'my-task-sk-skills', 'xoxb-not-a-token', 'xoxq-1234567890-abcdefgh1234', `npm_${'a1'.repeat(17)}`,
    'Use the sk_live_ prefix for live keys', 'risk_live_4eC39HqLyjWDarjtT1zdp7dc', 'disk-' + 'aB3'.repeat(16),
    'deadbeefdeadbeefdeadbeefdeadbeef', 'Hello, this is just some text with AKIA in it',
  ];
  for (const text of not) {
    const a = analyzePayload({ text });
    assert.notEqual(a.data.format, 'api-secret', `${text} must not be a secret`);
    assertNoWarning(a, 'danger', DANGER);
  }
  // A URL carrying a key is still a URL (the URL parser runs first).
  assert.equal(analyzePayload({ text: 'https://maps.example/?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI' }).type, 'url');
  // Huge texts are not scanned (bounded work).
  assert.equal(findApiSecrets(`${'x '.repeat(10000)}${STRIPE}`).length, 0);
});

test('secret parser never throws on mutated input', () => {
  assert.ok(fuzz(`aws_access_key_id=${AWS_ID} aws_secret_access_key=${AWS_SECRET}`, { step: 3 }) > 10);
  assert.ok(fuzz(STRIPE) > 10);
});

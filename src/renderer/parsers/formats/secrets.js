// API secrets and credentials (PAYLOADS.md §11.6 family): well-specified token formats
// with a fixed prefix and a random tail — Stripe, AWS access keys (+ a nearby secret
// access key), GitHub, GitLab, Slack, Google API keys, OpenAI / Anthropic keys, npm,
// PyPI, SendGrid, Shopify. `type: 'text'`, `data.format: 'api-secret'`, danger warning,
// values sensitive. Runs as a late parser before the generic base64 heuristic (an AWS
// key ID or a GitHub token is valid base64 too). Secret values never go into `data`.

import { createReport, prep, truncate } from './util.js';

const MESSAGE = 'Looks like an API secret/credential — don\'t share it';
/** Embedded tokens are only searched for in texts up to this size (UTF-16 units). */
const MAX_SCAN = 16 * 1024;
/** How far (UTF-16 units) from an AWS key ID a 40-char secret access key is looked for. */
const AWS_SECRET_DISTANCE = 400;

// `(?<![\w-])…(?![\w-])`: the token must not be part of a longer word. Every quantifier is
// bounded or followed by a fixed boundary, so each pattern scans in linear time.
const GITHUB_KINDS = { p: 'personal access token', o: 'OAuth token', u: 'user-to-server token', s: 'server-to-server token', r: 'refresh token' };
const PATTERNS = [
  {
    id: 'stripe', provider: 'Stripe',
    re: /(?<![\w-])([sr]k)_(live|test)_([0-9A-Za-z]{20,247})(?![\w-])/g,
    kind: (m) => `${m[2]} ${m[1] === 'sk' ? 'secret' : 'restricted'} key`,
    tail: (m) => m[3],
    mode: (m) => m[2],
  },
  {
    id: 'stripe-webhook', provider: 'Stripe',
    re: /(?<![\w-])whsec_([0-9A-Za-z+/]{32,256}={0,2})(?![\w-])/g,
    kind: () => 'webhook signing secret',
  },
  {
    id: 'aws-access-key', provider: 'AWS',
    re: /(?<![A-Za-z0-9])(AKIA|ASIA)([A-Z0-9]{16})(?![A-Za-z0-9])/g,
    kind: (m) => (m[1] === 'ASIA' ? 'temporary access key ID' : 'access key ID'),
    tail: (m) => m[2],
  },
  {
    id: 'github', provider: 'GitHub',
    re: /(?<![\w-])gh([pousr])_([A-Za-z0-9]{36,251})(?![\w-])/g,
    kind: (m) => GITHUB_KINDS[m[1]],
  },
  {
    id: 'github-pat', provider: 'GitHub',
    re: /(?<![\w-])github_pat_([A-Za-z0-9_]{60,251})(?![\w-])/g,
    kind: () => 'fine-grained personal access token',
  },
  {
    id: 'gitlab', provider: 'GitLab',
    re: /(?<![\w-])glpat-([A-Za-z0-9_-]{20,64})(?![\w-])/g,
    kind: () => 'personal access token',
  },
  {
    id: 'slack', provider: 'Slack',
    re: /(?<![\w-])xox([abpors])-((?:\d{1,20}-){1,4}[0-9A-Za-z]{8,64})(?![\w-])/g,
    kind: (m) => ({ b: 'bot token', p: 'user token', a: 'app token', o: 'OAuth token', r: 'refresh token', s: 'session token' })[m[1]],
  },
  {
    id: 'google-api-key', provider: 'Google',
    re: /(?<![\w-])AIza([0-9A-Za-z_-]{35})(?![\w-])/g,
    kind: () => 'API key',
  },
  {
    id: 'anthropic', provider: 'Anthropic',
    re: /(?<![\w-])sk-ant-([a-z]{2,10}\d{2})-([A-Za-z0-9_-]{32,256})(?![\w-])/g,
    kind: (m) => (m[1].startsWith('admin') ? 'admin API key' : m[1].startsWith('oat') ? 'OAuth token' : 'API key'),
    tail: (m) => m[2],
  },
  {
    id: 'openai', provider: 'OpenAI',
    re: /(?<![\w-])sk-(proj-|svcacct-|admin-)?([A-Za-z0-9_-]{32,256})(?![\w-])/g,
    kind: (m) => (m[1] === 'proj-' ? 'project API key' : m[1] === 'svcacct-' ? 'service account key' : m[1] === 'admin-' ? 'admin API key' : 'API key'),
    tail: (m) => m[2],
    // `sk-ant-…` is Anthropic's (matched above; overlaps are dropped).
    accept: (m) => !m[2].startsWith('ant-'),
  },
  {
    id: 'npm', provider: 'npm',
    re: /(?<![\w-])npm_([A-Za-z0-9]{36})(?![\w-])/g,
    kind: () => 'access token',
  },
  {
    id: 'pypi', provider: 'PyPI',
    re: /(?<![\w-])pypi-(AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000})(?![\w-])/g,
    kind: () => 'API token',
  },
  {
    id: 'sendgrid', provider: 'SendGrid',
    re: /(?<![\w.-])SG\.([A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![\w.-])/g,
    kind: () => 'API key',
  },
  {
    id: 'shopify', provider: 'Shopify',
    re: /(?<![\w-])shp(at|ca|pa|ss)_([a-fA-F0-9]{32})(?![\w-])/g,
    kind: (m) => ({ at: 'access token', ca: 'custom app token', pa: 'private app token', ss: 'shared secret' })[m[1]],
    tail: (m) => m[2],
  },
];

/** Random-looking tail: at least one digit and one letter (rules out `sk-aaaa…` words). */
const looksRandom = (s) => /[0-9]/.test(s) && /[A-Za-z]/.test(s);

const AWS_SECRET_RE = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g;

/** A 40-char AWS secret access key within AWS_SECRET_DISTANCE of `at`, or null. */
function nearbyAwsSecret(text, start, end) {
  const lo = Math.max(0, start - AWS_SECRET_DISTANCE);
  const window = text.slice(lo, Math.min(text.length, end + AWS_SECRET_DISTANCE));
  for (const m of window.matchAll(AWS_SECRET_RE)) {
    const v = m[0];
    // Base64-ish random: upper + lower + digit (a 40-hex SHA-1 or a word run is not it).
    if (/[A-Z]/.test(v) && /[a-z]/.test(v) && /[0-9]/.test(v)) return { value: v, start: lo + m.index, end: lo + m.index + 40 };
  }
  return null;
}

let lastText = null;
let lastFound = null;

/**
 * Finds API secrets in `text` (non-overlapping, in order).
 * @returns {Array<{ id, provider, kind, value, start, end, mode? }>}
 */
export function findApiSecrets(text) {
  const t = String(text ?? '');
  if (t === lastText) return lastFound;
  const found = [];
  if (t.length <= MAX_SCAN && t.length >= 20) {
    for (const p of PATTERNS) {
      for (const m of t.matchAll(p.re)) {
        const tail = p.tail ? p.tail(m) : m[m.length - 1];
        if (!looksRandom(tail) || (p.accept && !p.accept(m))) continue;
        const item = { id: p.id, provider: p.provider, kind: p.kind(m), value: m[0], start: m.index, end: m.index + m[0].length };
        if (p.mode) item.mode = p.mode(m);
        found.push(item);
      }
    }
    found.sort((a, b) => a.start - b.start || b.end - a.end);
    for (let i = 1; i < found.length; i++) {
      if (found[i].start < found[i - 1].end) found.splice(i--, 1);
    }
    for (let i = 0; i < found.length; i++) {
      const f = found[i];
      if (f.id !== 'aws-access-key') continue;
      const s = nearbyAwsSecret(t, f.start, f.end);
      if (s && !found.some((o) => o.start < s.end && s.start < o.end)) {
        found.splice(i + 1, 0, { id: 'aws-secret-key', provider: 'AWS', kind: 'secret access key', ...s });
        i++;
      }
    }
    found.sort((a, b) => a.start - b.start);
  }
  lastText = t;
  lastFound = found;
  return found;
}

/** True when the whole `text` is a single API secret. */
export function isApiSecret(text) {
  const t = String(text ?? '');
  const f = findApiSecrets(t);
  return f.length === 1 && f[0].start === 0 && f[0].end === t.length;
}

/** "sk_live_…" — the non-secret prefix of a token, for data / summaries. */
function prefixOf(item) {
  const m = /^(?:AKIA|ASIA|AIza|SG\.|[A-Za-z]+[_-](?:(?:live|test|ant-[a-z]+\d*|proj|svcacct|admin|pat)[_-])?)/.exec(item.value);
  return m && item.id !== 'aws-secret-key' ? `${m[0]}…` : '…';
}

const label = (f) => `${f.provider} ${f.kind}`;

export const apiSecret = {
  id: 'api-secret',
  phase: 'late', // after URL / JSON (a link or JSON may carry keys; they say so themselves), before base64
  label: 'API secret',
  detect(text) {
    return findApiSecrets(prep(text)).length > 0;
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const found = findApiSecrets(t);
    if (!found.length) return null;
    const whole = found.length === 1 && found[0].start === 0 && found[0].end === t.length;
    const awsPair = found.some((f) => f.id === 'aws-access-key') && found.some((f) => f.id === 'aws-secret-key');

    r.warn('danger', MESSAGE);
    if (awsPair) r.warn('danger', 'Contains an AWS access key ID together with its secret access key — anyone who sees this code can use the AWS account');
    else if (found.some((f) => f.id === 'aws-access-key')) r.warn('caution', 'An AWS access key ID alone cannot sign requests, but it identifies the account; its secret key may be nearby');
    if (found.some((f) => f.mode === 'test')) r.warn('info', 'Stripe test-mode key (no real payments), still a credential');
    if (found.some((f) => f.id === 'google-api-key')) r.warn('info', 'Google API keys are sometimes public (e.g. in web pages) but are often unrestricted and billable');
    r.warn('info', 'If this credential was shared unintentionally, revoke it with the provider');

    const providers = [...new Set(found.map((f) => f.provider))];
    if (providers.length === 1) r.field('Provider', providers[0], { check: false });
    for (const f of found) r.field(label(f), f.value, { sensitive: true, mono: true, check: false });
    if (!whole) r.field('Text', t, { sensitive: true });
    for (const f of found) r.copy(found.length > 1 ? `Copy ${label(f)}` : 'Copy secret', f.value, { sensitive: true });
    if (!whole) r.copy('Copy text', t, { sensitive: true });

    const first = found[0];
    const title = whole ? label(first) : 'API secret';
    const summary = whole
      ? `${label(first)} (${prefixOf(first)})`
      : found.length === 1 ? `Text with a ${label(first)}`
        : `Text with ${found.length} credentials (${truncate(providers.join(', '), 60)})`;
    return r.result({
      type: 'text',
      title,
      summary,
      data: {
        format: 'api-secret',
        provider: providers.length === 1 ? providers[0] : null,
        embedded: !whole,
        secrets: found.map((f) => ({ id: f.id, provider: f.provider, kind: f.kind, prefix: prefixOf(f), length: f.value.length, ...(f.mode ? { mode: f.mode } : {}) })),
      },
    });
  },
};

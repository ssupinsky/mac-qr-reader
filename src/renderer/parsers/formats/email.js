// Email payloads (PAYLOADS.md §5): `mailto:` (RFC 6068, `+` is literal), DoCoMo
// `MATMSG:` and ZXing `SMTP:`.

import {
  createReport, hasPrefix, prep, pctDecode, tokenizeDocomo, unescapeBackslash, embeddedUrlWarnings,
  extractUrls, isEmailAddress, domainWarnings, truncate, encodeComponent,
} from './util.js';
import { setOwn } from '../dict.js';

const KNOWN_HFIELDS = new Set(['to', 'cc', 'bcc', 'subject', 'body', 'in-reply-to']);
const ATTACH_HFIELDS = new Set(['attach', 'attachment', 'attachments']);

/** Percent-encodes for a mailto: URI while keeping `@` readable. */
const enc = (s) => encodeComponent(s).replace(/%40/g, '@');

/** Builds a normalised mailto: URI (used for Open). */
export function buildMailto({ to = [], cc = [], bcc = [], subject, body }) {
  const q = [];
  if (cc.length) q.push(`cc=${cc.map(enc).join(',')}`);
  if (bcc.length) q.push(`bcc=${bcc.map(enc).join(',')}`);
  if (subject) q.push(`subject=${encodeComponent(subject)}`);
  if (body) q.push(`body=${encodeComponent(body)}`);
  return `mailto:${to.map(enc).join(',')}${q.length ? `?${q.join('&')}` : ''}`;
}

/** Shared presentation + checks for all three email formats. */
function present(r, ctx, msg, format) {
  const all = [...msg.to, ...msg.cc, ...msg.bcc];
  const checkAddr = (addr, label) => {
    if (!isEmailAddress(addr)) {
      r.warn('caution', `${label} "${truncate(addr, 50)}" is not a valid email address`);
      return;
    }
    r.warnAll(domainWarnings(addr.slice(addr.lastIndexOf('@') + 1), `${label} domain`));
  };
  msg.to.forEach((a) => checkAddr(a, 'Recipient'));
  msg.cc.forEach((a) => checkAddr(a, 'Cc recipient'));
  msg.bcc.forEach((a) => checkAddr(a, 'Bcc recipient'));
  if (!all.length) r.warn('info', 'No recipient — you would choose one in Mail');
  if (msg.bcc.length) r.warn('caution', `Hidden recipients (Bcc: ${msg.bcc.join(', ')})`);
  if (all.length > 5) r.warn('caution', `Sends to ${all.length} recipients`);
  if ((msg.body || '').length > 1000) r.warn('info', `Long message body (${msg.body.length} characters)`);

  if (msg.to.length) r.field(msg.to.length > 1 ? 'To' : 'To', msg.to.join(', '), { mono: true, copy: true });
  if (msg.cc.length) r.field('Cc', msg.cc.join(', '), { mono: true });
  if (msg.bcc.length) r.field('Bcc', msg.bcc.join(', '), { mono: true });
  r.field('Subject', msg.subject, { singleLine: true });
  if (msg.inReplyTo) r.field('In reply to', msg.inReplyTo, { mono: true });
  r.field('Message', msg.body, { copy: true });
  for (const url of extractUrls(msg.body)) r.warnAll(embeddedUrlWarnings(url, ctx, 'Message link'));
  for (const url of extractUrls(msg.subject)) r.warnAll(embeddedUrlWarnings(url, ctx, 'Subject link'));

  if (!r.hasLevel('danger')) r.open('Compose email…', buildMailto(msg));
  if (all.length) r.copy(all.length > 1 ? 'Copy addresses' : 'Copy address', msg.to.length ? msg.to.join(', ') : all.join(', '));
  if (msg.body) r.copy('Copy message', msg.body);

  const subj = msg.subject ? ` — “${truncate(msg.subject, 50)}”` : '';
  return r.result({
    type: 'email',
    title: 'Email',
    summary: `Email to ${msg.to.join(', ') || all.join(', ') || '(no recipient)'}${subj}`,
    data: { format, ...msg },
  });
}

const splitAddrs = (s) => s.split(',').map((a) => a.trim()).filter(Boolean);

export const mailto = {
  id: 'mailto',
  label: 'mailto',
  detect(text) {
    return hasPrefix(prep(text), 'mailto:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const rest = prep(text).slice(7).replace(/#.*$/s, '');
    const q = rest.indexOf('?');
    const toPart = q < 0 ? rest : rest.slice(0, q);
    const query = q < 0 ? '' : rest.slice(q + 1);
    const msg = { to: [], cc: [], bcc: [], subject: undefined, body: undefined, inReplyTo: undefined, extra: {} };
    let malformed = false;
    const dec = (s) => {
      const d = pctDecode(s);
      if (!d.ok) malformed = true;
      return d.value;
    };
    msg.to.push(...toPart.split(',').map((a) => dec(a).trim()).filter(Boolean));
    for (const part of query.split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const name = dec(eq < 0 ? part : part.slice(0, eq)).toLowerCase();
      const value = eq < 0 ? '' : dec(part.slice(eq + 1));
      if (name === 'to' || name === 'cc' || name === 'bcc') msg[name].push(...splitAddrs(value));
      else if (name === 'subject') msg.subject ??= value;
      else if (name === 'body') msg.body ??= value;
      else if (name === 'in-reply-to') msg.inReplyTo ??= value;
      else {
        setOwn(msg.extra, name, value);
        if (ATTACH_HFIELDS.has(name)) r.warn('danger', `Tries to attach a local file "${truncate(value, 60)}"`);
        else if (!KNOWN_HFIELDS.has(name)) r.warn('info', `Unusual header "${name}"`);
      }
    }
    if (malformed) r.warn('info', 'Some parts are not valid percent-encoding; shown as-is');
    if (!Object.keys(msg.extra).length) delete msg.extra;
    for (const [k, v] of Object.entries(msg.extra || {})) r.field(`Header ${k}`, v, { mono: true });
    return present(r, ctx, msg, 'mailto');
  },
};

export const matmsg = {
  id: 'matmsg',
  label: 'MATMSG',
  detect(text) {
    return hasPrefix(prep(text), 'MATMSG:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const { tokens, terminated } = tokenizeDocomo(prep(text).slice(7));
    if (!terminated) r.warn('info', 'Not properly terminated (missing ";;")');
    const msg = { to: [], cc: [], bcc: [], subject: undefined, body: undefined };
    for (const { key, raw } of tokens) {
      const value = unescapeBackslash(raw);
      if (key === 'TO') msg.to.push(...splitAddrs(value));
      else if (key === 'CC') msg.cc.push(...splitAddrs(value));
      else if (key === 'BCC') msg.bcc.push(...splitAddrs(value));
      else if (key === 'SUB') msg.subject ??= value;
      else if (key === 'BODY') msg.body ??= value;
      else r.warn('info', `Unknown field "${key}"`);
    }
    return present(r, ctx, msg, 'matmsg');
  },
};

export const smtp = {
  id: 'smtp',
  label: 'SMTP',
  detect(text) {
    return hasPrefix(prep(text), 'SMTP:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const rest = prep(text).slice(5);
    const c1 = rest.indexOf(':');
    const c2 = c1 < 0 ? -1 : rest.indexOf(':', c1 + 1);
    const to = c1 < 0 ? rest : rest.slice(0, c1);
    const subject = c1 < 0 ? undefined : c2 < 0 ? rest.slice(c1 + 1) : rest.slice(c1 + 1, c2);
    const body = c2 < 0 ? undefined : rest.slice(c2 + 1);
    const msg = { to: splitAddrs(to), cc: [], bcc: [], subject, body };
    return present(r, ctx, msg, 'smtp');
  },
};

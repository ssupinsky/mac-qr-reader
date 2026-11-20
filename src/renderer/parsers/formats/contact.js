// Contacts (PAYLOADS.md §4): vCard 2.1/3.0/4.0, DoCoMo MECARD, BIZCARD, plus vCard 3.0
// generation for "Save contact…" (§4.2).

import {
  createReport, hasPrefix, prep, tokenizeDocomo, splitUnescaped, unescapeBackslash, toCrlf,
  embeddedUrlWarnings, isEmailAddress, domainWarnings, sanitizeFileName, utf8Length, truncate,
} from './util.js';
import { readContentLines, param, decodeQuotedPrintable, splitStructured, unescapeText } from './contentline.js';
import { stripTrailing } from '../strings.js';
import { analyzePhoneNumber } from './phone.js';
import { getOwn } from '../dict.js';

// ---------------------------------------------------------------------------
// vCard generation (§4.2)
// ---------------------------------------------------------------------------

/** Escapes a vCard 3.0 TEXT value. */
export function escapeVcardText(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/,/g, '\\,')
    .replace(/;/g, '\\;')
    .replace(/\r\n|\n|\r/g, '\\n');
}

/** Folds a content line to ≤ 75 octets per physical line (continuations start with a space). */
export function foldLine(line) {
  if (utf8Length(line) <= 75) return line;
  const out = [];
  let cur = '';
  let curLen = 0;
  for (const ch of line) {
    const len = utf8Length(ch);
    const limit = out.length === 0 ? 75 : 74;
    if (curLen + len > limit) {
      out.push(cur);
      cur = '';
      curLen = 0;
    }
    cur += ch;
    curLen += len;
  }
  out.push(cur);
  return out.join('\r\n ');
}

/**
 * Builds a vCard 3.0 (CRLF, folded) from a simple contact description.
 * @param {{ family?: string, given?: string, fn?: string, phoneticFamily?: string, phoneticGiven?: string,
 *   tel?: Array<{ value: string, type?: string }>, email?: string[], adr?: string, bday?: string,
 *   note?: string, url?: string[], nickname?: string, org?: string, title?: string }} c
 * @returns {string}
 */
export function buildVcard(c) {
  const lines = ['BEGIN:VCARD', 'VERSION:3.0'];
  const fn = c.fn || [c.given, c.family].filter(Boolean).join(' ') || c.org || 'Contact';
  lines.push(`N:${escapeVcardText(c.family)};${escapeVcardText(c.given)};;;`);
  lines.push(`FN:${escapeVcardText(fn)}`);
  if (c.phoneticFamily) lines.push(`X-PHONETIC-LAST-NAME:${escapeVcardText(c.phoneticFamily)}`);
  if (c.phoneticGiven) lines.push(`X-PHONETIC-FIRST-NAME:${escapeVcardText(c.phoneticGiven)}`);
  if (c.org) lines.push(`ORG:${escapeVcardText(c.org)}`);
  if (c.title) lines.push(`TITLE:${escapeVcardText(c.title)}`);
  for (const t of c.tel || []) lines.push(`TEL${t.type ? `;TYPE=${t.type}` : ''}:${escapeVcardText(t.value)}`);
  for (const e of c.email || []) lines.push(`EMAIL;TYPE=INTERNET:${escapeVcardText(e)}`);
  if (c.adr) lines.push(`ADR:;;${escapeVcardText(c.adr)};;;;`);
  if (c.bday) lines.push(`BDAY:${escapeVcardText(c.bday)}`);
  if (c.nickname) lines.push(`NICKNAME:${escapeVcardText(c.nickname)}`);
  for (const u of c.url || []) lines.push(`URL:${escapeVcardText(u)}`);
  if (c.note) lines.push(`NOTE:${escapeVcardText(c.note)}`);
  lines.push('END:VCARD');
  return lines.map(foldLine).join('\r\n') + '\r\n';
}

// ---------------------------------------------------------------------------
// Shared presentation of a contact's details
// ---------------------------------------------------------------------------

function checkPhone(r, value, label) {
  const number = value.replace(/^tel:/i, '').split(';')[0];
  r.warnAll(analyzePhoneNumber(number, { label }).warnings);
}

function checkEmail(r, value, label) {
  if (!isEmailAddress(value)) r.warn('caution', `${label} "${truncate(value, 40)}" is not a valid email address`);
  else r.warnAll(domainWarnings(value.slice(value.lastIndexOf('@') + 1), `${label} domain`));
}

const BDAY_RE = /^(\d{4})-?(\d{2})-?(\d{2})$/;
function formatDate(v) {
  const m = BDAY_RE.exec(v);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  const noYear = /^--(\d{2})-?(\d{2})$/.exec(v);
  if (noYear) return `--${noYear[1]}-${noYear[2]}`;
  return v;
}

// ---------------------------------------------------------------------------
// vCard parsing (§4.1)
// ---------------------------------------------------------------------------

const STRUCTURED = new Set(['N', 'ADR', 'ORG', 'GENDER']);
const MEDIA = new Set(['PHOTO', 'LOGO', 'SOUND', 'KEY']);

/** Strips Apple's `_$!<Label>!$_` wrapper. */
const appleLabel = (s) => s.replace(/^_\$!<(.*)>!\$_$/, '$1');

/** Parses one card's content lines into a plain object; warnings go to `r`. */
function parseCard(lines, r, prefix) {
  const card = { version: null, fn: null, n: null, org: [], tel: [], email: [], adr: [], url: [], other: [] };
  const groupLabels = new Map();
  for (const cl of lines) if (cl.name === 'X-ABLABEL' && cl.group) groupLabels.set(cl.group, appleLabel(unescapeText(cl.value)));

  for (const cl of lines) {
    if (cl.name === 'VERSION') {
      card.version = cl.value.trim();
      continue;
    }
    if (cl.name === 'BEGIN' || cl.name === 'END' || cl.name === 'X-ABLABEL') continue;
    const encoding = (param(cl, 'ENCODING') || '').toUpperCase();
    const charset = param(cl, 'CHARSET');
    const v21 = card.version === '2.1';

    // Binary / media values.
    if (MEDIA.has(cl.name)) {
      const valueType = (param(cl, 'VALUE') || '').toLowerCase();
      const value = cl.value.trim();
      const media = { property: cl.name.toLowerCase() };
      if (/^https?:/i.test(value) && encoding !== 'B' && encoding !== 'BASE64') {
        media.kind = 'remote';
        media.uri = value;
        r.warn('caution', `${prefix}contains a remote ${cl.name === 'SOUND' ? 'sound' : cl.name === 'KEY' ? 'key' : 'image'} link (${truncate(value, 60)}); Contacts may fetch it (tracking)`);
      } else if (encoding === 'B' || encoding === 'BASE64' || /^data:/i.test(value) || valueType === 'binary') {
        media.kind = 'inline';
        const b64 = value.replace(/^data:[^,]*,/i, '').replace(/\s+/g, '');
        media.size = Math.floor((b64.length * 3) / 4);
        if (media.size > 32 * 1024) r.warn('info', `${prefix}contains a large embedded ${cl.name.toLowerCase()} (${Math.round(media.size / 1024)} KB)`);
      } else {
        media.kind = 'uri';
        media.uri = value;
      }
      card[cl.name.toLowerCase()] = media;
      continue;
    }

    // Text decoding.
    let value = cl.value;
    if (encoding === 'QUOTED-PRINTABLE') {
      const dec = decodeQuotedPrintable(value, charset || 'utf-8');
      value = dec.text;
      if (!dec.charsetOk) r.warn('info', `${prefix}unknown character set "${charset}"; decoded as UTF-8`);
    }
    const unesc = v21 ? (s) => s.replace(/\\;/g, ';') : unescapeText;
    const parts = STRUCTURED.has(cl.name) ? splitStructured(value, ';').map(unesc) : null;
    const text = parts ? parts.join(';') : unesc(value);
    const types = (cl.params.TYPE || []).map((t) => t.toLowerCase());
    const label = (cl.group && groupLabels.get(cl.group)) || null;

    switch (cl.name) {
      case 'FN': card.fn ??= text; break;
      case 'N': {
        const [family = '', given = '', additional = '', prefixN = '', suffix = ''] = parts;
        card.n ??= { family, given, additional, prefix: prefixN, suffix };
        break;
      }
      case 'ORG': if (!card.org.length) card.org = parts.filter((p) => p !== ''); break;
      case 'TEL': card.tel.push({ value: text.trim(), types, ...(label ? { label } : {}) }); break;
      case 'EMAIL': card.email.push({ value: text.trim(), types: types.filter((t) => t !== 'internet'), ...(label ? { label } : {}) }); break;
      case 'ADR': {
        const [pobox = '', ext = '', street = '', locality = '', region = '', postal = '', country = ''] = parts;
        card.adr.push({ pobox, ext, street, locality, region, postal, country, types, ...(label ? { label } : {}) });
        break;
      }
      case 'URL': card.url.push(text.trim()); break;
      case 'TITLE': card.title ??= text; break;
      case 'ROLE': card.role ??= text; break;
      case 'NOTE': card.note = card.note ? `${card.note}\n${text}` : text; break;
      case 'NICKNAME': card.nickname ??= text; break;
      case 'BDAY': card.bday ??= formatDate(text.trim()); break;
      case 'ANNIVERSARY': card.anniversary ??= formatDate(text.trim()); break;
      case 'CATEGORIES': card.categories ??= splitStructured(cl.value, ',').map(unesc).filter(Boolean); break;
      case 'GEO': card.geo ??= text.replace(/^geo:/i, ''); break;
      case 'TZ': card.tz ??= text; break;
      case 'UID': card.uid ??= text; break;
      case 'REV': case 'PRODID': case 'SOURCE': case 'KIND': case 'GENDER': case 'LANG': case 'SORT-STRING': {
        const key = { 'SORT-STRING': 'sortString' }[cl.name] ?? cl.name.toLowerCase();
        card[key] ??= text;
        break;
      }
      default:
        card.other.push({ name: cl.name, value: text, ...(label ? { label } : {}) });
    }
  }
  if (!card.fn && card.n) {
    const { prefix: p, given, additional, family, suffix } = card.n;
    card.fn = [p, given, additional, family, suffix].filter(Boolean).join(' ') || null;
  }
  return card;
}

const TYPE_LABELS = { cell: 'mobile', voice: '', pref: '', internet: '', x400: '' };
function typeSuffix(entry) {
  if (entry.label) return ` (${entry.label})`;
  const t = entry.types.map((x) => getOwn(TYPE_LABELS, x) ?? x).filter(Boolean);
  return t.length ? ` (${[...new Set(t)].join(', ')})` : '';
}

function formatAdr(a) {
  return [a.pobox, a.ext, a.street, a.locality, a.region, a.postal, a.country]
    .filter(Boolean).join(', ').replace(/\r?\n/g, ', ');
}

/** Adds fields + warnings for one parsed vCard. */
function presentCard(r, card, ctx, prefix) {
  const P = (label) => `${prefix}${label}`;
  r.field(P('Name'), card.fn, { name: true, singleLine: true, copy: true });
  r.field(P('Organization'), card.org.join(' · '), { name: true });
  r.field(P('Job title'), card.title);
  r.field(P('Role'), card.role);
  for (const t of card.tel) {
    r.field(P(`Phone${typeSuffix(t)}`), t.value, { mono: true, singleLine: true, copy: true });
    checkPhone(r, t.value, P('Phone number'));
  }
  for (const e of card.email) {
    r.field(P(`Email${typeSuffix(e)}`), e.value, { mono: true, singleLine: true, copy: true });
    checkEmail(r, e.value, P('Email'));
  }
  for (const a of card.adr) r.field(P(`Address${typeSuffix(a)}`), formatAdr(a));
  for (const u of card.url) {
    r.field(P('Website'), u, { mono: true, copy: true });
    r.warnAll(embeddedUrlWarnings(u, ctx, P('Website')));
  }
  r.field(P('Birthday'), card.bday, { check: false });
  r.field(P('Anniversary'), card.anniversary, { check: false });
  r.field(P('Nickname'), card.nickname);
  r.field(P('Categories'), card.categories?.join(', '));
  r.field(P('Location'), card.geo, { mono: true });
  r.field(P('Time zone'), card.tz);
  r.field(P('Note'), card.note);
  for (const m of ['photo', 'logo', 'sound', 'key']) {
    const media = card[m];
    if (!media) continue;
    const label = P(m[0].toUpperCase() + m.slice(1));
    if (media.kind === 'inline') r.field(label, `Embedded (${Math.max(1, Math.round(media.size / 1024))} KB)`, { check: false });
    else r.field(label, media.uri, { mono: true });
  }
  for (const o of card.other.slice(0, 20)) {
    if (/^X-(AB|ADDRESSBOOKSERVER)/.test(o.name)) continue;
    const pretty = { IMPP: 'Instant messaging', 'X-SOCIALPROFILE': 'Social profile', RELATED: 'Related', MEMBER: 'Member' }[o.name] || o.name;
    r.field(P(o.label ? `${pretty} (${o.label})` : pretty), o.value);
  }
}

export const vcard = {
  id: 'vcard',
  label: 'vCard',
  detect(text) {
    return hasPrefix(prep(text), 'BEGIN:VCARD');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const lines = readContentLines(t);
    const cards = [];
    let current = null;
    let truncated = false;
    for (const cl of lines) {
      if (cl.name === 'BEGIN' && cl.value.trim().toUpperCase() === 'VCARD') {
        if (current) truncated = true;
        current = [];
        cards.push(current);
      } else if (cl.name === 'END' && cl.value.trim().toUpperCase() === 'VCARD') {
        current = null;
      } else if (current) {
        current.push(cl);
      }
    }
    if (current) truncated = true;
    if (truncated) r.warn('info', 'The contact data seems truncated (missing END:VCARD)');

    const parsed = cards.map((lines, i) => parseCard(lines, r, cards.length > 1 ? `Contact ${i + 1}: ` : ''));
    const first = parsed[0] || parseCard([], r, '');
    if (parsed.length > 1) r.warn('info', `This code contains ${parsed.length} contacts`);
    for (const [i, card] of parsed.entries()) {
      const p = parsed.length > 1 ? `Contact ${i + 1}: ` : '';
      if (!card.version) r.warn('info', `${p}no VERSION line`);
      else if (!['2.1', '3.0', '4.0'].includes(card.version)) r.warn('info', `${p}unknown vCard version ${card.version}`);
      presentCard(r, card, ctx, parsed.length > 1 ? `Contact ${i + 1} · ` : '');
    }

    const version = first.version;
    const data = {
      format: ['2.1', '3.0', '4.0'].includes(version) ? `vcard-${version}` : 'vcard',
      ...first,
      ...(parsed.length > 1 ? { cards: parsed } : {}),
    };

    // Save: the original card(s) with CRLF line endings, closed if truncated.
    let vcf = stripTrailing(toCrlf(t), '\r\n');
    if (truncated) vcf += '\r\nEND:VCARD';
    const name = first.fn || first.org[0] || 'contact';
    r.save('Save contact…', `${vcf}\r\n`, `${sanitizeFileName(name, 'contact')}.vcf`, 'vcf');
    if (first.fn) r.copy('Copy name', first.fn);
    if (first.tel[0]) r.copy('Copy phone number', first.tel[0].value);
    if (first.email[0]) r.copy('Copy email', first.email[0].value);

    const display = first.fn || first.org[0] || first.email[0]?.value || first.tel[0]?.value || 'Unnamed contact';
    const org = first.org.length && first.org[0] !== display ? ` — ${first.org[0]}` : '';
    return r.result({
      type: 'contact',
      title: parsed.length > 1 ? `${parsed.length} contacts` : 'Contact',
      summary: `Contact: ${display}${org}${parsed.length > 1 ? ` (+${parsed.length - 1} more)` : ''}`,
      data,
    });
  },
};

// ---------------------------------------------------------------------------
// MECARD (§4.3)
// ---------------------------------------------------------------------------

const MECARD_KEYS = new Set(['N', 'SOUND', 'TEL', 'TEL-AV', 'EMAIL', 'NOTE', 'BDAY', 'ADR', 'URL', 'NICKNAME', 'ORG']);

export const mecard = {
  id: 'mecard',
  label: 'MECARD',
  detect(text) {
    return hasPrefix(prep(text), 'MECARD:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const { tokens, terminated } = tokenizeDocomo(prep(text).slice(7));
    if (!terminated) r.warn('info', 'Not properly terminated (missing ";;")');
    const data = { format: 'mecard', name: { last: '', first: '' }, tel: [], telAv: [], email: [], url: [] };
    const extra = {};
    for (const { key, raw } of tokens) {
      const value = unescapeBackslash(raw);
      switch (key) {
        case 'N': {
          const [last, ...rest] = splitUnescaped(raw, ',').map(unescapeBackslash);
          data.name = { last: last.trim(), first: rest.join(',').trim() };
          break;
        }
        case 'TEL': data.tel.push(value); break;
        case 'TEL-AV': data.telAv.push(value); break;
        case 'EMAIL': data.email.push(value); break;
        case 'URL': data.url.push(value); break;
        case 'BDAY': {
          const m = /^(\d{4})(\d{2})(\d{2})$/.exec(value);
          data.bday = m ? `${m[1]}-${m[2]}-${m[3]}` : value;
          if (!m) r.warn('info', `Birthday "${value}" is not in YYYYMMDD form`);
          break;
        }
        default:
          if (MECARD_KEYS.has(key)) {
            const prop = { SOUND: 'sound', NOTE: 'note', ADR: 'adr', NICKNAME: 'nickname', ORG: 'org' }[key];
            data[prop] ??= value;
          } else {
            extra[key] = value;
            r.warn('info', `Unknown field "${key}"`);
          }
      }
    }
    if (Object.keys(extra).length) data.extra = extra;
    const fn = [data.name.first, data.name.last].filter(Boolean).join(' ');
    const [phoneticFamily, phoneticGiven] = data.sound ? data.sound.split(',') : [];

    r.field('Name', fn, { name: true, singleLine: true, copy: true });
    r.field('Reading', data.sound);
    r.field('Organization', data.org, { name: true });
    for (const tel of data.tel) {
      r.field('Phone', tel, { mono: true, singleLine: true, copy: true });
      checkPhone(r, tel, 'Phone number');
    }
    for (const tel of data.telAv) {
      r.field('Video phone', tel, { mono: true, singleLine: true });
      checkPhone(r, tel, 'Video phone number');
    }
    for (const e of data.email) {
      r.field('Email', e, { mono: true, singleLine: true, copy: true });
      checkEmail(r, e, 'Email');
    }
    r.field('Address', data.adr);
    for (const u of data.url) {
      r.field('Website', u, { mono: true, copy: true });
      r.warnAll(embeddedUrlWarnings(u, ctx, 'Website'));
    }
    r.field('Birthday', data.bday, { check: false });
    r.field('Nickname', data.nickname);
    r.field('Note', data.note);

    const vcf = buildVcard({
      family: data.name.last, given: data.name.first, fn, phoneticFamily, phoneticGiven,
      tel: [...data.tel.map((value) => ({ value })), ...data.telAv.map((value) => ({ value, type: 'video' }))],
      email: data.email, adr: data.adr, bday: data.bday, note: data.note, url: data.url,
      nickname: data.nickname, org: data.org,
    });
    data.vcf = vcf;
    r.save('Save contact…', vcf, `${sanitizeFileName(fn || data.org, 'contact')}.vcf`, 'vcf');
    if (fn) r.copy('Copy name', fn);
    if (data.tel[0]) r.copy('Copy phone number', data.tel[0]);
    if (data.email[0]) r.copy('Copy email', data.email[0]);

    return r.result({
      type: 'contact',
      title: 'Contact',
      summary: `Contact: ${fn || data.org || data.email[0] || data.tel[0] || 'Unnamed contact'}`,
      data,
    });
  },
};

// ---------------------------------------------------------------------------
// BIZCARD (§4.4)
// ---------------------------------------------------------------------------

export const bizcard = {
  id: 'bizcard',
  label: 'BIZCARD',
  detect(text) {
    return hasPrefix(prep(text), 'BIZCARD:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const { tokens, terminated } = tokenizeDocomo(prep(text).slice(8));
    if (!terminated) r.warn('info', 'Not properly terminated (missing ";;")');
    const data = { format: 'bizcard', phones: [], emails: [] };
    const kinds = { B: 'work', M: 'mobile', F: 'fax' };
    for (const { key, raw } of tokens) {
      const value = unescapeBackslash(raw);
      if (key in kinds) data.phones.push({ value, kind: kinds[key] });
      else if (key === 'E') data.emails.push(value);
      else {
        const prop = { N: 'first', X: 'last', T: 'title', C: 'company', A: 'address' }[key];
        if (prop) data[prop] ??= value;
        else r.warn('info', `Unknown field "${key}"`);
      }
    }
    const fn = [data.first, data.last].filter(Boolean).join(' ');
    r.field('Name', fn, { name: true, singleLine: true, copy: true });
    r.field('Job title', data.title);
    r.field('Company', data.company, { name: true });
    for (const p of data.phones) {
      r.field(`Phone (${p.kind})`, p.value, { mono: true, singleLine: true, copy: true });
      checkPhone(r, p.value, 'Phone number');
    }
    for (const e of data.emails) {
      r.field('Email', e, { mono: true, singleLine: true, copy: true });
      checkEmail(r, e, 'Email');
    }
    r.field('Address', data.address);

    const typeOf = { work: 'WORK', mobile: 'CELL', fax: 'FAX' };
    const vcf = buildVcard({
      family: data.last, given: data.first, fn, title: data.title, org: data.company, adr: data.address,
      tel: data.phones.map((p) => ({ value: p.value, type: typeOf[p.kind] })), email: data.emails,
    });
    data.vcf = vcf;
    r.save('Save contact…', vcf, `${sanitizeFileName(fn || data.company, 'contact')}.vcf`, 'vcf');
    if (fn) r.copy('Copy name', fn);
    if (data.phones[0]) r.copy('Copy phone number', data.phones[0].value);
    if (data.emails[0]) r.copy('Copy email', data.emails[0]);

    const who = fn || data.company || 'Unnamed contact';
    return r.result({
      type: 'contact',
      title: 'Business card',
      summary: `Contact: ${who}${data.company && data.company !== who ? ` — ${data.company}` : ''}`,
      data,
    });
  },
};

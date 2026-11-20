// Type-specific presentations ("heroes") shown at the top of an expanded card.
// Each returns { node, hide?: (field) => boolean, filterActions?: (action) => boolean,
//                primary?: () => Promise<{value, sensitive, what}|null>, extraActions?: Node[] }.
import { el } from './dom.js';
import { icon } from './icons.js';
import { copy, openLink } from './actions.js';
import { valueNode, secretValue, copyButton, checkBadge, fieldList, sectionTitle } from './fields.js';
import { displayText } from './text.js';
import { otpWidget } from './otp.js';

const byLabel = (re) => (f) => re.test(f.label);
const find = (a, re) => a.fields.find(byLabel(re));
const tag = (text, tone = 'neutral', ic = null, title = null) =>
  el('span', { class: `tag tag-${tone}`, title }, ic ? icon(ic, { size: 12 }) : null, el('span', { text }));

// ------------------------------------------------------------------------------ URL
/** Host text with every non-ASCII character marked (look-alike letters stand out). */
function hostText(h) {
  const s = String(h || '');
  if (/^[\x21-\x7e]*$/.test(s)) return displayText(s);
  const frag = document.createDocumentFragment();
  let buf = '';
  for (const ch of s) {
    if (ch.codePointAt(0) > 0x7e) {
      if (buf) { frag.append(buf); buf = ''; }
      frag.append(el('mark', { class: 'nonascii', title: `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} — not a plain Latin letter` }, displayText(ch)));
    } else buf += ch;
  }
  if (buf) frag.append(buf);
  return frag;
}
function urlHero(a) {
  const d = a.data;
  const node = el('div', { class: 'hero url-hero' });
  const scheme = String(d.scheme || '').toLowerCase();

  const risky = a.warnings.some((w) => w.level === 'danger');
  const schemeTag = scheme === 'https' ? tag('HTTPS', risky ? 'neutral' : 'ok', 'lock', 'Encrypted connection — says nothing about who runs the site')
    : scheme === 'http' ? tag('HTTP', 'caution', 'lockOpen', 'Not encrypted — anyone on the network can see or change this page')
      : tag(scheme ? `${scheme}:` : 'link', d.openable ? 'neutral' : 'danger', d.openable ? null : 'warning');
  const tags = el('div', { class: 'tags' }, schemeTag);
  if (d.assumedScheme) tags.append(tag('No scheme — https assumed', 'neutral', 'info'));
  if (d.special?.kind === 'shortener') tags.append(tag(`Short link · ${d.special.service}`, d.special.firstParty ? 'neutral' : 'caution'));
  if (d.special?.kind === 'redirector') tags.append(tag(`Redirect · ${d.special.service}`, 'caution'));
  if (d.special && !['shortener', 'redirector'].includes(d.special.kind) && d.special.service) tags.append(tag(d.special.service || d.special.store, 'neutral', 'sparkle'));
  if (d.special?.store) tags.append(tag(d.special.store, 'neutral', 'sparkle'));
  node.append(tags);

  if (d.host) {
    const host = el('div', { class: 'url-host', 'data-testid': 'url-host' });
    if (d.hostKind === 'domain' && d.registrableDomainUnicode) {
      const sub = d.subdomainUnicode || '';
      if (sub) host.append(el('span', { class: 'host-sub' }, hostText(`${sub}.`)));
      host.append(el('span', { class: 'host-reg' }, hostText(d.registrableDomainUnicode)));
    } else {
      host.append(el('span', { class: 'host-reg' }, hostText(d.hostUnicode || d.host)));
    }
    if (d.port) host.append(el('span', { class: 'host-port', text: `:${d.port}` }));
    node.append(host);
    if (d.hostKind === 'domain' && d.registrableDomainUnicode && d.registrableDomainUnicode !== d.host) {
      node.append(el('div', { class: 'host-caption', text: 'Registrable domain — the part that identifies the site owner' }));
    }
    if (d.hostUnicode && d.host && d.hostUnicode !== d.host) {
      node.append(el('dl', { class: 'idn' },
        el('div', {}, el('dt', { text: 'Looks like' }), el('dd', {}, el('span', { class: 'val mono' }, hostText(d.hostUnicode)))),
        el('div', {}, el('dt', { text: 'Actually (punycode)' }), el('dd', {}, valueNode(d.host, { mono: true }), copyButton(d.host, { what: 'Punycode host' })))));
    }
  } else if (d.special?.kind === 'messenger' || d.special?.kind === 'appstore') {
    // e.g. sgnl:// or itms-apps:// — summary already says what it is
  }

  // Full link, monospaced, with the host emphasised by weight only.
  const href = String(d.href || a.raw.text);
  const full = el('div', { class: 'url-full mono' });
  const ui = d.username ? `${d.username}${d.password ? `:${d.password}` : ''}@` : '';
  const at = ui ? href.indexOf(ui) : -1;
  if (at >= 0) {
    full.append(displayText(href.slice(0, at)),
      el('span', { class: 'ui-mark', title: 'Ignored by the browser — often used to disguise the real site' }, displayText(d.password ? `${d.username}:••••@` : ui)),
      displayText(href.slice(at + ui.length)));
  } else full.append(displayText(href));
  node.append(full);
  if (href.length > 240) {
    // Very long links: show the first lines; the parts table below breaks them down anyway.
    full.classList.add('clamped');
    const more = el('button', { type: 'button', class: 'link-btn', 'aria-expanded': 'false', text: `Show full link (${href.length} characters)` });
    more.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = full.classList.toggle('clamped') === false;
      more.setAttribute('aria-expanded', String(open));
      more.textContent = open ? 'Show less' : `Show full link (${href.length} characters)`;
    });
    node.append(more);
  }

  // Path / query / fragment breakdown.
  const rows = [];
  const pathV = d.pathDecoded ?? d.path;
  if (pathV && pathV !== '/' && d.hostKind) rows.push(el('div', { class: 'q-row' }, el('span', { class: 'q-name', text: 'Path' }), el('span', { class: 'q-val mono' }, displayText(pathV)), el('span', { class: 'q-meta' })));
  for (const q of d.query || []) {
    const vals = el('span', { class: 'q-val mono' });
    if (q.sensitive) vals.append(secretValue(q.decoded ?? q.value, { what: q.decodedName || q.name }));
    else vals.append(displayText(q.decoded ?? q.value));
    const meta = el('span', { class: 'q-meta' });
    if (q.tracking) meta.append(tag('Tracking', 'muted', null, 'Tracking parameter — safe to remove'));
    if (q.nestedUrl) {
      const nested = (d.nested || []).find((n) => n.url === q.nestedUrl)?.analysis?.data;
      meta.append(tag(`→ ${nested?.registrableDomainUnicode || nested?.hostUnicode || 'another link'}`, 'caution', null, `Contains a link: ${q.nestedUrl}`));
    }
    rows.push(el('div', { class: ['q-row', q.tracking && 'q-tracking'] }, el('span', { class: 'q-name mono' }, displayText(q.decodedName || q.name)), vals, meta));
  }
  if (d.fragment) rows.push(el('div', { class: 'q-row' }, el('span', { class: 'q-name', text: 'Fragment' }), el('span', { class: 'q-val mono' }, displayText(`#${d.fragmentDecoded ?? d.fragment}`)), el('span', { class: 'q-meta' })));
  if (rows.length) {
    const table = el('div', { class: 'q-table', role: 'table', 'aria-label': 'Link parts' }, rows);
    node.append(table);
    const SHOW = 8;
    if (rows.length > SHOW + 2) {
      // Keep flagged rows (tracking / nested links / secrets) visible; fold the plain rest.
      const keep = (r) => r.querySelector('.tag, .secret-wrap');
      const folded = rows.filter((r, i) => i >= SHOW && !keep(r));
      for (const r of folded) r.hidden = true;
      if (folded.length) {
        const more = el('button', { type: 'button', class: 'link-btn', 'aria-expanded': 'false', text: `Show ${folded.length} more parameters` });
        more.addEventListener('click', (e) => {
          e.stopPropagation();
          const open = more.getAttribute('aria-expanded') !== 'true';
          for (const r of folded) r.hidden = !open;
          more.setAttribute('aria-expanded', String(open));
          more.textContent = open ? 'Show fewer parameters' : `Show ${folded.length} more parameters`;
        });
        node.append(more);
      }
    }
  }

  const nestedOnes = (d.nested || []).filter((n) => n.analysis);
  for (const n of nestedOnes) {
    const nd = n.analysis.data || {};
    const top = n.analysis.warnings?.[0];
    node.append(el('div', { class: 'nested' }, icon('chevronRight', { size: 13 }),
      el('span', {}, 'Leads on to ', el('b', {}, displayText(nd.registrableDomainUnicode || nd.hostUnicode || n.url)),
        top ? el('span', { class: `nested-w lvl-${top.level}`, text: ` — ${top.message}` }) : null)));
  }

  const handled = /^(Link|Host|Host \(ACE\)|Registrable domain|Path|Parameter .*|Fragment|Port|User ?info.*|Username|Password)$/;
  return {
    node,
    hide: byLabel(handled),
    openLabel: scheme === 'http' || scheme === 'https' ? 'Open in Browser…' : null,
    disabledReason: !d.openable ? d.notOpenableReason : null,
  };
}

// ------------------------------------------------------------------------------ Wi-Fi
function wifiHero(a) {
  const d = a.data;
  if (d.format && !String(d.format).startsWith('wifi')) return null; // DPP etc.: generic list
  const sec = find(a, /^Security$/)?.value || '';
  const open = !d.password && /open|none|nopass/i.test(`${sec} ${d.auth || ''}`);
  const pw = find(a, /^Password$/);
  const node = el('div', { class: 'hero wifi-hero' },
    el('div', { class: 'wifi-tile' },
      el('div', { class: 'wifi-glyph' }, icon('wifi', { size: 26 })),
      el('div', { class: 'wifi-text' },
        el('div', { class: 'wifi-name' }, displayText(d.ssid ?? find(a, /^Network$/)?.value ?? '')),
        el('div', { class: 'tags' },
          open ? tag('Open network · no password', 'caution', 'lockOpen') : tag(sec || 'Secured', 'neutral', 'lock'),
          d.hidden ? tag('Hidden network', 'neutral', 'hidden', 'The network does not broadcast its name') : null)),
      el('span', { class: 'row-tools' }, copyButton(d.ssid ?? '', { what: 'Network name' }))),
    pw ? el('div', { class: 'wifi-pw' }, el('span', { class: 'f-label', text: 'Password' }), secretValue(pw.value, { what: 'Password' })) : null);
  return { node, hide: byLabel(/^(Network|Security|Password|Hidden network)$/) };
}

// ------------------------------------------------------------------------------ OTP
function otpHero(a) {
  const d = a.data;
  const details = [d.type === 'hotp' ? `HOTP (counter ${d.counter ?? '?'})` : 'TOTP', d.algorithm, d.digits ? `${d.digits} digits` : null, d.type !== 'hotp' && d.period ? `${d.period} s` : null].filter(Boolean).join(' · ');
  const node = el('div', { class: 'hero otp-hero' },
    el('div', { class: 'otp-who' },
      el('div', { class: 'otp-issuer' }, displayText(d.issuer || 'Unnamed account')),
      d.account ? el('div', { class: 'otp-account' }, displayText(d.account)) : null,
      el('div', { class: 'otp-details', text: details })));
  let w = null;
  if (d.codeComputable && d.otpParams) {
    w = otpWidget(d.otpParams);
    node.append(w.node);
  } else {
    node.append(el('div', { class: 'otp-na' }, icon('info', { size: 14 }), el('span', { text: d.notComputableReason || 'A code can’t be computed for this setup.' })));
  }
  const secret = find(a, /^Secret$/);
  if (secret) node.append(el('div', { class: 'otp-secret' }, el('span', { class: 'f-label', text: 'Secret key' }), secretValue(secret.value, { what: 'Secret', chunk: true, copyValue: d.secretB32 })));
  return {
    node,
    hide: byLabel(/^(Issuer|Account|Type|Algorithm|Digits|Period|Secret|Counter)$/),
    primary: w ? async () => { const c = await w.current(); return c ? { value: c, sensitive: true, what: 'Code' } : null; } : null,
  };
}

function otpMigrationHero(a) {
  const accts = a.data.accounts || [];
  const list = el('div', { class: 'hero mig-list', role: 'list' });
  const widgets = [];
  accts.forEach((acc, i) => {
    const details = [acc.type === 'hotp' ? `HOTP · counter ${acc.counter}` : 'TOTP', acc.algorithm, `${acc.digits} digits`].filter(Boolean).join(' · ');
    const w = acc.codeComputable && acc.otpParams ? otpWidget(acc.otpParams, { compact: true }) : null;
    if (w) widgets.push(w);
    list.append(el('div', { class: 'mig-item', role: 'listitem' },
      el('div', { class: 'mig-head' },
        el('span', { class: 'mig-n', text: String(i + 1) }),
        el('div', { class: 'mig-who' },
          el('div', { class: 'otp-issuer small' }, displayText(acc.issuer || acc.name || 'Unnamed account')),
          el('div', { class: 'otp-account' }, displayText(acc.account || '')),
          el('div', { class: 'otp-details', text: details })),
        w ? w.node : el('span', { class: 'otp-na', text: acc.notComputableReason || 'No code' })),
      el('div', { class: 'mig-foot' },
        acc.secretB32 ? el('span', { class: 'mig-secret' }, el('span', { class: 'f-label', text: 'Secret' }), secretValue(acc.secretB32.replace(/(.{4})/g, '$1 ').trim(), { what: 'Secret', copyValue: acc.secretB32, chunk: true })) : el('span'),
        acc.uri ? el('button', { type: 'button', class: 'btn btn-small', title: 'Clipboard clears in 60 s', on: { click: () => copy(acc.uri, { sensitive: true, what: 'otpauth URI' }) } }, icon('copy', { size: 13 }), el('span', { text: 'Copy otpauth URI' })) : null)));
  });
  return {
    node: list,
    hide: () => true,
    filterActions: (x) => !/^Copy otpauth URI \(/.test(x.label),
    primary: widgets[0] ? async () => { const c = await widgets[0].current(); return c ? { value: c, sensitive: true, what: 'Code' } : null; } : null,
  };
}

// ------------------------------------------------------------------------------ Contact
const CONTACT_KINDS = [
  [/^(Phone|Mobile|Tel|Fax)/i, 'phone'],
  [/^E-?mail/i, 'envelope'],
  [/^Address/i, 'pin'],
  [/^(Website|URL|Web)/i, 'globe'],
];
function contactHero(a) {
  const name = find(a, /^Name$/)?.value || a.data.fn || '';
  const org = find(a, /^Organi[sz]ation$/)?.value;
  const title = find(a, /^(Job )?title$/i)?.value;
  const initials = name.replace(/^(Dr|Mr|Mrs|Ms|Prof)\.?\s+/i, '').split(/\s+/).filter(Boolean).map((p) => Array.from(p)[0]).slice(0, 2).join('').toUpperCase();
  const rows = [];
  const used = new Set();
  for (const f of a.fields) {
    const k = CONTACT_KINDS.find(([re]) => re.test(f.label));
    if (!k) continue;
    used.add(f);
    const sub = /\((.+)\)/.exec(f.label)?.[1];
    rows.push(el('div', { class: 'c-row' },
      el('span', { class: 'c-ic' }, icon(k[1], { size: 14 })),
      el('div', { class: 'c-text' },
        el('div', { class: 'c-label', text: sub ? `${f.label.replace(/\s*\(.+\)/, '')} · ${sub}` : f.label }),
        el('div', { class: 'c-val' }, valueNode(f.value, { mono: false }))),
      el('span', { class: 'row-tools' }, copyButton(f.value, { what: f.label.replace(/\s*\(.+\)/, '') }))));
  }
  const node = el('div', { class: 'hero contact-hero' },
    el('div', { class: 'c-head' },
      el('div', { class: 'avatar', 'aria-hidden': 'true' }, initials ? el('span', { text: initials }) : icon('person', { size: 26 })),
      el('div', {},
        el('div', { class: 'c-name' }, displayText(name || 'Unnamed contact')),
        org || title ? el('div', { class: 'c-org' }, displayText([title, org].filter(Boolean).join(' · '))) : null)),
    rows.length ? el('div', { class: 'c-rows' }, rows) : null);
  return { node, hide: (f) => used.has(f) || /^(Name|Organi[sz]ation|(Job )?title)$/i.test(f.label) };
}

// ------------------------------------------------------------------------------ Event
function eventHero(a) {
  const d = a.data;
  let date = null;
  if (d.start) {
    const s = String(d.start);
    date = new Date(/T/.test(s) || /Z$/.test(s) ? s : `${s}T00:00:00`);
    if (Number.isNaN(date.getTime())) date = null;
  }
  const tile = el('div', { class: 'date-tile', 'aria-hidden': 'true' },
    el('div', { class: 'dt-month', text: date ? date.toLocaleString('en', { month: 'short' }).toUpperCase() : '—' }),
    el('div', { class: 'dt-day', text: date ? String(date.getDate()) : '?' }),
    el('div', { class: 'dt-wd', text: date ? date.toLocaleString('en', { weekday: 'short' }) : '' }));
  const when = d.whenLocal || d.when || find(a, /^When$/)?.value || '';
  const orig = d.when && d.whenLocal && d.when !== d.whenLocal ? d.when : null;
  const node = el('div', { class: 'hero event-hero' }, tile,
    el('div', { class: 'ev-text' },
      el('div', { class: 'ev-title' }, displayText(d.summary || find(a, /^Title$/)?.value || 'Untitled event')),
      el('div', { class: 'ev-when' }, icon('clock', { size: 13 }), el('span', {}, displayText(when)), d.whenLocal && d.startKind !== 'floating' ? el('span', { class: 'ev-tz', text: 'your time' }) : null),
      orig ? el('div', { class: 'ev-orig', text: `Original: ${orig}` }) : null,
      d.location ? el('div', { class: 'ev-loc' }, icon('pin', { size: 13 }), el('span', {}, displayText(d.location))) : null));
  return { node, hide: byLabel(/^(Title|When|Your time|Location)$/) };
}

// ------------------------------------------------------------------------------ Payments
const AMOUNT = /^Amount$/;
const PAYEE = /^(Beneficiary|Pay to|Merchant|Payee|Recipient|Creditor)$/;
const ACCOUNT = /^(IBAN|QR-IBAN|Address|Pix key.*|UPI ID|VPA|Account.*)$/;
function paymentHero(a) {
  const amount = find(a, AMOUNT);
  const payee = find(a, PAYEE);
  const acct = a.fields.find((f) => ACCOUNT.test(f.label) && f.mono);
  const checks = a.fields.filter((f) => /^[✓✗✔✘]/.test(String(f.value)));
  const crypto = a.type === 'crypto';
  const network = crypto ? find(a, /^Network$/)?.value : null;
  if (!amount && !acct) return null;
  const unset = amount && /^Not set/.test(amount.value);
  const node = el('div', { class: 'hero pay-hero' });
  node.append(el('div', { class: 'pay-label', text: crypto ? `${network || 'Crypto'} payment` : 'You would pay' }));
  if (amount) {
    const m = /^(.*?)\s*\(([^()]+)\)$/.exec(amount.value);
    node.append(el('div', { class: ['pay-amount', unset && 'unset'], 'data-testid': 'amount' }, displayText(m && !unset ? m[1] : amount.value),
      m && !unset ? el('span', { class: 'pay-amount-sub', text: m[2] }) : null));
  }
  if (payee) node.append(el('div', { class: 'pay-to' }, el('span', { class: 'pay-to-l', text: 'to ' }), el('b', {}, displayText(payee.value)), el('span', { class: 'row-tools' }, copyButton(payee.value, { what: payee.label }))));
  if (acct) {
    const flat = String(acct.value).replace(/\s+/g, '');
    const grouped = /\s/.test(acct.value) ? acct.value : flat.replace(/(.{4})/g, '$1 ').trim();
    node.append(el('div', { class: 'pay-acct' },
      el('div', { class: 'f-label', text: acct.label }),
      el('div', { class: 'pay-acct-row' }, valueNode(grouped, { mono: true, chunk: true }), el('span', { class: 'row-tools' }, copyButton(flat, { what: acct.label })))));
  }
  const badges = checks.map((c) => checkBadge(c.value));
  if (crypto && a.data.addressValid !== undefined && a.data.addressValid !== null) badges.push(checkBadge(a.data.addressValid ? '✓ Address checksum valid' : '✗ Address checksum invalid'));
  if (badges.length) node.append(el('div', { class: 'tags' }, badges));
  const hidden = new Set([amount, payee, acct, ...checks].filter(Boolean));
  return { node, hide: (f) => hidden.has(f) || (crypto && /^(Network|Starts \/ ends with)$/.test(f.label)) };
}

// ------------------------------------------------------------------------------ Text / JSON / binary
function textHero(a) {
  const d = a.data;
  const t = a.raw.text;
  const node = el('div', { class: 'hero text-hero' });
  // A secret (recovery phrase, private key, token) is shown once, masked, in its own field
  // row — never in clear text up here.
  const norm = (v) => String(v ?? '').replace(/\s+/g, ' ').trim();
  const secretIsText = a.fields.some((f) => f.sensitive && norm(f.value) === norm(t));
  if (!secretIsText) {
    node.append(el('div', { class: ['text-body', t.length > 600 && 'long'], tabindex: '0', 'aria-label': 'Decoded text' }, displayText(t)));
  }
  const links = (d.detected || []).filter((x) => x.kind === 'url' || x.kind === 'email' || x.kind === 'phone');
  if (links.length) node.append(sectionTitle(`${links.length === 1 ? 'Link' : 'Links'} in this text`), linkList(links));
  return { node: node.childElementCount ? node : null, hide: byLabel(/^Text$/) };
}

function linkList(links) {
  return el('div', { class: 'links' }, links.map((l) => {
    const href = l.kind === 'url' && !/^[a-z][a-z0-9+.-]*:/i.test(l.value) ? `https://${l.value}` : l.kind === 'email' && !/^mailto:/i.test(l.value) ? `mailto:${l.value}` : l.kind === 'phone' && !/^tel:/i.test(l.value) ? `tel:${l.value.replace(/[\s().-]/g, '')}` : l.value;
    const lvl = l.level;
    return el('div', { class: 'link-row' },
      el('span', { class: 'c-ic' }, icon(l.kind === 'url' ? 'globe' : l.kind === 'email' ? 'envelope' : 'phone', { size: 14 })),
      el('div', { class: 'c-text' },
        el('div', { class: 'c-val mono' }, displayText(l.value)),
        el('div', { class: `c-label ${lvl ? `lvl-${lvl}` : ''}` }, displayText(l.warnings?.find((w) => w.level !== 'info')?.message || l.summary || ''))),
      el('span', { class: 'row-tools always' },
        copyButton(l.value, { what: 'Link' }),
        el('button', { type: 'button', class: 'icon-btn', 'aria-label': `Open ${l.value}…`, title: 'Open… (asks first)', on: { click: () => openLink(href) } }, icon('open', { size: 13 }))));
  }));
}

const JSON_TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],])/g;
function jsonHero(a) {
  const pretty = a.data.pretty || a.raw.text;
  const pre = el('pre', { class: 'json mono', tabindex: '0', 'aria-label': 'JSON' });
  let last = 0;
  for (const m of pretty.matchAll(JSON_TOKEN)) {
    if (m.index > last) pre.append(document.createTextNode(pretty.slice(last, m.index)));
    last = m.index + m[0].length;
    if (m[1]) {
      pre.append(el('span', { class: m[2] ? 'j-key' : 'j-str' }, displayText(m[1])));
      if (m[2]) pre.append(el('span', { class: 'j-punc', text: m[2] }));
    } else if (m[3]) pre.append(el('span', { class: 'j-lit', text: m[3] }));
    else if (m[4]) pre.append(el('span', { class: 'j-num', text: m[4] }));
    else pre.append(el('span', { class: 'j-punc', text: m[5] }));
  }
  if (last < pretty.length) pre.append(document.createTextNode(pretty.slice(last)));
  const node = el('div', { class: 'hero json-hero' }, pre);
  const urls = a.data.urls || [];
  if (urls.length) {
    node.append(sectionTitle('Links in this data'), linkList(urls.map((u) => (typeof u === 'string' ? { kind: 'url', value: u } : { kind: 'url', value: u.url || u.value, summary: u.path || u.summary, level: u.level, warnings: u.warnings })).filter((u) => u.value)));
  }
  return { node, hide: byLabel(/^JSON$/) };
}

function binaryHero(a) {
  const hex = a.data.hexDump || find(a, /^Hex$/)?.value || '';
  return {
    node: el('div', { class: 'hero bin-hero' }, a.data.magic ? el('div', { class: 'tags' }, tag(`Looks like ${a.data.magic.name || a.data.magic}`, 'neutral', 'doc')) : null,
      el('pre', { class: 'hexdump mono', tabindex: '0', 'aria-label': 'Hex dump' }, hex)),
    hide: byLabel(a.data.magic ? /^(Hex|Looks like)$/ : /^Hex$/),
  };
}

// ------------------------------------------------------------------------------ simple lead value
function leadHero(a) {
  const f = a.fields[0];
  if (!f || f.sensitive) return null;
  const isNum = a.type === 'phone' || a.type === 'sms';
  const node = el('div', { class: 'hero lead-hero' },
    el('div', { class: 'f-label', text: f.label }),
    el('div', { class: 'lead-row' }, el('div', { class: ['lead-val', isNum && 'num'] }, displayText(f.value)), el('span', { class: 'row-tools' }, copyButton(f.value, { what: f.label }))));
  const msg = a.type === 'sms' || a.type === 'email' ? find(a, /^(Message|Body)$/) : null;
  if (msg) node.append(el('div', { class: 'bubble' }, displayText(msg.value)));
  return { node, hide: (x) => x === f || x === msg };
}

const HEROES = {
  url: urlHero, wifi: wifiHero, otp: otpHero, 'otp-migration': otpMigrationHero, contact: contactHero,
  event: eventHero, 'epc-payment': paymentHero, 'swiss-qr-bill': paymentHero, payment: paymentHero, crypto: paymentHero,
  text: textHero, json: jsonHero, binary: binaryHero, phone: leadHero, email: leadHero, sms: leadHero, geo: leadHero,
};

export function buildHero(a) {
  const fn = HEROES[a.type];
  if (!fn) return null;
  try { return fn(a); } catch (e) {
    console.error('hero failed', a.type, e);
    return null;
  }
}

export { fieldList };

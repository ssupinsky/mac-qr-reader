// Label/value rows, masked secrets with reveal, inline copy buttons, chunked values.
import { el } from './dom.js';
import { icon } from './icons.js';
import { copy } from './actions.js';
import { displayText } from './text.js';

/** Small icon-only copy button. */
export function copyButton(value, { sensitive = false, what = '', label } = {}) {
  const l = label || `Copy ${what ? what.toLowerCase() : 'value'}`;
  return el('button', {
    type: 'button', class: 'icon-btn copy-btn', 'aria-label': l,
    title: sensitive ? `${l} — clipboard clears in 60 s` : l,
    on: { click: (e) => { e.stopPropagation(); copy(value, { sensitive, what }); } },
  }, icon('copy', { size: 13 }));
}

/** Value node: text with chips for invisible chars; optional mono/chunked. */
export function valueNode(value, { mono = false, chunk = false, cls = '' } = {}) {
  const v = String(value ?? '');
  const node = el('span', { class: ['val', mono && 'mono', cls] });
  if (chunk && /\S \S/.test(v) && !/[^\x20-\x7e]/.test(v)) {
    node.classList.add('chunked');
    v.split(' ').filter(Boolean).forEach((g, i) => node.append(el('span', { class: `chunk${i % 2 ? ' alt' : ''}`, text: g })));
  } else {
    node.append(displayText(v));
  }
  return node;
}

/** A masked secret with a reveal toggle and a sensitive copy button. */
export function secretValue(value, { mono = true, what = 'Secret', copyValue = null, chunk = false } = {}) {
  const v = String(value ?? '');
  const dots = el('span', { class: 'secret-dots', 'aria-label': `${what} hidden`, text: '•'.repeat(Math.min(Math.max(v.length, 8), 16)) });
  const shown = valueNode(v, { mono, chunk });
  shown.hidden = true;
  const eyeBtn = el('button', { type: 'button', class: 'icon-btn', 'aria-pressed': 'false', 'aria-label': `Show ${what.toLowerCase()}`, title: `Show ${what.toLowerCase()}` }, icon('eye', { size: 14 }));
  const wrap = el('span', { class: 'secret', 'data-testid': 'secret' }, dots, shown);
  eyeBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const reveal = shown.hidden;
    shown.hidden = !reveal;
    dots.hidden = reveal;
    wrap.classList.toggle('revealed', reveal);
    eyeBtn.replaceChildren(icon(reveal ? 'eyeSlash' : 'eye', { size: 14 }));
    eyeBtn.setAttribute('aria-pressed', String(reveal));
    const l = `${reveal ? 'Hide' : 'Show'} ${what.toLowerCase()}`;
    eyeBtn.setAttribute('aria-label', l);
    eyeBtn.title = l;
  });
  return el('span', { class: 'secret-wrap' }, wrap,
    el('span', { class: 'row-tools' }, eyeBtn, copyButton(copyValue ?? v.replace(/\s+/g, mono ? '' : ' '), { sensitive: true, what })));
}

/** One label/value row for the generic field list. */
export function fieldRow(f, opts = {}) {
  const label = el('dt', { class: 'f-label', text: f.label });
  let value;
  if (f.sensitive) {
    value = secretValue(f.value, { mono: !!f.mono, what: f.label, copyValue: opts.copyValue });
  } else {
    const isCheck = /^[✓✗✔✘]/.test(String(f.value));
    const v = isCheck ? checkBadge(f.value) : valueNode(f.value, { mono: !!f.mono, chunk: opts.chunk });
    value = el('span', { class: 'f-value-inner' }, v,
      f.copy ? el('span', { class: 'row-tools' }, copyButton(opts.copyValue ?? f.value, { what: f.label })) : null);
  }
  const multiline = String(f.value).includes('\n');
  return el('div', { class: ['f-row', multiline && 'f-multiline'] }, label, el('dd', { class: 'f-value' }, value));
}

/** "✓ Checksum valid" → green check badge; "✗ …" → red. */
export function checkBadge(text) {
  const t = String(text);
  const ok = /^[✓✔]/.test(t);
  return el('span', { class: `check-badge ${ok ? 'ok' : 'bad'}` }, icon(ok ? 'checkCircle' : 'xmarkCircle', { size: 13 }), el('span', { text: t.replace(/^[✓✗✔✘]\s*/, '') }));
}

export function fieldList(fields, { chunkLabels = null } = {}) {
  if (!fields.length) return null;
  return el('dl', { class: 'fields' }, fields.map((f) => fieldRow(f, { chunk: !!(chunkLabels && chunkLabels.test(f.label) && f.mono) })));
}

/** Section heading inside a card body. */
export const sectionTitle = (t) => el('div', { class: 'section-title', text: t });

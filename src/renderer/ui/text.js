// Safe rendering of untrusted text: invisible / bidi / control characters become visible
// chips (PAYLOADS.md §1.2), everything else is plain text nodes.
import { escapeForDisplay, codePointName } from '../parsers/text-safety.js';
import { el } from './dom.js';

const TOKEN = /\\\\|\\n\n?|\\r|\\t|\\u\{([0-9A-F]+)\}/g;
const WS_NAMES = { n: 'LF', r: 'CR', t: 'TAB' };

function chip(label, title, cls = '') {
  return el('span', { class: `cp-chip ${cls}`.trim(), title, text: label });
}

/**
 * Renders an escaped string (`raw.escaped` / escapeForDisplay output) with chips.
 * @param {string} escaped
 * @param {{showWhitespace?: boolean}} opts showWhitespace → CR/LF/TAB as chips too (Escaped view)
 */
export function renderEscaped(escaped, { showWhitespace = false } = {}) {
  const frag = document.createDocumentFragment();
  let last = 0;
  let buf = '';
  const flush = () => { if (buf) { frag.append(document.createTextNode(buf)); buf = ''; } };
  for (const m of escaped.matchAll(TOKEN)) {
    buf += escaped.slice(last, m.index);
    last = m.index + m[0].length;
    const t = m[0];
    if (t === '\\\\') { buf += '\\'; continue; }
    if (m[1]) {
      const cp = parseInt(m[1], 16);
      const name = codePointName(cp);
      const hex = `U+${m[1]}`;
      flush();
      frag.append(chip(name && name !== hex ? name : hex, `${hex}${name ? ` ${name}` : ''} — invisible or control character`, 'cp-flag'));
      continue;
    }
    const k = t[1];
    if (showWhitespace) {
      flush();
      frag.append(chip(WS_NAMES[k] === 'LF' ? '↵' : WS_NAMES[k] === 'TAB' ? '⇥' : 'CR', WS_NAMES[k], 'cp-ws'));
      if (k === 'n') buf += '\n';
    } else if (k === 'n') buf += '\n';
    else if (k === 't') buf += '\t';
    else if (k === 'r') { /* CR before LF: drop for display */ }
  }
  buf += escaped.slice(last);
  flush();
  return frag;
}

/** True when the string contains anything escapeForDisplay flags (not just \, CR/LF/TAB). */
export function hasFlagged(value) {
  return /\\u\{/.test(escapeForDisplay(String(value ?? ''), { multiline: true }));
}

/**
 * A node showing `value` readably and safely. Flagged code points → chips; otherwise a
 * plain text node (selectable). Wrap in an element with `unicode-bidi: plaintext`.
 */
export function displayText(value) {
  const s = String(value ?? '');
  const esc = escapeForDisplay(s, { multiline: true });
  if (!/\\u\{/.test(esc)) return document.createTextNode(s);
  return renderEscaped(esc);
}

/** Classic 16-bytes-per-line hex dump from a hex string. */
export function hexDump(hex, maxBytes = 4096) {
  const bytes = [];
  for (let i = 0; i + 1 < hex.length && bytes.length < maxBytes; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const row = bytes.slice(off, off + 16);
    const h = row.map((b) => b.toString(16).padStart(2, '0'));
    const left = h.slice(0, 8).join(' ');
    const right = h.slice(8).join(' ');
    const ascii = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·')).join('');
    lines.push(`${off.toString(16).padStart(8, '0')}  ${left.padEnd(23)}  ${right.padEnd(23)}  ${ascii}`);
  }
  const total = hex.length / 2;
  if (total > maxBytes) lines.push(`… ${total - maxBytes} more bytes`);
  return lines.join('\n');
}

/** Untrusted text for attributes (title / aria-label): invisible and bidi characters escaped. */
export function attrText(value) {
  return escapeForDisplay(String(value ?? ''), { multiline: false });
}

// "Raw" disclosure: exact text / escaped view with invisible characters as chips / hex dump,
// plus code metadata (symbology, QR version, EC level, mask, sizes, encoding).
import { el, nextId, formatBytes } from './dom.js';
import { icon } from './icons.js';
import { renderEscaped, displayText, hexDump } from './text.js';
import { copyButton } from './fields.js';

const EC_NAMES = { L: 'L (~7%)', M: 'M (~15%)', Q: 'Q (~25%)', H: 'H (~30%)' };

/**
 * @param {object} a Analysis
 * @param {object} code HelperCode-like ({symbology, qr, page, pass, confidence, bytesKind})
 * @param {{sensitive: boolean, pages?: number}} opts
 */
export function rawDisclosure(a, code, { sensitive = false, pages = 1 } = {}) {
  const raw = a.raw || {};
  const id = nextId('raw');
  const toggle = el('button', { type: 'button', class: 'disclosure', 'aria-expanded': 'false', 'aria-controls': id, 'data-testid': 'raw-toggle' },
    icon('chevronRight', { size: 12, cls: 'disc-chev' }), el('span', { text: 'Raw data & details' }),
    raw.hasInvisible && a.type !== 'binary' ? el('span', { class: 'tag tag-caution small', text: 'hidden characters' }) : null);
  const panel = el('div', { class: 'raw-panel', id, hidden: true, 'data-testid': 'raw' });
  let built = false;
  toggle.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', String(open));
    panel.hidden = !open;
    if (open && !built) { built = true; build(panel, a, code, { sensitive, pages }); }
  });
  return el('div', { class: 'raw' }, toggle, panel);
}

function build(panel, a, code, { sensitive, pages }) {
  const raw = a.raw || {};
  // Metadata grid
  const meta = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') meta.push(el('div', { class: 'm-item' }, el('dt', { text: k }), el('dd', { text: String(v) }))); };
  add('Symbology', code?.symbology === 'text' ? 'Pasted text' : code?.symbology);
  if (code?.qr) {
    add('QR version', code.qr.version);
    add('Error correction', EC_NAMES[code.qr.ecLevel] || code.qr.ecLevel);
    add('Mask', code.qr.maskPattern);
  }
  add('Characters', raw.length);
  if (raw.byteLength !== undefined) add('Bytes', formatBytes(raw.byteLength));
  add('Encoding', raw.encoding ? raw.encoding.toUpperCase() : null);
  if (raw.bytesKind) add('Byte source', raw.bytesKind === 'payload' ? 'Decoded payload' : 'Raw codewords');
  add('Format', a.data?.format);
  if (pages > 1 && code?.page !== undefined) add('Page', `${code.page + 1} of ${pages}`);
  if (code?.pass && code.pass !== 'original') add('Found by', ({ inverted: 'Inverted image pass', enhanced: 'Contrast-enhanced pass', upscaled: 'Upscaled pass', tile: 'Tiled pass' })[code.pass] || code.pass);
  panel.append(el('dl', { class: 'meta-grid' }, meta));

  if (raw.hiddenText) {
    panel.append(el('div', { class: 'warn lvl-danger compact' }, icon('danger', { size: 14 }),
      el('span', {}, 'Hidden text in invisible tag characters: ', el('code', {}, displayText(raw.hiddenText)))));
  }

  // View switcher
  const views = [['text', 'Text'], ['escaped', 'Escaped']];
  if (raw.bytesHex) views.push(['hex', 'Hex']);
  if (raw.systemText) views.push(['system', 'System decoding']);
  const content = el('div', { class: 'raw-content' });
  const seg = el('div', { class: 'segmented', role: 'tablist', 'aria-label': 'Raw view' });
  let current = raw.hasInvisible ? 'escaped' : 'text';
  let revealed = !sensitive;

  const render = () => {
    for (const b of seg.children) {
      const on = b.dataset.view === current;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
    }
    content.replaceChildren();
    if (!revealed) {
      content.append(el('div', { class: 'raw-masked' }, icon('lock', { size: 14 }),
        el('span', { text: 'Contains a secret.' }),
        el('button', { type: 'button', class: 'btn btn-small', on: { click: () => { revealed = true; render(); } } }, el('span', { text: 'Show raw data' }))));
      return;
    }
    let pre;
    if (current === 'text') pre = el('pre', { class: 'raw-pre mono' }, displayText(raw.text ?? ''));
    else if (current === 'escaped') pre = el('pre', { class: 'raw-pre mono' }, renderEscaped(raw.escaped ?? '', { showWhitespace: true }));
    else if (current === 'hex') pre = el('pre', { class: 'raw-pre mono hex' }, hexDump(raw.bytesHex));
    else pre = el('pre', { class: 'raw-pre mono' }, displayText(raw.systemText));
    pre.tabIndex = 0;
    const copyVal = current === 'hex' ? raw.bytesHex : current === 'system' ? raw.systemText : current === 'escaped' ? raw.escaped : raw.text;
    content.append(pre, el('div', { class: 'raw-tools' }, copyButton(copyVal ?? '', { sensitive, what: current === 'hex' ? 'Hex' : 'Raw text', label: current === 'hex' ? 'Copy hex' : 'Copy raw text' })));
    if (current === 'system') content.prepend(el('p', { class: 'hint', text: 'macOS decoded this code’s text differently. Shown for comparison; the card uses the bytes in the code.' }));
  };
  for (const [v, label] of views) {
    seg.append(el('button', { type: 'button', role: 'tab', class: 'seg', dataset: { view: v }, text: label, on: { click: () => { current = v; render(); } } }));
  }
  seg.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    e.stopPropagation();
    const i = views.findIndex(([v]) => v === current);
    current = views[(i + (e.key === 'ArrowRight' ? 1 : views.length - 1)) % views.length][0];
    render();
    seg.querySelector('[aria-selected="true"]')?.focus();
  });
  panel.append(seg, content);
  render();
}

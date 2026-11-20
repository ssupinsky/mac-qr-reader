// Toolbar popover reflecting View ▸ "Scan Clipboard When Activated" (the only setting).
import { el } from './dom.js';
import { icon } from './icons.js';

const qr = window.qr;

export function settingsControl() {
  const sw = el('input', { type: 'checkbox', role: 'switch', class: 'switch', id: 'auto-scan', 'data-testid': 'auto-scan' });
  const pop = el('div', { class: 'popover', role: 'dialog', 'aria-label': 'Settings', hidden: true },
    el('label', { class: 'pop-row', for: 'auto-scan' },
      el('span', { class: 'pop-text' },
        el('span', { class: 'pop-title', text: 'Scan clipboard when activated' }),
        el('span', { class: 'pop-sub', text: 'When you switch to QR Reader with a new image on the clipboard, it’s scanned automatically. Text is never read without ⌘V.' })),
      sw),
    el('div', { class: 'pop-foot' }, icon('shield', { size: 12 }), el('span', { text: 'No network · no history · nothing saved unless you choose Save' })));
  const btn = el('button', { type: 'button', class: 'tb-btn icon-only', 'aria-label': 'Settings', title: 'Settings', 'aria-haspopup': 'dialog', 'aria-expanded': 'false' }, icon('sliders', { size: 16 }));
  const dot = el('span', { class: 'tb-dot', title: 'Auto-scan is on' });
  btn.append(dot);
  const wrap = el('div', { class: 'pop-wrap' }, btn, pop);

  const close = () => { pop.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
  const open = () => { pop.hidden = false; btn.setAttribute('aria-expanded', 'true'); sw.focus(); };
  btn.addEventListener('click', (e) => { e.stopPropagation(); if (pop.hidden) open(); else close(); });
  document.addEventListener('mousedown', (e) => { if (!pop.hidden && !wrap.contains(e.target)) close(); });
  sw.addEventListener('change', async () => {
    try { await qr.setSetting('autoScanClipboard', sw.checked); } catch { /* re-sync below */ }
    sync();
  });

  async function sync() {
    try {
      const s = await qr.getSettings();
      sw.checked = !!s.autoScanClipboard;
      dot.hidden = !s.autoScanClipboard;
    } catch { /* keep */ }
  }
  sync();
  return { node: wrap, sync, close, isOpen: () => !pop.hidden };
}

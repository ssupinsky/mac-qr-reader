// Small transient feedback capsule ("Copied", "Saved"). One at a time; aria-live polite.
import { el } from './dom.js';
import { icon } from './icons.js';

let host = null;
let timer = 0;

export function initToast(root) { host = root; }

/** @param {string} message @param {{icon?: string, tone?: 'ok'|'warn'|'muted', ms?: number}} [opts] */
export function toast(message, { icon: ic = 'check', tone = 'ok', ms = 1800 } = {}) {
  if (!host) return;
  clearTimeout(timer);
  const t = el('div', { class: `toast toast-${tone}`, role: 'status', 'data-testid': 'toast' },
    icon(ic, { size: 14 }), el('span', { text: message }));
  host.replaceChildren(t);
  requestAnimationFrame(() => t.classList.add('show'));
  timer = setTimeout(() => {
    t.classList.remove('show');
    timer = setTimeout(() => { if (t.isConnected) t.remove(); }, 250);
  }, ms);
}

export function clearToast() { clearTimeout(timer); host?.replaceChildren(); }

// Live one-time-password display with a countdown ring. Codes are computed locally with
// WebCrypto (parsers/totp.js); a single 1 s ticker updates only widgets that are on screen
// while the document is visible.
import { generateOtp, otpTimeStep } from '../parsers/totp.js';
import { el, svg } from './dom.js';
import { icon } from './icons.js';
import { copy } from './actions.js';

const widgets = new Set();
let timer = 0;
const io = new IntersectionObserver((entries) => {
  for (const e of entries) {
    const w = e.target.__otp;
    if (w) { w.visible = e.isIntersecting; if (w.visible) w.update(); }
  }
  schedule();
});

function anyActive() {
  for (const w of widgets) if (w.visible) return true;
  return false;
}

function schedule() {
  clearTimeout(timer);
  timer = 0;
  if (document.visibilityState !== 'visible' || !anyActive()) return;
  const delay = 1000 - (Date.now() % 1000) + 15;
  timer = setTimeout(tick, delay);
}

function tick() {
  for (const w of [...widgets]) {
    if (!w.node.isConnected) { dispose(w); continue; }
    if (w.visible) w.update();
  }
  schedule();
}

function dispose(w) { widgets.delete(w); io.unobserve(w.node); }

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') for (const w of widgets) if (w.visible) w.update();
  schedule();
});

/** Drops every widget (Clear / new results). */
export function disposeAllOtp() {
  for (const w of [...widgets]) dispose(w);
  clearTimeout(timer);
}

const RING_R = 9;
const RING_C = 2 * Math.PI * RING_R;

function groupDigits(code) {
  if (code.length === 6) return [code.slice(0, 3), code.slice(3)];
  if (code.length === 8) return [code.slice(0, 4), code.slice(4)];
  return [code];
}

/**
 * @param {{secret, algorithm, digits, period?, counter?}} params otpParams from the parser
 * @param {{compact?: boolean, label?: string}} opts
 * @returns {{node: HTMLElement, current: () => Promise<string|null>}}
 */
export function otpWidget(params, { compact = false, label = 'Current code' } = {}) {
  const isHotp = params.counter !== undefined && params.counter !== null;
  const period = Number(params.period) > 0 ? Number(params.period) : 30;
  const codeEl = el('span', { class: 'otp-code', 'aria-live': 'off', text: '—' });
  const secsEl = el('span', { class: 'otp-secs' });
  const prog = svg('circle', { class: 'otp-ring-fg', cx: 12, cy: 12, r: RING_R, 'stroke-dasharray': RING_C.toFixed(2), 'stroke-dashoffset': 0, transform: 'rotate(-90 12 12)' });
  const ring = isHotp ? null : el('span', { class: 'otp-ring', title: 'Seconds until the code changes' },
    svg('svg', { viewBox: '0 0 24 24', width: compact ? 22 : 30, height: compact ? 22 : 30, 'aria-hidden': 'true' },
      svg('circle', { class: 'otp-ring-bg', cx: 12, cy: 12, r: RING_R }), prog),
    secsEl);
  let lastKey = null;
  let code = null;
  let failed = false;

  const copyBtn = el('button', {
    type: 'button', class: 'btn btn-small', 'aria-label': 'Copy code',
    title: 'Copy code — clipboard clears in 60 s',
    on: { click: async () => { const c = await w.current(); if (c) copy(c, { sensitive: true, what: 'Code' }); } },
  }, icon('copy', { size: 13 }), compact ? null : el('span', { text: 'Copy code' }));

  const node = el('div', { class: ['otp', compact && 'otp-compact'], 'data-testid': 'otp' },
    el('div', { class: 'otp-main' },
      el('div', { class: 'otp-label', text: isHotp ? `Code for counter ${params.counter}` : label }),
      el('div', { class: 'otp-value' }, codeEl, ring)),
    copyBtn);

  const w = {
    node, visible: false,
    async current() {
      try { return await generateOtp(params, Date.now()); } catch { return null; }
    },
    async update() {
      if (failed) return;
      const step = isHotp ? null : otpTimeStep(period, Date.now());
      const key = isHotp ? 'hotp' : step.counter;
      if (step) {
        const frac = step.secondsRemaining / period;
        secsEl.textContent = String(step.secondsRemaining);
        const reset = key !== lastKey;
        prog.classList.toggle('no-anim', reset);
        prog.setAttribute('stroke-dashoffset', (RING_C * (1 - frac)).toFixed(2));
        node.classList.toggle('otp-expiring', step.secondsRemaining <= 5);
      }
      if (key === lastKey) return;
      lastKey = key;
      try {
        code = await generateOtp(params, Date.now());
        const groups = groupDigits(code);
        codeEl.replaceChildren(...groups.map((g) => el('span', { class: 'otp-group', text: g })));
        codeEl.setAttribute('aria-label', code.split('').join(' '));
      } catch (e) {
        failed = true;
        codeEl.textContent = 'Can’t compute';
        codeEl.title = String(e?.message || e);
        node.classList.add('otp-failed');
        copyBtn.disabled = true;
      }
    },
  };
  node.__otp = w;
  widgets.add(w);
  io.observe(node);
  w.update();
  return w;
}

// SF-Symbols-like stroke icons drawn as inline SVG via createElementNS (no external assets).
// 24×24 grid, 1.6 px strokes, round caps/joins; colour = currentColor.
import { svg } from './dom.js';

const P = (d) => ['path', { d }];
const C = (cx, cy, r, fill) => ['circle', { cx, cy, r, ...(fill ? { fill: 'currentColor', stroke: 'none' } : {}) }];
const R = (x, y, w, h, rx) => ['rect', { x, y, width: w, height: h, rx }];
const E = (cx, cy, rx, ry) => ['ellipse', { cx, cy, rx, ry }];

const ICONS = {
  link: [P('M10.2 13.8a4.3 4.3 0 0 0 6.1 0l3.2-3.2a4.3 4.3 0 0 0-6.1-6.1L12.2 5.7'), P('M13.8 10.2a4.3 4.3 0 0 0-6.1 0l-3.2 3.2a4.3 4.3 0 0 0 6.1 6.1l1.2-1.2')],
  globe: [C(12, 12, 9), P('M3 12h18'), P('M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9'), P('M12 3c-2.4 2.5-3.6 5.5-3.6 9s1.2 6.5 3.6 9')],
  wifi: [P('M2.6 9.2a13.6 13.6 0 0 1 18.8 0'), P('M5.7 12.5a9.2 9.2 0 0 1 12.6 0'), P('M8.8 15.8a4.7 4.7 0 0 1 6.4 0'), C(12, 19, 1.25, true)],
  key: [C(8, 15.5, 4.2), P('M11 12.5l8.6-8.6'), P('M16.3 7.2l2.6 2.6'), P('M13.9 9.6l1.9 1.9')],
  person: [C(12, 8, 3.9), P('M4.6 20.2a7.4 7.4 0 0 1 14.8 0')],
  envelope: [R(3, 5.5, 18, 13, 2.4), P('M3.6 7.2l8.4 6 8.4-6')],
  phone: [P('M7 3.6h2.1l1.7 4.3-2.2 1.5a11.5 11.5 0 0 0 6 6l1.5-2.2 4.3 1.7v2.1a2.2 2.2 0 0 1-2.4 2.2A16.6 16.6 0 0 1 4.8 6a2.2 2.2 0 0 1 2.2-2.4z')],
  message: [P('M5 5h14a2.5 2.5 0 0 1 2.5 2.5v7.5a2.5 2.5 0 0 1-2.5 2.5h-7.5L7 21v-3.5H5A2.5 2.5 0 0 1 2.5 15V7.5A2.5 2.5 0 0 1 5 5z')],
  pin: [P('M12 21.2s-6.6-5.8-6.6-11.2a6.6 6.6 0 0 1 13.2 0c0 5.4-6.6 11.2-6.6 11.2z'), C(12, 10, 2.4)],
  calendar: [R(3.5, 5, 17, 15.5, 2.8), P('M3.5 10h17'), P('M8 3v4'), P('M16 3v4')],
  bitcoin: [C(12, 12, 9), P('M9.6 7.6h3.6a2.1 2.1 0 0 1 0 4.2H9.6z'), P('M9.6 11.8h4.1a2.3 2.3 0 0 1 0 4.6H9.6z'), P('M9.6 7.6v8.8'), P('M11.2 6.2v1.4M11.2 16.4v1.4M13.4 6.2v1.4M13.4 16.4v1.4')],
  bank: [P('M3.2 9.4L12 4.2l8.8 5.2z'), P('M3.5 20h17'), P('M5.8 12v5.5M9.9 12v5.5M14.1 12v5.5M18.2 12v5.5')],
  card: [R(2.5, 5.5, 19, 13, 2.6), P('M2.5 10h19'), P('M6 15h4')],
  braces: [P('M8.5 4C6.6 4 6 5 6 6.6v2.7C6 10.9 5.3 12 4 12c1.3 0 2 1.1 2 2.7v2.7C6 19 6.6 20 8.5 20'), P('M15.5 4c1.9 0 2.5 1 2.5 2.6v2.7c0 1.6.7 2.7 2 2.7-1.3 0-2 1.1-2 2.7v2.7c0 1.6-.6 2.6-2.5 2.6')],
  text: [P('M5 6.5h14'), P('M5 10.5h14'), P('M5 14.5h14'), P('M5 18.5h8.5')],
  binary: [R(3, 3.5, 18, 17, 3), P('M7.8 9l1.4-1v8'), E(15, 12, 2.1, 4)],
  barcode: [P('M4 5.5v13M6.8 5.5v13M10.6 5.5v13M13 5.5v13M16.8 5.5v13M20 5.5v13')],
  qr: [R(3.5, 3.5, 6.5, 6.5, 1.4), R(14, 3.5, 6.5, 6.5, 1.4), R(3.5, 14, 6.5, 6.5, 1.4), P('M14 14h2.6v2.6H14zM17.9 17.9h2.6v2.6h-2.6zM14 20.5h.01M20.5 14h.01'), C(6.75, 6.75, 0.9, true), C(17.25, 6.75, 0.9, true), C(6.75, 17.25, 0.9, true)],
  open: [P('M14 4h6v6'), P('M20 4l-8.6 8.6'), P('M18 13.8v4.7a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6h4.7')],
  copy: [R(8.5, 8.5, 11.5, 11.5, 2.2), P('M15.5 8.5V6.2a2.2 2.2 0 0 0-2.2-2.2H6.2A2.2 2.2 0 0 0 4 6.2v7.1a2.2 2.2 0 0 0 2.2 2.2h2.3')],
  save: [P('M12 4v10.5'), P('M7.8 10.5L12 14.7l4.2-4.2'), P('M4.5 15.5v3a1.5 1.5 0 0 0 1.5 1.5h12a1.5 1.5 0 0 0 1.5-1.5v-3')],
  eye: [P('M2.5 12S6 5.6 12 5.6 21.5 12 21.5 12 18 18.4 12 18.4 2.5 12 2.5 12z'), C(12, 12, 3)],
  eyeSlash: [P('M2.5 12S6 5.6 12 5.6 21.5 12 21.5 12 18 18.4 12 18.4 2.5 12 2.5 12z'), C(12, 12, 3), P('M4.5 4.5l15 15')],
  lock: [R(5, 10.5, 14, 10, 2.2), P('M8.2 10.5V7.8a3.8 3.8 0 0 1 7.6 0v2.7')],
  lockOpen: [R(5, 10.5, 14, 10, 2.2), P('M8.2 10.5V7.8a3.8 3.8 0 0 1 7.3-1.5')],
  warning: [P('M10.3 4.3a2 2 0 0 1 3.4 0l7.5 13A2 2 0 0 1 19.5 20.3h-15a2 2 0 0 1-1.7-3z'), P('M12 9.4v4.6'), C(12, 16.9, 0.95, true)],
  danger: [P('M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z'), P('M12 7.6v5.4'), C(12, 16.2, 0.95, true)],
  info: [C(12, 12, 9), P('M12 11v5.4'), C(12, 7.9, 0.95, true)],
  chevronRight: [P('M9.5 6l6 6-6 6')],
  chevronDown: [P('M6 9.5l6 6 6-6')],
  chevronUp: [P('M6 14.5l6-6 6 6')],
  xmark: [P('M6.5 6.5l11 11M17.5 6.5l-11 11')],
  xmarkCircle: [C(12, 12, 9), P('M9 9l6 6M15 9l-6 6')],
  clipboard: [R(5, 4.8, 14, 16.2, 2.4), R(8.6, 3, 6.8, 3.8, 1.3), P('M8.8 12h6.4M8.8 15.6h4.2')],
  folder: [P('M3.5 7.4a2 2 0 0 1 2-2h3.9l2 2.1h7.1a2 2 0 0 1 2 2v8.1a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z')],
  sliders: [P('M4 7.5h9M17.4 7.5H20M4 16.5h2.6M11 16.5h9'), C(15.2, 7.5, 2.2), C(8.8, 16.5, 2.2)],
  check: [P('M5 12.6l4.4 4.4L19 7.4')],
  checkCircle: [C(12, 12, 9), P('M8 12.3l2.8 2.8L16.2 9.6')],
  clock: [C(12, 12, 9), P('M12 7.2V12l3.4 2.1')],
  photo: [R(3, 5, 18, 14, 2.6), C(8.8, 10, 1.7), P('M3.6 17.2l4.9-4.4 3.5 3 3.1-2.6 5.3 4.4')],
  doc: [P('M6.5 3h7l5 5v11.5a1.5 1.5 0 0 1-1.5 1.5h-10.5A1.5 1.5 0 0 1 5 19.5v-15A1.5 1.5 0 0 1 6.5 3z'), P('M13.5 3v5h5')],
  shield: [P('M12 3l7.5 3v5.4c0 4.6-3.2 8.4-7.5 9.6-4.3-1.2-7.5-5-7.5-9.6V6z')],
  tray: [P('M12 3.5v10'), P('M7.8 9.4l4.2 4.2 4.2-4.2'), P('M3.5 14.5v3a2.5 2.5 0 0 0 2.5 2.5h12a2.5 2.5 0 0 0 2.5-2.5v-3')],
  zoom: [C(10.5, 10.5, 6.3), P('M15.2 15.2l5 5')],
  hidden: [P('M3 3l18 18'), P('M10.6 6.1A10 10 0 0 1 12 6c6 0 9.5 6 9.5 6a17 17 0 0 1-3 3.6M6.4 7.3A16.7 16.7 0 0 0 2.5 12S6 18 12 18c1.6 0 3-.4 4.3-1')],
  tag: [P('M3.5 12.4V5a1.5 1.5 0 0 1 1.5-1.5h7.4l8.1 8.1a1.5 1.5 0 0 1 0 2.1l-6.3 6.3a1.5 1.5 0 0 1-2.1 0z'), C(8, 8, 1.3, true)],
  sparkle: [P('M12 3.5l1.8 5 5 1.8-5 1.8-1.8 5-1.8-5-5-1.8 5-1.8z')],
};

/** Returns an <svg> icon. `size` in px (default 16). Decorative unless `label` given. */
export function icon(name, { size = 16, label = null, cls = '' } = {}) {
  const parts = ICONS[name] || ICONS.text;
  const s = svg('svg', {
    viewBox: '0 0 24 24', width: size, height: size, class: `icon ${cls}`.trim(),
    fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    'aria-hidden': label ? null : 'true', role: label ? 'img' : null, 'aria-label': label,
  }, ...parts.map(([tag, attrs]) => svg(tag, attrs)));
  return s;
}

/** Per-type icon + tint (tile colour class). */
export const TYPE_META = {
  url: { icon: 'globe', tint: 'blue' },
  wifi: { icon: 'wifi', tint: 'blue' },
  contact: { icon: 'person', tint: 'graphite' },
  otp: { icon: 'key', tint: 'orange' },
  'otp-migration': { icon: 'key', tint: 'orange' },
  email: { icon: 'envelope', tint: 'blue' },
  phone: { icon: 'phone', tint: 'green' },
  sms: { icon: 'message', tint: 'green' },
  geo: { icon: 'pin', tint: 'red' },
  event: { icon: 'calendar', tint: 'red' },
  crypto: { icon: 'bitcoin', tint: 'orange' },
  'epc-payment': { icon: 'bank', tint: 'green' },
  'swiss-qr-bill': { icon: 'bank', tint: 'green' },
  payment: { icon: 'card', tint: 'green' },
  json: { icon: 'braces', tint: 'purple' },
  text: { icon: 'text', tint: 'graphite' },
  binary: { icon: 'binary', tint: 'graphite' },
};
export const typeMeta = (t) => TYPE_META[t] || TYPE_META.text;

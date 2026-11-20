// Tiny DOM helpers. Everything is built with createElement/textContent — the CSP's
// Trusted Types policy makes HTML string sinks throw, and that is the point.

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * el('div', { class: 'x', text: 'hi', on: { click }, dataset: {a: 1}, attrs }, ...children)
 * Props: class, text, title, on, dataset, style (object, applied via CSSOM), aria-* / role /
 * any other key → setAttribute. `false`/`null`/`undefined` values and children are skipped.
 */
export function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  applyProps(e, props);
  append(e, children);
  return e;
}

export function svg(tag, attrs = {}, ...children) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.setAttribute('class', v);
    else e.setAttribute(k, String(v));
  }
  append(e, children);
  return e;
}

function applyProps(e, props) {
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.className = Array.isArray(v) ? v.filter(Boolean).join(' ') : v;
    else if (k === 'text') e.textContent = String(v);
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) e.dataset[dk] = String(dv);
    else if (k === 'style') for (const [sk, sv] of Object.entries(v)) e.style.setProperty(sk, String(sv));
    else if (k === 'disabled' || k === 'hidden') e[k] = !!v;
    else e.setAttribute(k, v === true ? '' : String(v));
  }
}

function append(e, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    e.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

let uid = 0;
export const nextId = (p = 'id') => `${p}-${++uid}`;

export const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

/** Formats a byte count like Finder (1 KB = 1000 bytes). */
export function formatBytes(n) {
  if (!Number.isFinite(n)) return '';
  if (n < 1000) return `${n} byte${n === 1 ? '' : 's'}`;
  const units = ['KB', 'MB', 'GB'];
  let v = n; let i = -1;
  do { v /= 1000; i++; } while (v >= 1000 && i < units.length - 1);
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

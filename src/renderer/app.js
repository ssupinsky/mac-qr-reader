// QR Reader renderer entry. Owns the in-memory state of the CURRENT batch only (no history):
// Clear drops every reference. DOM is built with createElement/textContent (Trusted Types).
import { analyzePayload } from './parsers/index.js';
import { el, $, plural, reducedMotion } from './ui/dom.js';
import { icon } from './ui/icons.js';
import { initToast, toast, clearToast } from './ui/toast.js';
import { copy } from './ui/actions.js';
import { buildCard } from './ui/card.js';
import { previewPane, imageStrip } from './ui/preview.js';
import { errorState, noCodeState, messageState } from './ui/states.js';
import { disposeAllOtp } from './ui/otp.js';
import { settingsControl } from './ui/settings.js';

const qr = window.qr;
const MAX_BYTES = 64 * 1024 * 1024;
const BUSY_DELAY_MS = 150;

const ui = {
  app: $('#app'), empty: $('#empty'), results: $('#results'), busy: $('#busy'),
  drag: $('#drag-overlay'), toolbar: $('#toolbar'), context: $('#tb-context'),
};
initToast($('#toasts'));

/** Current batch. Nothing here is ever persisted. */
const state = {
  results: [],
  analyses: new Map(), // ScanResult → entries[]
  img: 0,
  sel: null,
  cards: [],
  preview: null,
  run: 0,
};

// ----------------------------------------------------------------------------- toolbar
function tbButton(ic, label, onClick, { title, testid } = {}) {
  return el('button', { type: 'button', class: 'tb-btn', title: title || label, 'data-testid': testid, on: { click: onClick } },
    icon(ic, { size: 15 }), el('span', { class: 'tb-label', text: label }));
}
const btnOpen = tbButton('folder', 'Open…', () => doOpen(), { title: 'Open an image or PDF (⌘O)', testid: 'open' });
const btnPaste = tbButton('clipboard', 'Paste', () => doPaste(), { title: 'Scan the clipboard (⌘V)', testid: 'paste' });
const btnClear = tbButton('xmarkCircle', 'Clear', () => clearAll(), { title: 'Clear (⌘K)', testid: 'clear' });
const settings = settingsControl();
ui.toolbar.append(el('div', { class: 'tb-group' }, btnOpen, btnPaste, btnClear), settings.node);

// ----------------------------------------------------------------------------- empty state
function buildEmpty() {
  const kbd = (t) => el('kbd', { text: t });
  ui.empty.replaceChildren(
    el('div', { class: 'drop-card' },
      el('div', { class: 'drop-glyph' }, icon('qr', { size: 44 })),
      el('h1', { class: 'drop-title' }, 'Drop an image, paste ', kbd('⌘V'), ', or open a file ', kbd('⌘O')),
      el('p', { class: 'drop-hint', text: 'Works with files from Finder, screenshots, PDFs and HEIC photos.' }),
      el('div', { class: 'drop-actions' },
        el('button', { type: 'button', class: 'btn btn-large', on: { click: () => doOpen() } }, icon('folder', { size: 15 }), el('span', { text: 'Open…' })),
        el('button', { type: 'button', class: 'btn btn-large', on: { click: () => doPaste() } }, icon('clipboard', { size: 15 }), el('span', { text: 'Paste' })))),
    el('p', { class: 'privacy' }, icon('shield', { size: 12 }), el('span', { text: 'Everything stays on this Mac. No network, no history.' })));
}
buildEmpty();

// ----------------------------------------------------------------------------- analysis
function entriesFor(r) {
  if (state.analyses.has(r)) return state.analyses.get(r);
  const codes = r.source?.kind === 'text' && typeof r.text === 'string'
    ? [{ text: r.text, bytesBase64: null, bytesKind: null, symbology: 'text' }]
    : (r.ok ? r.codes || [] : []);
  const entries = codes.map((code, i) => {
    let analysis;
    try { analysis = analyzePayload({ text: code.text, bytesBase64: code.bytesBase64, bytesKind: code.bytesKind, symbology: code.symbology }); } catch (e) {
      analysis = { type: 'text', title: 'Text', summary: String(code.text || ''), fields: [], warnings: [{ level: 'info', message: `Couldn’t analyse: ${e.message}` }], actions: code.text ? [{ kind: 'copy', label: 'Copy text', value: code.text }] : [], data: { format: 'error' }, raw: { text: code.text || '', escaped: code.text || '', length: (code.text || '').length } };
    }
    return { index: i, n: i + 1, total: codes.length, code, analysis, pages: r.image?.pages || 1 };
  });
  state.analyses.set(r, entries);
  return entries;
}
const codeCount = (r) => (r.source?.kind === 'text' ? 1 : (r.ok ? (r.codes || []).length : 0));

// ----------------------------------------------------------------------------- rendering
function teardownView() {
  disposeAllOtp();
  state.preview?.dispose();
  state.preview = null;
  state.cards = [];
  for (const img of ui.results.querySelectorAll('img')) img.removeAttribute('src');
  ui.results.replaceChildren();
}

function setResults(results) {
  settings.close();
  teardownView();
  state.results = Array.isArray(results) ? results : [];
  state.analyses = new Map();
  // Start on the first result that has codes (else the first one).
  const firstWithCodes = state.results.findIndex((r) => codeCount(r) > 0);
  state.img = Math.max(0, firstWithCodes);
  render();
}

function render() {
  const has = state.results.length > 0;
  ui.empty.hidden = has;
  ui.results.hidden = !has;
  btnClear.disabled = !has;
  ui.app.classList.toggle('has-results', has);
  if (!has) { ui.context.textContent = ''; return; }
  renderImage();
}

function contextText() {
  const rs = state.results;
  const total = rs.reduce((n, r) => n + codeCount(r), 0);
  if (rs.length === 1) {
    const r = rs[0];
    if (!r.ok) return 'Couldn’t scan';
    if (r.source?.kind === 'text') return 'Pasted text';
    return total ? plural(total, 'code') : 'No code found';
  }
  return `${plural(rs.length, 'file')} · ${plural(total, 'code')}`;
}

function renderImage({ focusStrip = false } = {}) {
  teardownView();
  ui.context.textContent = contextText();
  const r = state.results[state.img];
  const parts = [];
  if (state.results.length > 1) {
    parts.push(imageStrip(state.results, state.img, (i, o) => { state.img = i; renderImage(o); }, codeCount));
  }
  const view = el('div', { class: 'split' });
  parts.push(view);
  const entries = entriesFor(r);

  if (!r.ok) {
    view.classList.add('single');
    view.append(errorState(r, [
      el('button', { type: 'button', class: 'btn', on: { click: () => doOpen() } }, icon('folder', { size: 14 }), el('span', { text: 'Open…' })),
      el('button', { type: 'button', class: 'btn', on: { click: () => doPaste() } }, icon('clipboard', { size: 14 }), el('span', { text: 'Paste' }))]));
  } else {
    const hasImage = !!r.image?.previewDataUrl;
    const cb = { onSelect: (i, o) => select(i, { ...o, scroll: true, from: 'preview' }), onHover: hover };
    if (hasImage) {
      state.preview = previewPane(r, entries, cb);
      view.append(el('div', { class: 'pane-left' }, state.preview.node));
    } else view.classList.add('single');

    const right = el('div', { class: 'pane-right', tabindex: '-1' });
    const list = el('div', { class: 'cards', role: 'list', 'aria-label': 'Detected codes' });
    if (!entries.length) {
      right.append(noCodeState(r));
    } else {
      const distinct = new Set(entries.map((e) => e.code.text ?? e.code.bytesBase64));
      if (distinct.size > 1) {
        right.append(el('p', { class: 'batch-note', 'data-testid': 'multi-note', title: 'A sticker can be placed over an original code — compare each code with what you expected.' },
          icon('info', { size: 13 }), el('span', { text: `${distinct.size} different codes here — make sure you use the right one.` })));
      }
      const collapsible = entries.length > 1;
      state.sel = 0;
      state.cards = entries.map((e) => buildCard(e, { expanded: !collapsible || e.index === 0, collapsible, onSelect: (i, o) => select(i, { ...o, from: 'card' }), onHover: hover }));
      for (const c of state.cards) list.append(el('div', { role: 'listitem', class: 'card-slot' }, c.node));
      right.append(list);
    }
    view.append(right);
  }
  ui.results.replaceChildren(...parts);
  if (state.cards.length) select(0, { scroll: false });
  if (focusStrip) ui.results.querySelector('.st-item[aria-selected="true"]')?.focus();
}

function select(i, { toggle = false, scroll = false, from = '' } = {}) {
  if (!state.cards.length || i === null || i < 0 || i >= state.cards.length) return;
  const collapsible = state.cards.length > 1;
  const prev = state.sel;
  state.sel = i;
  state.cards.forEach((c, k) => {
    c.setSelected(k === i);
    if (!collapsible) return;
    if (k === i) c.setExpanded(toggle && prev === i ? !c.expanded : true);
    else if (c.expanded) c.setExpanded(false);
  });
  state.preview?.setSelected(i);
  if (scroll) {
    const node = state.cards[i].node;
    node.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
  }
}

function hover(i) {
  state.cards.forEach((c, k) => c.setHover(k === i));
  state.preview?.setHover(i);
}

function clearAll() {
  state.run++;
  hideBusy();
  teardownView();
  state.results = [];
  state.analyses = new Map();
  state.sel = null;
  clearToast();
  render();
}

// ----------------------------------------------------------------------------- busy + inputs
let busyTimer = 0;
let busyLabel = '';
function showBusy(label) {
  clearTimeout(busyTimer);
  busyLabel = label;
  busyTimer = setTimeout(() => {
    ui.busy.replaceChildren(el('div', { class: 'busy-card' }, el('span', { class: 'spinner', 'aria-hidden': 'true' }), el('span', { class: 'busy-label', text: busyLabel })));
    ui.busy.hidden = false;
    ui.app.classList.add('is-busy');
  }, BUSY_DELAY_MS);
}
/** Updates the busy label in place (no re-layout of the card). */
function setBusyLabel(label) {
  busyLabel = label;
  const n = ui.busy.querySelector('.busy-label');
  if (n) n.textContent = label;
}
function hideBusy() {
  clearTimeout(busyTimer);
  ui.busy.hidden = true;
  ui.app.classList.remove('is-busy');
}

async function run(label, producer) {
  const token = ++state.run;
  showBusy(label);
  try {
    const results = await producer(token);
    if (token !== state.run) return;
    if (results && results.length) setResults(results);
  } catch (e) {
    if (token !== state.run) return;
    toast(`${label.replace(/…$/, '')} failed: ${e?.message || e}`, { icon: 'warning', tone: 'warn', ms: 3500 });
  } finally {
    if (token === state.run) hideBusy();
  }
}

const doOpen = () => run('Opening…', () => qr.openFiles());
const doPaste = () => run('Reading clipboard…', () => qr.pasteFromClipboard());

const MAX_FILES = 100;
/** Decodes dropped files, two at a time (= main's decoder concurrency), keeping their order. */
async function decodeFiles(files, source, token) {
  const list = files.slice(0, MAX_FILES);
  const out = new Array(list.length);
  let next = 0;
  let done = 0;
  const one = async (f) => {
    if (f.size > MAX_BYTES) return localError(f.name, 'too_large', 'File is larger than 64 MiB');
    try {
      return await qr.decodeImage(new Uint8Array(await f.arrayBuffer()), { name: f.name, source });
    } catch (e) {
      return localError(f.name, e instanceof RangeError ? 'too_large' : 'read_error', e?.message || String(e));
    }
  };
  const worker = async () => {
    while (next < list.length && token === state.run) {
      const i = next++;
      out[i] = await one(list[i]);
      done++;
      if (list.length > 1 && token === state.run) setBusyLabel(`Scanning ${done + 1 > list.length ? list.length : done + 1} of ${list.length}…`);
    }
  };
  await Promise.all([worker(), worker()]);
  if (files.length > MAX_FILES) out.push(localError(`${files.length - MAX_FILES} more files`, 'too_many_files', 'Too many files'));
  return out.filter(Boolean);
}
function localError(name, code, message) {
  return { id: `local-${Math.random().toString(36).slice(2)}`, source: { kind: 'drop', name }, ok: false, error: { code, message }, codes: [] };
}

// Drag & drop: the whole window is a drop target.
let dragDepth = 0;
const hasFiles = (e) => [...(e.dataTransfer?.types || [])].some((t) => t === 'Files' || t === 'text/plain' || t === 'text/uri-list');
function setDrag(on) {
  ui.app.classList.toggle('dragging', on);
  if (on && !ui.drag.childElementCount) {
    ui.drag.append(el('div', { class: 'drag-card' }, icon('tray', { size: 34 }), el('span', { text: 'Drop to scan' })));
  }
}
window.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; setDrag(true); });
window.addEventListener('dragover', (e) => { if (!hasFiles(e)) return; e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'; });
window.addEventListener('dragleave', (e) => { if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth || !e.relatedTarget) { dragDepth = 0; setDrag(false); } });
window.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  setDrag(false);
  const files = [...(e.dataTransfer?.files || [])];
  if (files.length) { run(files.length > 1 ? `Scanning 1 of ${Math.min(files.length, MAX_FILES)}…` : 'Scanning…', (token) => decodeFiles(files, 'drop', token)); return; }
  const text = e.dataTransfer?.getData('text/plain');
  if (text) setResults([{ id: 'dropped-text', source: { kind: 'text', name: 'Dropped text' }, ok: true, codes: [], text: text.slice(0, 1_000_000) }]);
});

// Paste: always let main read the clipboard (Chromium only exposes the first Finder file).
document.addEventListener('paste', (e) => { e.preventDefault(); doPaste(); });

qr.onScanResults((results) => {
  state.run++;
  hideBusy();
  if (Array.isArray(results) && results.length) {
    setResults(results);
    if (results[0]?.source?.kind === 'clipboard-auto') toast('Scanned the image on your clipboard', { icon: 'clipboard', tone: 'muted', ms: 2400 });
  }
});

async function copyPrimary() {
  const c = state.cards[state.sel ?? 0];
  if (!c) { toast('Nothing to copy', { icon: 'info', tone: 'muted' }); return; }
  const p = await c.primary();
  if (p?.value) copy(p.value, { sensitive: p.sensitive, what: p.what });
}

qr.onCommand((cmd) => {
  if (cmd === 'open') doOpen();
  else if (cmd === 'paste') doPaste();
  else if (cmd === 'clear') clearAll();
  else if (cmd === 'copy-primary') copyPrimary();
  else if (cmd === 'settings-changed') settings.sync();
});

// ----------------------------------------------------------------------------- keyboard
document.addEventListener('keydown', (e) => {
  if (e.defaultPrevented) return;
  const t = e.target;
  const typing = t instanceof HTMLInputElement && t.type !== 'checkbox';
  if (e.key === 'Escape') {
    if (settings.isOpen()) { settings.close(); return; }
    if (state.results.length) { e.preventDefault(); clearAll(); }
    return;
  }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  if (!state.cards.length) return;
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    if (t instanceof Element && t.closest('.segmented, .strip')) return;
    e.preventDefault();
    const n = state.cards.length;
    const next = Math.min(n - 1, Math.max(0, (state.sel ?? 0) + (e.key === 'ArrowDown' ? 1 : -1)));
    select(next, { scroll: true });
    if (t instanceof Element && t.closest('.card')) state.cards[next].focus();
  } else if (e.key === 'Enter') {
    if (t instanceof Element && t.classList.contains('card-head')) { e.preventDefault(); copyPrimary(); return; }
    if (t instanceof HTMLButtonElement || t instanceof HTMLAnchorElement || (t instanceof HTMLInputElement)) return;
    e.preventDefault();
    copyPrimary();
  } else if ((e.key === 'z' || e.key === 'Z') && !e.shiftKey) {
    state.preview?.toggleZoom();
  }
});

render();

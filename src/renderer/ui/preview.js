// Image preview with outlines + numbered badges for every detected code, hover/selection
// sync with the cards, zoom-to-code for small codes, multi-page (PDF/GIF) notes.
import { el, svg, plural } from './dom.js';
import { icon } from './icons.js';
import { displayText, attrText } from './text.js';

const SOURCE_WORDS = {
  drop: 'Dropped', paste: 'Pasted', file: 'Opened', 'open-with': 'Opened', 'clipboard-auto': 'Clipboard · auto-scan', text: 'Pasted text',
};
export const sourceWord = (r) => SOURCE_WORDS[r.source?.kind] || '';

/**
 * @param {object} result ScanResult (ok, with image)
 * @param {Array<{index:number, n:number, code:object}>} entries
 * @param {{onSelect:(i:number)=>void, onHover:(i:number|null)=>void}} cb
 */
export function previewPane(result, entries, cb) {
  const img = result.image;
  const pw = img.previewWidth || img.width;
  const ph = img.previewHeight || img.height;
  const page = img.previewPage || 0;
  const ratio = pw > 0 && ph > 0 ? pw / ph : 1;

  const picture = el('img', { class: 'pv-img', alt: `Preview of ${attrText(result.source?.name || 'image')}`, draggable: 'false', decoding: 'async' });
  picture.src = img.previewDataUrl;
  const overlay = svg('svg', { class: 'pv-overlay', viewBox: '0 0 1 1', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  const badges = el('div', { class: 'pv-badges' });
  const zoomer = el('div', { class: 'pv-zoomer' }, picture, overlay, badges);
  const frame = el('div', { class: 'pv-frame', style: { '--ratio': ratio } }, zoomer);
  const stage = el('div', { class: 'pv-stage' }, frame);

  const shapes = new Map();
  const onPage = entries.filter((e) => (e.code.page || 0) === page && Array.isArray(e.code.corners) && e.code.corners.length === 4);
  const offPage = entries.filter((e) => !onPage.includes(e));
  const multi = entries.length > 1;

  for (const e of onPage) {
    const pts = e.code.corners.map(([x, y]) => `${clamp01(x)},${clamp01(y)}`).join(' ');
    const halo = svg('polygon', { class: 'pv-halo', points: pts, 'vector-effect': 'non-scaling-stroke' });
    const poly = svg('polygon', { class: 'pv-poly', points: pts, 'vector-effect': 'non-scaling-stroke' });
    const g = svg('g', { class: 'pv-code' }, halo, poly);
    overlay.append(g);
    // Badge at the top-most-left corner.
    const [bx, by] = e.code.corners.reduce((m, c) => (c[1] + c[0] * 0.3 < m[1] + m[0] * 0.3 ? c : m));
    const badge = el('button', {
      type: 'button', class: 'pv-badge', tabindex: '-1', text: multi ? String(e.n) : '',
      'aria-label': `Select code ${e.n}`, style: { left: `${clamp01(bx) * 100}%`, top: `${clamp01(by) * 100}%` },
      on: {
        click: (ev) => { ev.stopPropagation(); cb.onSelect(e.index); },
        mouseenter: () => cb.onHover(e.index), mouseleave: () => cb.onHover(null),
      },
    });
    if (multi) badges.append(badge);
    // Clicking inside the outline selects it too.
    const hit = el('button', {
      type: 'button', class: 'pv-hit', tabindex: '-1', 'aria-hidden': 'true',
      style: bboxStyle(e.code),
      on: { click: (ev) => { ev.stopPropagation(); cb.onSelect(e.index); }, mouseenter: () => cb.onHover(e.index), mouseleave: () => cb.onHover(null) },
    });
    badges.prepend(hit);
    shapes.set(e.index, { g, badge, code: e.code });
  }

  // Zoom control (only useful when the selected code is small in the frame).
  let zoomed = false;
  let selected = null;
  const zoomBtn = el('button', { type: 'button', class: 'pv-zoom icon-btn glass', 'aria-pressed': 'false', 'aria-label': 'Zoom to code', title: 'Zoom to code (Z)' }, icon('zoom', { size: 15 }));
  zoomBtn.hidden = true;
  zoomBtn.addEventListener('click', () => setZoom(!zoomed));
  frame.append(zoomBtn);

  function setZoom(on) {
    const s = selected !== null ? shapes.get(selected) : null;
    zoomed = !!on && !!s;
    zoomBtn.setAttribute('aria-pressed', String(zoomed));
    zoomBtn.replaceChildren(icon(zoomed ? 'xmark' : 'zoom', { size: 15 }));
    zoomBtn.setAttribute('aria-label', zoomed ? 'Show whole image' : 'Zoom to code');
    zoomBtn.title = zoomed ? 'Show whole image (Z)' : 'Zoom to code (Z)';
    frame.classList.toggle('zoomed', zoomed);
    if (!zoomed) { zoomer.style.transform = ''; updatePixelation(); return; }
    const b = bbox(s.code);
    const scale = Math.min(0.55 / Math.max(b.w, 0.001), 0.55 / Math.max(b.h, 0.001), 12);
    const cx = b.x + b.w / 2; const cy = b.y + b.h / 2;
    const tx = clampT(0.5 - cx * scale, scale); const ty = clampT(0.5 - cy * scale, scale);
    zoomer.style.transform = `translate(${tx * 100}%, ${ty * 100}%) scale(${scale})`;
    zoomer.style.setProperty('--zoom', String(scale));
    updatePixelation(scale);
  }

  function updatePixelation(scale = 1) {
    const shown = frame.clientWidth * devicePixelRatio * scale;
    picture.classList.toggle('pixelated', shown > pw * 1.15);
  }
  const ro = new ResizeObserver(() => updatePixelation(zoomed ? Number(zoomer.style.getPropertyValue('--zoom')) || 1 : 1));
  ro.observe(frame);

  // Caption
  const fmt = (img.format || '').toUpperCase();
  const pages = img.pages || 1;
  const capBits = [fmt, `${img.width} × ${img.height}`];
  if (pages > 1) capBits.push(img.format === 'gif' ? plural(pages, 'frame') : plural(pages, 'page'));
  const caption = el('div', { class: 'pv-caption' },
    el('div', { class: 'pv-name', title: attrText(result.source?.name || '') }, icon(img.format === 'pdf' ? 'doc' : 'photo', { size: 13 }), el('span', {}, displayText(result.source?.name || 'Image'))),
    el('div', { class: 'pv-meta', text: [sourceWord(result), ...capBits].filter(Boolean).join(' · ') }));
  const notes = el('div', { class: 'pv-notes' });
  if (pages > 1) {
    notes.append(el('div', { class: 'pv-note' }, icon('doc', { size: 12 }),
      el('span', { text: `Preview shows ${img.format === 'gif' ? 'frame' : 'page'} ${page + 1} of ${pages}${offPage.length ? '' : ''}` })));
  }
  if (offPage.length) {
    const byPage = offPage.map((e) => `${multi ? `#${e.n}` : 'The code'} on ${img.format === 'gif' ? 'frame' : 'page'} ${(e.code.page || 0) + 1}`).join(', ');
    notes.append(el('div', { class: 'pv-note' }, icon('info', { size: 12 }), el('span', { text: `${byPage} — not in this preview` })));
  }

  const node = el('section', { class: 'preview', 'aria-label': 'Image preview' }, stage, caption, notes.childElementCount ? notes : null);

  return {
    node,
    setSelected(i) {
      selected = i;
      for (const [k, s] of shapes) {
        s.g.classList.toggle('selected', k === i);
        s.badge.classList.toggle('selected', k === i);
      }
      overlay.classList.toggle('has-selection', i !== null && shapes.has(i) && shapes.size > 1);
      const s = shapes.get(i);
      const small = s ? Math.max(bbox(s.code).w, bbox(s.code).h) < 0.2 : false;
      zoomBtn.hidden = !small;
      if (zoomed) setZoom(!!s);
    },
    setHover(i) {
      for (const [k, s] of shapes) { s.g.classList.toggle('hover', k === i); s.badge.classList.toggle('hover', k === i); }
    },
    toggleZoom() { if (!zoomBtn.hidden) setZoom(!zoomed); },
    dispose() { ro.disconnect(); picture.removeAttribute('src'); },
  };
}

const clamp01 = (v) => Math.min(1, Math.max(0, Number(v) || 0));
const clampT = (t, s) => Math.min(0, Math.max(1 - s, t));

function bbox(code) {
  if (Array.isArray(code.corners) && code.corners.length) {
    const xs = code.corners.map((c) => clamp01(c[0])); const ys = code.corners.map((c) => clamp01(c[1]));
    const x = Math.min(...xs); const y = Math.min(...ys);
    return { x, y, w: Math.max(...xs) - x, h: Math.max(...ys) - y };
  }
  const b = code.bounds || { x: 0, y: 0, w: 1, h: 1 };
  return { x: b.x, y: b.y, w: b.w, h: b.h };
}
function bboxStyle(code) {
  const b = bbox(code);
  return { left: `${b.x * 100}%`, top: `${b.y * 100}%`, width: `${b.w * 100}%`, height: `${b.h * 100}%` };
}

/** Thumbnail strip for batches with several images/files. */
export function imageStrip(results, current, onPick, countFor) {
  const strip = el('div', { class: 'strip', role: 'tablist', 'aria-label': 'Scanned files', 'data-testid': 'strip' });
  results.forEach((r, i) => {
    const n = countFor(r);
    const thumb = r.ok && r.image?.previewDataUrl
      ? el('img', { class: 'st-img', alt: '', draggable: 'false', decoding: 'async' })
      : el('span', { class: 'st-icon' }, icon(r.ok ? (r.source?.kind === 'text' ? 'text' : 'photo') : 'warning', { size: 18 }));
    if (thumb.tagName === 'IMG') thumb.src = r.image.previewDataUrl;
    const badge = !r.ok ? el('span', { class: 'st-badge err', text: '!' })
      : el('span', { class: ['st-badge', n === 0 && 'zero'], text: String(n) });
    const item = el('button', {
      type: 'button', role: 'tab', class: 'st-item', 'aria-selected': String(i === current), tabindex: i === current ? '0' : '-1',
      title: `${attrText(r.source?.name || 'Item')} — ${!r.ok ? 'error' : plural(n, 'code')}`,
      on: { click: () => onPick(i) },
    }, el('span', { class: 'st-thumb' }, thumb, badge), el('span', { class: 'st-name' }, displayText(r.source?.name || `Item ${i + 1}`)));
    strip.append(item);
  });
  strip.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault(); e.stopPropagation();
    const next = Math.min(results.length - 1, Math.max(0, current + (e.key === 'ArrowRight' ? 1 : -1)));
    if (next !== current) onPick(next, { focusStrip: true });
  });
  requestAnimationFrame(() => strip.children[current]?.scrollIntoView({ block: 'nearest', inline: 'nearest' }));
  return strip;
}

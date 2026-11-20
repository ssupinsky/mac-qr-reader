// Result card: header (type icon, title, summary, number), warnings, type-specific hero,
// remaining fields, actions, and the Raw disclosure.
import { el, nextId } from './dom.js';
import { icon, typeMeta } from './icons.js';
import { runAction, copyNoun } from './actions.js';
import { buildHero } from './heroes.js';
import { fieldList } from './fields.js';
import { rawDisclosure } from './rawview.js';
import { displayText, renderEscaped } from './text.js';

const LEVEL_ICON = { danger: 'danger', caution: 'warning', info: 'info' };
const LEVEL_WORD = { danger: 'Danger', caution: 'Caution', info: 'Note' };

export function warningBanner(w, { compact = false } = {}) {
  return el('div', { class: ['warn', `lvl-${w.level}`, compact && 'compact'], role: w.level === 'danger' ? 'alert' : null, 'data-testid': 'warning' },
    icon(LEVEL_ICON[w.level] || 'info', { size: compact ? 13 : 15 }),
    el('span', { class: 'sr-only', text: `${LEVEL_WORD[w.level] || 'Note'}: ` }),
    el('span', { class: 'warn-msg' }, displayText(w.message)));
}

function isSensitive(a) {
  return a.fields.some((f) => f.sensitive) || a.actions.some((x) => x.sensitive)
    || (Array.isArray(a.data?.query) && a.data.query.some((q) => q?.sensitive)) || a.type === 'otp' || a.type === 'otp-migration';
}

function actionButton(x, { label } = {}) {
  const ic = x.kind === 'open' ? 'open' : x.kind === 'save' ? 'save' : 'copy';
  const text = label || x.label;
  return el('button', {
    type: 'button',
    class: ['btn', x.kind === 'open' && 'btn-accent'],
    title: x.sensitive ? `${text} — clipboard clears in 60 s` : x.kind === 'open' ? 'You’ll be asked to confirm before anything opens' : null,
    dataset: { kind: x.kind },
    on: { click: (e) => { e.stopPropagation(); runAction(x); } },
  }, icon(ic, { size: 14 }), el('span', { text }), x.sensitive ? icon('lock', { size: 11, cls: 'btn-lock' }) : null);
}

/**
 * @param {{n: number, total: number, code: object, analysis: object, pages: number}} entry
 * @param {{expanded: boolean, collapsible: boolean, onSelect: Function, onHover: Function}} opts
 */
export function buildCard(entry, opts) {
  const a = entry.analysis;
  const meta = typeMeta(a.type);
  const bodyId = nextId('card-body');
  const top = a.warnings.find((w) => w.level !== 'info');
  const dangerCount = a.warnings.filter((w) => w.level === 'danger').length;

  const head = el(opts.collapsible ? 'button' : 'div', {
    class: 'card-head', type: opts.collapsible ? 'button' : null,
    'aria-expanded': opts.collapsible ? String(!!opts.expanded) : null,
    'aria-controls': opts.collapsible ? bodyId : null,
  },
  entry.total > 1 ? el('span', { class: 'num-badge', 'aria-label': `Code ${entry.n}`, text: String(entry.n) }) : null,
  el('span', { class: `type-tile tint-${dangerCount ? 'red' : meta.tint}` }, icon(meta.icon, { size: 18 })),
  el('span', { class: 'head-text' },
    el('span', { class: 'card-title', 'data-testid': 'title' },
      el('span', {}, displayText(a.title)),
      dangerCount ? el('span', { class: 'tag tag-danger small', text: dangerCount > 1 ? `${dangerCount} risks` : 'Risk' }) : null),
    el('span', { class: 'card-summary', 'data-testid': 'summary' }, summaryNode(a))),
  el('span', { class: 'symb', text: symbLabel(entry.code) }),
  opts.collapsible ? icon('chevronDown', { size: 14, cls: 'card-chev' }) : null);

  const peek = top ? el('div', { class: 'card-peek' }, warningBanner(top, { compact: true })) : null;
  const body = el('div', { class: 'card-body', id: bodyId });
  let bodyBuilt = false;

  const node = el('article', {
    class: ['card', `type-${a.type}`, top && `has-${top.level}`],
    'data-testid': 'code', dataset: { index: entry.index, type: a.type },
    'aria-label': `${entry.total > 1 ? `Code ${entry.n}: ` : ''}${a.title}`,
  }, head, peek, body);

  let hero = null;
  const buildBody = () => {
    if (bodyBuilt) return;
    bodyBuilt = true;
    const strong = a.warnings.filter((w) => w.level !== 'info');
    const infos = a.warnings.filter((w) => w.level === 'info');
    const warns = strong.length ? el('div', { class: 'warns' }, strong.map((w) => warningBanner(w))) : null;
    const notes = infos.length ? el('ul', { class: 'notes', 'aria-label': 'Notes' }, infos.map((w) => el('li', {}, icon('info', { size: 13 }), el('span', {}, displayText(w.message))))) : null;
    hero = buildHero(a);
    const rest = hero?.hide ? a.fields.filter((f) => !hero.hide(f)) : a.fields;
    const fl = fieldList(rest, { chunkLabels: /IBAN|Address|Account|Reference|Key/i });

    const acts = a.actions.filter((x) => (hero?.filterActions ? hero.filterActions(x) : true));
    const left = acts.filter((x) => x.kind !== 'open');
    const right = acts.filter((x) => x.kind === 'open');
    const bar = el('div', { class: 'actions', 'data-testid': 'actions' },
      left.map((x) => actionButton(x)),
      right.map((x, i) => { const b = actionButton(x, { label: hero?.openLabel && /^Open…$/.test(x.label) ? hero.openLabel : null }); if (i === 0) b.classList.add('push'); return b; }));
    let reason = null;
    if (hero?.disabledReason && !right.length) {
      bar.append(el('button', { type: 'button', class: 'btn btn-accent push', disabled: true, 'aria-describedby': `${bodyId}-why` }, icon('open', { size: 14 }), el('span', { text: 'Open…' })));
      reason = el('p', { class: 'not-openable', id: `${bodyId}-why` }, icon('info', { size: 13 }), el('span', { text: hero.disabledReason }));
    }
    body.append(...[warns, hero?.node, notes, fl && el('div', { class: 'details' }, fl), bar, reason,
      rawDisclosure(a, entry.code, { sensitive: isSensitive(a), pages: entry.pages })].filter(Boolean));
  };

  const api = {
    node,
    expanded: false,
    setExpanded(on) {
      api.expanded = !!on;
      if (on) buildBody();
      body.hidden = !on;
      if (peek) peek.hidden = !!on;
      node.classList.toggle('expanded', !!on);
      if (opts.collapsible) head.setAttribute('aria-expanded', String(!!on));
    },
    setSelected(on) { node.classList.toggle('selected', !!on); node.setAttribute('aria-current', on ? 'true' : 'false'); },
    setHover(on) { node.classList.toggle('hover', !!on); },
    focus() { head.focus({ preventScroll: true }); },
    /** Value for ⇧⌘C / Enter. */
    async primary() {
      buildBody();
      if (hero?.primary) { const p = await hero.primary(); if (p) return p; }
      const c = a.actions.find((x) => x.kind === 'copy');
      if (c) return { value: c.value, sensitive: !!c.sensitive, what: copyNoun(c.label, c.sensitive) };
      return a.raw?.text ? { value: a.raw.text, sensitive: isSensitive(a), what: 'Text' } : null;
    },
  };
  if (opts.collapsible) {
    head.addEventListener('click', () => opts.onSelect(entry.index, { toggle: true }));
  }
  node.addEventListener('click', (e) => { if (!head.contains(e.target)) opts.onSelect(entry.index, { toggle: false }); });
  node.addEventListener('mouseenter', () => opts.onHover(entry.index));
  node.addEventListener('mouseleave', () => opts.onHover(null));
  api.setExpanded(!!opts.expanded);
  return api;
}

function symbLabel(code) {
  if (!code || code.symbology === 'text') return 'Text';
  const s = code.symbology;
  return ({ MicroQR: 'Micro QR', DataMatrix: 'Data Matrix', MicroPDF417: 'MicroPDF417', EAN13: 'EAN-13', EAN8: 'EAN-8', UPCE: 'UPC-E', Code39: 'Code 39', Code93: 'Code 93', Code128: 'Code 128', ITF14: 'ITF-14', I2of5: 'ITF', GS1DataBar: 'GS1 DataBar' })[s] || s;
}

/** Summary line. Parsers escape invisible characters in it; a truncated escape (\\u{20…) is
 *  dropped so it never shows as a half-escaped sequence. */
function summaryNode(a) {
  const s = String(a.summary ?? '');
  if (a.raw?.hasInvisible && /\\u\{/.test(s)) return renderEscaped(s.replace(/(?<!\\)\\(u(\{[0-9A-Fa-f]*)?)?…$/, '…'));
  return displayText(s);
}

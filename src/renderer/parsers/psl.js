// Public Suffix List lookup ("Formal algorithm", https://publicsuffix.org/list/).
// Rules come from the bundled snapshot in data/psl-rules.js (ASCII/punycode form),
// so lookups take WHATWG `url.hostname` (ACE) directly.

import { ICANN_RULES, PRIVATE_RULES, PSL_VERSION } from './data/psl-rules.js';

export { PSL_VERSION };

/** @type {{ exact: Map<string,string>, wildcard: Map<string,string>, exception: Map<string,string> } | null} */
let tables = null;

/** Builds the lookup tables lazily (≈10k rules, a few ms). Values = section. */
function getTables() {
  if (tables) return tables;
  const t = { exact: new Map(), wildcard: new Map(), exception: new Map(), maxLabels: 0 };
  const add = (rules, section) => {
    if (typeof rules !== 'string') return;
    for (const rule of rules.split('\n')) {
      if (!rule) continue;
      t.maxLabels = Math.max(t.maxLabels, rule.split('.').length);
      if (rule.startsWith('!')) t.exception.set(rule.slice(1), section);
      else if (rule.startsWith('*.')) t.wildcard.set(rule.slice(2), section);
      else t.exact.set(rule, section);
    }
  };
  add(ICANN_RULES, 'icann');
  add(PRIVATE_RULES, 'private');
  tables = t;
  return t;
}

/** Whether the bundled list is available (used to decide on the heuristic fallback). */
export function pslAvailable() {
  return getTables().exact.size > 0;
}

const FALLBACK_SLDS = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ne', 'or', 'go']);

/**
 * Looks up the public suffix and registrable domain of an ASCII host.
 *
 * @param {string} host ACE hostname (e.g. `url.hostname`); ASCII case is ignored;
 *   a single trailing root dot is ignored for matching and re-appended to results.
 * @returns {{ publicSuffix: string|null, registrableDomain: string|null, subdomain: string,
 *   isPublicSuffix: boolean, listed: boolean, section: 'icann'|'private'|null,
 *   approximate: boolean }}
 *   `listed` = a rule other than the default `*` matched. `publicSuffix`/`registrableDomain`
 *   are null for empty/invalid input (empty labels, leading dot).
 */
export function lookup(host) {
  const empty = {
    publicSuffix: null, registrableDomain: null, subdomain: '', isPublicSuffix: false,
    listed: false, section: null, approximate: false,
  };
  if (typeof host !== 'string' || !host) return empty;
  let name = host.replace(/[A-Z]/g, (c) => c.toLowerCase());
  let rootDot = '';
  if (name.endsWith('.') && name.length > 1) {
    name = name.slice(0, -1);
    rootDot = '.';
  }
  const labels = name.split('.');
  if (labels.some((l) => l === '')) return empty;

  const t = getTables();
  let suffixLen;
  let listed = true;
  let section = null;
  let approximate = false;

  if (t.exact.size === 0) {
    // Fallback heuristic (list failed to load): last two labels, or three for co.uk-style.
    approximate = true;
    listed = false;
    const n = labels.length;
    suffixLen = n >= 2 && /^[a-z]{2}$/.test(labels[n - 1]) && FALLBACK_SLDS.has(labels[n - 2]) ? 2 : 1;
  } else {
    suffixLen = 0;
    // Walk suffixes from the shortest; the longest matching rule wins, exceptions override.
    // No rule has more than `maxLabels` labels, so longer candidates are skipped (keeps
    // hosts with thousands of labels linear).
    const stop = Math.max(0, labels.length - t.maxLabels);
    for (let i = labels.length - 1; i >= stop; i--) {
      const candidate = labels.slice(i).join('.');
      const len = labels.length - i;
      if (t.exception.has(candidate)) {
        suffixLen = len - 1;
        section = t.exception.get(candidate);
        break; // exception rules always win
      }
      if (t.exact.has(candidate) && len > suffixLen) {
        suffixLen = len;
        section = t.exact.get(candidate);
      }
      const parent = labels.slice(i + 1).join('.');
      if (i + 1 < labels.length && t.wildcard.has(parent) && len > suffixLen) {
        suffixLen = len;
        section = t.wildcard.get(parent);
      }
    }
    if (suffixLen === 0) {
      suffixLen = 1; // default rule "*"
      listed = false;
    }
  }

  const publicSuffix = labels.slice(-suffixLen).join('.') + rootDot;
  if (labels.length <= suffixLen) {
    return { ...empty, publicSuffix, isPublicSuffix: true, listed, section, approximate };
  }
  const registrable = labels.slice(-(suffixLen + 1)).join('.') + rootDot;
  const subdomain = labels.slice(0, labels.length - suffixLen - 1).join('.');
  return {
    publicSuffix, registrableDomain: registrable, subdomain, isPublicSuffix: false,
    listed, section, approximate,
  };
}

/** Convenience: registrable domain ("eTLD+1") of an ASCII host, or null. */
export function getRegistrableDomain(host) {
  return lookup(host).registrableDomain;
}

/** Convenience: public suffix of an ASCII host, or null. */
export function getPublicSuffix(host) {
  return lookup(host).publicSuffix;
}

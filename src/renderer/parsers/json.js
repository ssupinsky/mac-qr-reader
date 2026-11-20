// JSON payloads (PAYLOADS.md §11.8): pretty-printed view with a depth guard, URLs
// inside string values analysed (§2), secret-looking keys marked sensitive.

import { analyzeUrl } from './url.js';
import { isApiSecret } from './formats/secrets.js';

const MAX_DEPTH = 64;
const SECRET_KEY = /password|passwd|secret|token|apikey|api_key|private|(^|_)key$/i;
const URL_VALUE = /^(?:https?|ftp|javascript|data|file):/i;

/** Max nesting depth of a parsed JSON value (iterative; never recurses deeply). */
function depthOf(value) {
  let max = 0;
  const stack = [[value, 1]];
  while (stack.length) {
    const [v, d] = stack.pop();
    if (v && typeof v === 'object') {
      if (d > max) max = d;
      if (d > MAX_DEPTH) return d;
      for (const child of Object.values(v)) stack.push([child, d + 1]);
    }
  }
  return max;
}

/** Walks string leaves with their JSON paths (bounded). */
function* leaves(value, path = '$', budget = { n: 0 }) {
  if (budget.n++ > 5000) return;
  if (typeof value === 'string') yield [path, value, null];
  else if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) yield* leaves(value[i], `${path}[${i}]`, budget);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      const p = /^[A-Za-z_$][\w$]*$/.test(k) ? `${path}.${k}` : `${path}[${JSON.stringify(k)}]`;
      if (typeof v !== 'object' || v === null) yield [p, v, k];
      else yield* leaves(v, p, budget);
    }
  }
}

export const jsonParser = {
  id: 'json',
  detect(text) {
    if (!/^\s*[[{]/.test(text)) return false;
    try {
      JSON.parse(text);
      return true;
    } catch {
      return false;
    }
  },
  parse(text) {
    const value = JSON.parse(text);
    const warnings = [];
    const fields = [];
    const depth = depthOf(value);
    const tooDeep = depth > MAX_DEPTH;
    const pretty = tooDeep ? text : JSON.stringify(value, null, 2);
    if (tooDeep) warnings.push({ level: 'info', message: `Deeply nested JSON (> ${MAX_DEPTH} levels); shown as is` });

    const urls = [];
    const sensitivePaths = [];
    let hasApiSecret = false;
    if (!tooDeep) {
      for (const [path, v, key] of leaves(value)) {
        const apiSecret = typeof v === 'string' && isApiSecret(v);
        if (apiSecret) hasApiSecret = true;
        if (v !== null && v !== '' && ((key && SECRET_KEY.test(key)) || apiSecret)) {
          sensitivePaths.push(path);
          fields.push({ label: path, value: String(v), sensitive: true, mono: true });
        }
        if (typeof v === 'string' && URL_VALUE.test(v) && urls.length < 20) {
          const a = analyzeUrl(v, { depth: 1 });
          urls.push({ path, url: v, summary: a.summary, warnings: a.warnings });
          for (const w of a.warnings) {
            if (w.level !== 'info') warnings.push({ level: w.level, message: `Link at ${path}: ${w.message}` });
          }
        }
      }
    }
    if (hasApiSecret) warnings.push({ level: 'danger', message: 'Looks like an API secret/credential — don\'t share it' });
    if (sensitivePaths.length) {
      warnings.push({ level: 'caution', message: `Contains secret-looking values (${sensitivePaths.slice(0, 3).join(', ')}${sensitivePaths.length > 3 ? ', …' : ''})` });
    }

    const kind = Array.isArray(value) ? `array of ${value.length}` : value && typeof value === 'object'
      ? `object with ${Object.keys(value).length} keys` : typeof value;
    return {
      type: 'json',
      title: 'JSON data',
      summary: `JSON ${kind}`,
      fields: [{ label: 'JSON', value: pretty, mono: true }, ...fields],
      warnings,
      actions: [
        { kind: 'copy', label: 'Copy JSON', value: text, ...(sensitivePaths.length ? { sensitive: true } : {}) },
        ...(pretty !== text ? [{ kind: 'copy', label: 'Copy formatted', value: pretty, ...(sensitivePaths.length ? { sensitive: true } : {}) }] : []),
      ],
      data: { format: 'json', value: tooDeep ? null : value, pretty, depth, tooDeep, urls, sensitivePaths },
    };
  },
};

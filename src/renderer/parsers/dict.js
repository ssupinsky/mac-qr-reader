// Dictionary helpers for objects keyed by attacker-controlled strings. A plain `{}`
// inherits `constructor`, `toString`, `__proto__`…, so `key in obj` / `obj[key]` give
// false hits (functions) and `obj.__proto__ = v` silently drops the value.

/** Own-property test (never sees Object.prototype). */
export const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/** `obj[key]` restricted to own properties (lookup tables keyed by payload text). */
export const getOwn = (obj, key) => (hasOwn(obj, key) ? obj[key] : undefined);

/** Defines an own enumerable property (works for "__proto__" too). */
export function setOwn(obj, key, value) {
  Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
  return obj;
}

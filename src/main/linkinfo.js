'use strict';
// Helpers for the openExternal confirm dialog (docs/SECURITY.md §5.9): registrable domain via
// the bundled Public Suffix List, display truncation, bidi isolation, local-address detection.

const path = require('node:path');
const { pathToFileURL } = require('node:url');

// The PSL module is an ES module shared with the renderer parsers; CommonJS main loads it with
// dynamic import() (works in Electron's main process, also from inside app.asar). Cached.
let pslPromise = null;
function loadPsl() {
  if (!pslPromise) {
    const file = path.join(__dirname, '..', 'renderer', 'parsers', 'psl.js'); // = paths.SRC_DIR (no electron import: unit-testable)
    pslPromise = import(pathToFileURL(file).href).catch(() => null);
  }
  return pslPromise;
}

/** Registrable domain ("eTLD+1", ACE) of an ASCII hostname, or null (IP, public suffix, error). */
async function registrableDomain(hostname) {
  if (!hostname || hostname.startsWith('[') || /^[0-9.]+$/.test(hostname)) return null;
  const psl = await loadPsl();
  if (!psl || typeof psl.lookup !== 'function') return null;
  try {
    const r = psl.lookup(hostname);
    return typeof r?.registrableDomain === 'string' ? r.registrableDomain : null;
  } catch {
    return null;
  }
}

const LRI = '⁦';
const PDI = '⁩';
/** Wraps text in a left-to-right isolate so RTL characters cannot reorder the surrounding text. */
const isolate = (s) => `${LRI}${s}${PDI}`;

const SHOW_MAX = 300;
/** First SHOW_MAX code points + "… (N more characters)". */
function truncateForDisplay(s, max = SHOW_MAX) {
  const cps = Array.from(s);
  if (cps.length <= max) return s;
  return `${cps.slice(0, max).join('')}… (${cps.length - max} more characters)`;
}

// ---------------------------------------------------------------- local addresses
function parseIPv4(h) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return null;
  const b = m.slice(1).map(Number);
  return b.every((x) => x <= 255) ? b : null;
}

function ipv4Kind([a, b]) {
  if (a === 127) return 'loopback';
  if (a === 0) return 'unspecified';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade NAT (shared)';
  return null;
}

/** "[...]" (WHATWG-serialized) → 8 numbers, or null. */
function parseIPv6(h) {
  if (!h.startsWith('[') || !h.endsWith(']')) return null;
  let s = h.slice(1, -1).toLowerCase();
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s); // not produced by WHATWG, but be lenient
  if (v4) {
    const b = parseIPv4(v4[1]);
    if (!b) return null;
    s = `${s.slice(0, -v4[1].length)}${((b[0] << 8) | b[1]).toString(16)}:${((b[2] << 8) | b[3]).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const part = (x) => (x ? x.split(':') : []);
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

function ipv6Kind(g) {
  if (g.slice(0, 7).every((x) => x === 0)) return g[7] === 1 ? 'loopback' : g[7] === 0 ? 'unspecified' : null;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) { // IPv4-mapped
    return ipv4Kind([g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff]);
  }
  if ((g[0] & 0xfe00) === 0xfc00) return 'private (unique local)';
  if ((g[0] & 0xffc0) === 0xfe80) return 'link-local';
  return null;
}

/**
 * Classifies a WHATWG URL hostname that points at this Mac or the local network.
 * → 'loopback' | 'private' | 'link-local' | ... | null
 */
function localAddressKind(hostname) {
  if (typeof hostname !== 'string' || !hostname) return null;
  const h = hostname.toLowerCase().replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return 'loopback';
  if (h.endsWith('.local')) return 'local network (mDNS)';
  const v4 = parseIPv4(h);
  if (v4) return ipv4Kind(v4);
  const v6 = parseIPv6(h);
  if (v6) return ipv6Kind(v6);
  return null;
}

module.exports = { registrableDomain, isolate, truncateForDisplay, localAddressKind, loadPsl };

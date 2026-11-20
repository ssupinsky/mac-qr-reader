// URL analysis (PAYLOADS.md §2): WHATWG parsing plus raw-vs-parsed differential
// checks, host analysis (IP literals, IDN/punycode, mixed script, confusables,
// registrable domain via the PSL, brand lookalikes), query/tracking/nested-redirect
// analysis, scheme policy and special URL families (§2.8, §7.2, §11.1–11.3).
//
// Pure: no DOM, no network. `new URL()` is the browser's own parser, so what is shown
// is exactly what would be opened.

import { domainToUnicode } from './punycode.js';
import { lookup as pslLookup } from './psl.js';
import { trimWith, truncateDisplay } from './strings.js';
import {
  textSafety, scriptProfile, wholeScriptConfusable, skeleton,
} from './text-safety.js';

// ---------------------------------------------------------------------------
// Scheme tables (§2.2)
// ---------------------------------------------------------------------------

/** Schemes the main process may open (after its own confirm). */
export const OPENABLE_SCHEMES = new Set(['https', 'http', 'mailto', 'tel', 'sms', 'facetime', 'facetime-audio']);

const UNSAFE_SCHEMES = new Set([
  'javascript', 'vbscript', 'data', 'blob', 'file', 'filesystem', 'about', 'view-source', 'chrome',
  'chrome-extension', 'jar', 'ms-msdt', 'search-ms', 'ms-officecmd', 'intent',
]);
const LOCAL_APP_SCHEMES = new Set([
  'shortcuts', 'x-apple.systempreferences', 'applescript', 'x-man-page', 'smb', 'afp', 'nfs', 'vnc',
  'rdp', 'ssh', 'sftp', 'ftp', 'telnet',
]);
const APPSTORE_SCHEMES = new Set(['market', 'itms-apps', 'itms-appss', 'macappstore']);
const APP_LINK_SCHEMES = new Set([
  'tg', 'sgnl', 'whatsapp', 'signal', 'zoommtg', 'zoomus', 'msteams', 'spotify', 'steam', 'discord', 'slack',
]);
/** Schemes handled by their own (structured) parsers; listed so they still count as links. */
const OWN_PARSER_SCHEMES = new Set([
  'mailto', 'tel', 'sms', 'smsto', 'mms', 'mmsto', 'facetime', 'facetime-audio', 'geo', 'otpauth',
  'otpauth-migration', 'upi', 'bank', 'bitcoin', 'lightning', 'ethereum', 'litecoin', 'dogecoin', 'dash',
  'zcash', 'bitcoincash', 'monero', 'solana', 'ton', 'tron', 'xrpl', 'ripple', 'web+stellar',
  'web+cardano', 'algorand', 'cosmos', 'lnurlp', 'lnurlw',
]);
const SPECIAL_SCHEMES = new Set(['http', 'https', 'ws', 'wss', 'ftp', 'file']);

/** Every scheme that makes a `scheme:` prefix count as a link (§0.3 rule 21). */
export const KNOWN_SCHEMES = new Set([
  ...OPENABLE_SCHEMES, ...UNSAFE_SCHEMES, ...LOCAL_APP_SCHEMES, ...APPSTORE_SCHEMES, ...APP_LINK_SCHEMES,
  ...OWN_PARSER_SCHEMES, 'itms-services', 'magnet', 'ws', 'wss',
]);

const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.-]*):/;

// ---------------------------------------------------------------------------
// Heuristic data (§2.4, §2.6, §2.7)
// ---------------------------------------------------------------------------

const DOWNLOAD_EXTS = [
  'apk', 'aab', 'ipa', 'exe', 'msi', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'dmg', 'pkg', 'app',
  'command', 'iso', 'img', 'zip', 'rar', '7z', 'xpi', 'crx',
];
const PROFILE_EXTS = ['mobileconfig', 'mobileprovision'];

const TRACKING_PREFIXES = ['utm_', 'mtm_', 'pk_', 'piwik_', 'matomo_', 'hsa_', '_hs', '__hs', 'mc_', 'oly_', 'vero_', 'ga_'];
const TRACKING_EXACT = new Set([
  'fbclid', 'gclid', 'gclsrc', 'dclid', 'gbraid', 'wbraid', 'gad_source', 'gad_campaignid', 'msclkid',
  'yclid', 'ysclid', 'twclid', 'ttclid', 'li_fat_id', 'igshid', 'igsh', 'mkt_tok', '_openstat', 'srsltid',
  'wickedid', 'rb_clickid', 's_cid', 'ef_id', 'epik', 'sc_cid', '_branch_match_id', '_branch_referrer',
  '_kx', 'trk', 'trkcampaign', 'ncid', 'cmpid', 'spm', 'scm', '_ga', '_gl',
]);

const NESTED_PARAM_NAMES = new Set([
  'url', 'u', 'q', 'to', 'dest', 'destination', 'redirect', 'redirect_uri', 'redirect_url', 'redirectto',
  'return', 'returnto', 'return_url', 'returnurl', 'next', 'continue', 'goto', 'target', 'link', 'out',
  'r', 'rurl', 'service', 'callback', 'forward', 'fwd', 'page', 'view',
]);

const SHORTENERS = new Set(`bit.ly bitly.com j.mp bit.do tinyurl.com tiny.cc t.co goo.gl g.co ow.ly buff.ly is.gd v.gd
rebrand.ly rb.gy cutt.ly shorturl.at t.ly s.id tr.ee linktr.ee lnkd.in fb.me m.me
amzn.to amzn.eu a.co youtu.be wp.me ift.tt dlvr.it trib.al soo.gd x.co clck.ru
shorte.st adf.ly ouo.io bl.ink short.io sl.ink hyperurl.co aka.ms apple.co spoti.fi
msft.it flic.kr db.tt 1drv.ms forms.gle maps.app.goo.gl page.link app.link onelink.me
qrco.de q-r.to l.ead.me qr.codes qrfy.io me-qr.com scnv.io bitly.page`.split(/\s+/));
const FIRST_PARTY_SHORT = { 'youtu.be': 'YouTube', 'forms.gle': 'Google Forms', 'maps.app.goo.gl': 'Google Maps' };

/**
 * Brand → canonical registrable domains (§2.6). `*` = the brand label under any
 * public suffix (google.de, amazon.co.uk, …).
 */
const BRANDS = {
  apple: ['apple.com'], icloud: ['icloud.com'], google: ['*'], gmail: ['gmail.com'],
  youtube: ['youtube.com', 'youtu.be'], microsoft: ['microsoft.com'], outlook: ['outlook.com'],
  office: ['office.com'], live: ['live.com'], windows: ['windows.com'], amazon: ['*'],
  aws: ['amazon.com', 'amazonaws.com', 'aws.com'], paypal: ['*', 'paypal.me'], ebay: ['*'],
  facebook: ['facebook.com', 'fb.com', 'fb.me'], instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'wa.me'], meta: ['meta.com'], messenger: ['messenger.com', 'm.me'],
  netflix: ['netflix.com'], spotify: ['spotify.com'], linkedin: ['linkedin.com'],
  twitter: ['twitter.com', 'x.com', 't.co'], x: ['x.com'], tiktok: ['tiktok.com'],
  telegram: ['telegram.org', 'telegram.me', 't.me'], signal: ['signal.org', 'signal.me', 'signal.group'],
  dropbox: ['dropbox.com'], github: ['github.com'], gitlab: ['gitlab.com'], adobe: ['adobe.com'],
  docusign: ['docusign.com', 'docusign.net'], zoom: ['zoom.us', 'zoom.com'], slack: ['slack.com'],
  binance: ['binance.com'], coinbase: ['coinbase.com'], kraken: ['kraken.com'], metamask: ['metamask.io'],
  ledger: ['ledger.com'], revolut: ['revolut.com'], wise: ['wise.com'], n26: ['n26.com'], ing: ['*'],
  chase: ['chase.com'], wellsfargo: ['wellsfargo.com'], bankofamerica: ['bankofamerica.com'],
  citi: ['citi.com', 'citibank.com'], hsbc: ['*'], barclays: ['*'], santander: ['*'],
  deutschebank: ['deutsche-bank.de', 'db.com'], sparkasse: ['sparkasse.de'], dhl: ['*'],
  fedex: ['fedex.com'], ups: ['ups.com'], usps: ['usps.com'], royalmail: ['royalmail.com'],
  post: ['*'], booking: ['booking.com'], airbnb: ['*'], uber: ['uber.com'],
};
/**
 * Brand names that are also ordinary words: only the homograph rule (skeleton equal
 * after a substitution) applies to them, not the "contains the brand" rules.
 */
const GENERIC_BRANDS = new Set([
  'x', 'live', 'post', 'office', 'windows', 'meta', 'wise', 'ing', 'ups', 'zoom', 'chase', 'ledger',
  'booking', 'signal', 'messenger', 'citi', 'aws', 'n26',
]);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const asciiLower = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** decodeURIComponent that never throws; `ok:false` when malformed. */
function safeDecode(s, plusAsSpace = false) {
  const input = plusAsSpace ? s.replace(/\+/g, ' ') : s;
  try {
    return { value: decodeURIComponent(input), ok: true };
  } catch {
    return { value: input, ok: false };
  }
}

function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 1) return 2; // only distance ≤ 1 matters here
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** GTIN mod-10 check (weights 3,1 from the right, excluding the check digit). */
export function gtinValid(digits) {
  if (!/^\d{8,14}$/.test(digits)) return false;
  let sum = 0;
  const body = digits.slice(0, -1);
  for (let i = 0; i < body.length; i++) {
    sum += Number(body[body.length - 1 - i]) * (i % 2 === 0 ? 3 : 1);
  }
  return (10 - (sum % 10)) % 10 === Number(digits.at(-1));
}

function decodeBase64Text(s) {
  try {
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    const bin = atob(b);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

const LOOKS_LIKE_URL = /^(?:https?:)?\/\/|^[a-z][a-z0-9+.-]*:\/\//i;

/** Finds a URL hidden in a value: raw, up to 3 decoding rounds, or base64(url). */
function findNestedUrl(value) {
  let v = value;
  for (let round = 0; round < 4; round++) {
    if (LOOKS_LIKE_URL.test(v)) return v.startsWith('//') ? `https:${v}` : v;
    const d = safeDecode(v);
    if (!d.ok || d.value === v) break;
    v = d.value;
  }
  if (/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(value)) {
    const text = decodeBase64Text(value);
    if (text && LOOKS_LIKE_URL.test(text) && !/[\s\x00-\x1f]/.test(text)) return text;
  }
  return null;
}

const LEVEL_RANK = { info: 0, caution: 1, danger: 2 };

// ---------------------------------------------------------------------------
// Detection (§0.3 rules 19 and 21, §2.1 step 1)
// ---------------------------------------------------------------------------

/** WHATWG pre-processing: strip leading/trailing C0+space, remove TAB/LF/CR. */
const whatwgPreprocess = (s) => trimWith(s, (ch) => ch <= '\x20').replace(/[\t\n\r]/g, '');

function unescapeMecard(s) {
  return s.replace(/\\(.)/gs, '$1');
}

/**
 * Detects a link payload.
 * @param {string} text normalised payload (trimmed, BOM stripped)
 * @returns {null | { kind: 'url'|'www'|'mebkm'|'urlto', url: string, title?: string }}
 */
export function detectUrl(text) {
  if (typeof text !== 'string' || !text) return null;
  const head = text.slice(0, 6).toUpperCase();
  if (head === 'MEBKM:') {
    const fields = {};
    for (const tok of text.slice(6).split(/(?<!\\);/)) {
      const m = /^([A-Za-z]+):([\s\S]*)$/.exec(tok);
      if (m && !(m[1].toUpperCase() in fields)) fields[m[1].toUpperCase()] = unescapeMecard(m[2]);
    }
    if (fields.URL) return { kind: 'mebkm', url: fields.URL, title: fields.TITLE };
    return null;
  }
  if (text.slice(0, 6).toUpperCase() === 'URLTO:') {
    const rest = text.slice(6);
    const i = rest.indexOf(':');
    if (i >= 0 && (SCHEME_RE.test(rest.slice(i + 1)) || /^www\./i.test(rest.slice(i + 1)))) {
      return { kind: 'urlto', url: rest.slice(i + 1), title: rest.slice(0, i) };
    }
    if (SCHEME_RE.test(rest)) return { kind: 'urlto', url: rest, title: '' };
    return null;
  }
  for (const candidate of [text, whatwgPreprocess(text)]) {
    const m = SCHEME_RE.exec(candidate);
    if (m) {
      const scheme = asciiLower(m[1]);
      if (KNOWN_SCHEMES.has(scheme) || candidate.slice(m[0].length, m[0].length + 2) === '//') {
        return { kind: 'url', url: text };
      }
    }
  }
  if (/^www\.[^\s./]+\.[^\s]/i.test(text)) return { kind: 'www', url: text };
  return null;
}

// ---------------------------------------------------------------------------
// Raw authority extraction (§2.1 step 2)
// ---------------------------------------------------------------------------

/**
 * @returns {{ authority: string|null, userinfo: string|null, host: string|null, port: string|null,
 *   slashes: string, naiveHost: string|null }}
 */
function rawAuthority(text, scheme) {
  const out = { authority: null, userinfo: null, host: null, port: null, slashes: '', naiveHost: null };
  const m = SCHEME_RE.exec(text);
  if (!m) return out;
  const rest = text.slice(m[0].length);
  const special = SPECIAL_SCHEMES.has(scheme);
  const slashMatch = (special ? /^[/\\]*/ : /^\/\//).exec(rest);
  if (!slashMatch || (!special && !slashMatch[0])) return out;
  out.slashes = slashMatch[0];
  if (special && scheme === 'file') return out;
  const after = rest.slice(slashMatch[0].length);
  const end = after.search(special ? /[/?#\\]/ : /[/?#]/);
  const authority = end < 0 ? after : after.slice(0, end);
  out.authority = authority;
  const split = (auth) => {
    const at = auth.lastIndexOf('@');
    const userinfo = at >= 0 ? auth.slice(0, at) : null;
    const hostport = at >= 0 ? auth.slice(at + 1) : auth;
    let host = hostport;
    let port = null;
    const v6 = /^(\[[^\]]*\])(?::(.*))?$/.exec(hostport);
    if (v6) {
      host = v6[1];
      port = v6[2] ?? null;
    } else {
      const c = hostport.lastIndexOf(':');
      if (c >= 0) {
        host = hostport.slice(0, c);
        port = hostport.slice(c + 1);
      }
    }
    return { userinfo, host, port };
  };
  Object.assign(out, split(authority));
  // How a naive parser (no backslash handling) would read the authority.
  const naiveEnd = after.search(/[/?#]/);
  out.naiveHost = split(naiveEnd < 0 ? after : after.slice(0, naiveEnd)).host;
  return out;
}

/** IDNA-maps a raw host the way the URL parser would (special schemes only). */
function canonicalHost(rawHost, protocol) {
  if (rawHost === '') return '';
  try {
    return new URL(`${protocol}//${rawHost}/`).hostname;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// IP addresses (§2.3)
// ---------------------------------------------------------------------------

function ipv4Local(ip) {
  const [a, b] = ip.split('.').map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

/** Expands a (bracketless) IPv6 literal to 8 16-bit groups, or null. */
function ipv6Groups(ip) {
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const parse = (s) => (s ? s.split(':').map((h) => parseInt(h, 16)) : []);
  const head = parse(parts[0]);
  const tail = parts.length === 2 ? parse(parts[1]) : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (parts.length === 1 && fill !== 0)) return null;
  const groups = [...head, ...Array(fill).fill(0), ...tail];
  return groups.some((g) => Number.isNaN(g)) ? null : groups;
}

function analyzeIpv6(hostname) {
  const groups = ipv6Groups(hostname.slice(1, -1));
  const info = { local: false, mappedIpv4: null };
  if (!groups) return info;
  const zeroPrefix = groups.slice(0, 5).every((g) => g === 0);
  if (zeroPrefix && groups[5] === 0xffff) {
    info.mappedIpv4 = `${groups[6] >> 8}.${groups[6] & 255}.${groups[7] >> 8}.${groups[7] & 255}`;
    info.local = ipv4Local(info.mappedIpv4);
  }
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] <= 1) info.local = true; // :: and ::1
  if ((groups[0] & 0xfe00) === 0xfc00 || (groups[0] & 0xffc0) === 0xfe80) info.local = true;
  return info;
}

// ---------------------------------------------------------------------------
// Host analysis (§2.3, §2.5, §2.6) — reusable for e-mail domains etc.
// ---------------------------------------------------------------------------

/**
 * Analyses a domain name: IDN decoding, mixed script, whole-script confusables,
 * registrable domain, subdomain depth and brand lookalikes.
 *
 * @param {string} hostname ACE hostname as produced by WHATWG (`url.hostname`), or any
 *   domain (Unicode allowed; it is converted with the URL parser).
 * @param {{ level?: 'caution'|'danger' }} [opts] level used for mixed-script/confusable
 *   findings (default danger — hosts; use caution for names).
 * @returns {{ host: string, hostUnicode: string, registrableDomain: string|null,
 *   registrableDomainUnicode: string|null, publicSuffix: string|null, subdomain: string,
 *   subdomainUnicode: string, isPublicSuffix: boolean, idn: boolean, brand: string|null,
 *   warnings: Array<{level, message}> }}
 */
export function analyzeDomain(hostname, opts = {}) {
  const level = opts.level || 'danger';
  const warnings = [];
  const w = (lvl, message) => warnings.push({ level: lvl, message });
  let host = String(hostname);
  if (/[^\x00-\x7f]/.test(host) || /[A-Z]/.test(host)) {
    host = canonicalHost(host, 'https:') ?? asciiLower(host);
  }

  const { unicode: hostUnicode, errors } = domainToUnicode(host);
  for (const label of errors) w('danger', `Invalid punycode label "${label}"`);

  const labels = hostUnicode.replace(/\.$/, '').split('.');
  const tld = labels.at(-1) || '';
  const tldAscii = /^[\x00-\x7f]+$/.test(tld) && !/^xn--/i.test(tld);
  let idn = false;
  for (const label of labels) {
    if (!/[^\x00-\x7f]/.test(label)) continue;
    idn = true;
    const profile = scriptProfile(label);
    if (profile.mixed) {
      w(level, `Domain mixes ${profile.scripts.join(' and ').replace(/_/g, ' ')} letters ("${label}")`);
      continue;
    }
    const lookalike = wholeScriptConfusable(label);
    if (lookalike && tldAscii && /[a-z]/.test(lookalike)) {
      w(level, `Domain label "${label}" is written in ${profile.scripts[0]} letters but looks like the Latin word "${lookalike}"`);
    }
  }
  if (idn) w('info', 'Internationalised domain name — check the Unicode and ACE forms');
  const safety = textSafety(hostUnicode, { context: 'url' });
  if (safety.findings.length) w('danger', 'Domain contains invisible or control characters');
  if (host.endsWith('.')) w('info', 'Trailing dot in domain');

  const psl = pslLookup(host);
  const toUni = (s) => (s ? domainToUnicode(s).unicode : s);
  const result = {
    host, hostUnicode, idn,
    registrableDomain: psl.registrableDomain, registrableDomainUnicode: toUni(psl.registrableDomain),
    publicSuffix: psl.publicSuffix, subdomain: psl.subdomain, subdomainUnicode: toUni(psl.subdomain),
    isPublicSuffix: psl.isPublicSuffix, approximate: psl.approximate, brand: null, warnings,
  };
  if (psl.approximate) w('info', 'Registrable domain is approximate (suffix list unavailable)');
  if (psl.isPublicSuffix && labels.length > 1) w('caution', `Host "${hostUnicode}" is a public suffix, not a single site`);

  const subLabels = psl.subdomain ? psl.subdomain.split('.') : [];
  if (subLabels.length >= 4) w('caution', `Unusually many subdomains (${subLabels.length}) before ${result.registrableDomainUnicode}`);
  if (host.length > 80) w('caution', `Very long host name (${host.length} characters)`);
  if (host.split('.').some((l) => l.length > 40)) w('caution', 'Host contains a very long label');

  if (psl.registrableDomain) brandChecks(result, w);
  return result;
}

/** §2.6 lookalike-of-popular-brands heuristic. */
function brandChecks(result, w) {
  const regUni = result.registrableDomainUnicode;
  const suffixUni = domainToUnicode(result.publicSuffix.replace(/\.$/, '')).unicode;
  const reg = result.registrableDomain.replace(/\.$/, '');
  const L = regUni.replace(/\.$/, '').slice(0, -(suffixUni.length + 1));
  if (!L) return;
  const S = skeleton(L, { brand: true });
  const isOfficial = (brand, label) =>
    BRANDS[brand].includes(reg) || (BRANDS[brand].includes('*') && label === brand);
  // Official domain of any brand → nothing to say about lookalikes of the registrable part.
  const officialOf = Object.keys(BRANDS).find((b) => isOfficial(b, L));
  if (officialOf) {
    result.brand = officialOf;
  } else {
    let flagged = false;
    for (const brand of Object.keys(BRANDS)) {
      if (S === brand) {
        if (L !== brand) {
          w('danger', `"${regUni}" imitates ${brand} (look-alike characters)`);
          flagged = true;
        } else if (!GENERIC_BRANDS.has(brand)) {
          w('caution', `Uses the brand name ${brand} but is not one of ${brand}'s usual domains (${BRANDS[brand].filter((d) => d !== '*').join(', ') || brand + '.*'})`);
          flagged = true;
        }
        break;
      }
    }
    if (!flagged) {
      for (const brand of Object.keys(BRANDS)) {
        if (GENERIC_BRANDS.has(brand)) continue;
        if (brand.length >= 5 && levenshtein(S, brand) === 1) {
          w('caution', `"${regUni}" is similar to ${brand}`);
          break;
        }
        const tokens = S.split('-');
        if (tokens.length > 1 && tokens.some((t) => t.startsWith(brand))) {
          w('caution', `"${regUni}" uses the brand name ${brand} but is not ${brand}'s domain`);
          break;
        }
      }
    }
  }
  // Brand as a whole label in the subdomain: paypal.com.example.net, apple.id.example.
  if (result.subdomainUnicode) {
    const subs = result.subdomainUnicode.split('.').map((l) => skeleton(l, { brand: true }));
    for (const brand of Object.keys(BRANDS)) {
      if (GENERIC_BRANDS.has(brand) || brand === result.brand) continue;
      if (subs.includes(brand)) {
        w('danger', `"${brand}" appears in the subdomain, but the site is ${regUni}`);
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Query parsing & tracking (§2.4)
// ---------------------------------------------------------------------------

function isTrackingParam(name, ctx) {
  const n = name.toLowerCase();
  if (TRACKING_EXACT.has(n) || TRACKING_PREFIXES.some((p) => n.startsWith(p))) return true;
  const { host, label } = ctx;
  if (n === 'si' && (host === 'open.spotify.com' || host === 'youtu.be' || ctx.reg === 'youtube.com')) return true;
  if (n === 'feature' && (host === 'youtu.be' || ctx.reg === 'youtube.com')) return true;
  if ((n === 'ref_src' || n === 'ref_url') && (ctx.reg === 'twitter.com' || ctx.reg === 'x.com')) return true;
  if (n === 'smid' && ctx.reg === 'nytimes.com') return true;
  if (label === 'amazon' && (['tag', 'ascsubtag', 'ref', 'ref_', 'psc'].includes(n) ||
      n.startsWith('pd_rd_') || n.startsWith('pf_rd_'))) return true;
  return false;
}

function parseQuery(search, { formEncoding }) {
  if (!search || search === '?') return [];
  return search.slice(1).split('&').filter((p) => p !== '').map((pair) => {
    const eq = pair.indexOf('=');
    const name = eq < 0 ? pair : pair.slice(0, eq);
    const value = eq < 0 ? '' : pair.slice(eq + 1);
    const dn = safeDecode(name, formEncoding);
    const dv = safeDecode(value, formEncoding);
    return { raw: pair, name, value, decodedName: dn.value, decoded: dv.value, malformed: !dn.ok || !dv.ok, tracking: false };
  });
}

// ---------------------------------------------------------------------------
// Special URL families (§2.8, §7.2, §11.1–11.3)
// ---------------------------------------------------------------------------

const COORD_PAIR = /^\s*(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$/;

function coords(lat, lon) {
  const la = Number(lat);
  const lo = Number(lon);
  if (!Number.isFinite(la) || !Number.isFinite(lo) || Math.abs(la) > 90 || Math.abs(lo) > 180) return null;
  return { lat: la, lon: lo };
}

function pairFrom(s) {
  const m = COORD_PAIR.exec(s || '');
  return m ? coords(m[1], m[2]) : null;
}

/** Map URLs (§7.2) → { service, geo|null, label?, shortened? } or null. */
function detectMap(u, q, label) {
  const host = u.hostname;
  const get = (n) => q.find((p) => p.decodedName === n)?.decoded;
  const path = safeDecode(u.pathname).value;
  if (host === 'maps.app.goo.gl' || (host === 'goo.gl' && path.startsWith('/maps'))) {
    return { service: 'Google Maps', geo: null, shortened: true };
  }
  if (label === 'google' && (path.startsWith('/maps') || host.startsWith('maps.'))) {
    let geo = null;
    const pin = /!3d(-?\d+(?:\.\d+)?)!4d(-?\d+(?:\.\d+)?)/.exec(u.href);
    if (pin) geo = coords(pin[1], pin[2]);
    if (!geo) {
      const at = /\/@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)(?:,([\d.]+)z)?/.exec(path);
      if (at) geo = coords(at[1], at[2]);
    }
    if (!geo) geo = pairFrom(get('query')) || pairFrom(get('destination')) || pairFrom(get('q')) || pairFrom(get('ll'));
    const place = /\/maps\/place\/([^/]+)/.exec(path);
    const lbl = place ? place[1].replace(/\+/g, ' ') : (!geo ? get('q') || get('query') : undefined);
    return { service: 'Google Maps', geo, label: lbl };
  }
  if (host === 'maps.apple.com' || host === 'maps.apple') {
    const geo = pairFrom(get('ll')) || pairFrom(get('coordinate')) || pairFrom(get('sll'));
    return { service: 'Apple Maps', geo, label: get('q') || get('name') || get('address') || get('daddr') };
  }
  if (label === 'openstreetmap') {
    let geo = coords(get('mlat'), get('mlon'));
    if (!get('mlat')) geo = null;
    const hash = /map=\d+(?:\.\d+)?\/(-?\d+(?:\.\d+)?)\/(-?\d+(?:\.\d+)?)/.exec(u.hash);
    if (!geo && hash) geo = coords(hash[1], hash[2]);
    return { service: 'OpenStreetMap', geo };
  }
  if (label === 'waze' && path.startsWith('/ul')) {
    return { service: 'Waze', geo: pairFrom(get('ll')), label: get('q') };
  }
  return null;
}

function detectSpecial(u, scheme, q, dom, w) {
  const host = u.hostname;
  const reg = dom?.registrableDomain?.replace(/\.$/, '') || '';
  const label = reg.split('.')[0] || '';
  const path = safeDecode(u.pathname).value;
  const get = (n) => q.find((p) => p.decodedName.toLowerCase() === n)?.decoded;

  // Signal — device linking is the dangerous one (§2.8, [S33]).
  if (scheme === 'sgnl' || scheme === 'signal' || reg === 'signal.me' || reg === 'signal.group') {
    if (host === 'linkdevice' || /linkdevice/i.test(u.href)) {
      w('danger', 'Links a new device to YOUR Signal account — attackers use this to read your messages.');
      return { kind: 'messenger', service: 'Signal', action: 'link-device', summary: 'Signal: link a new device to your account' };
    }
    if (reg === 'signal.group' || host === 'signal.group') return { kind: 'messenger', service: 'Signal', action: 'group-invite', summary: 'Signal group invite' };
    const p = /^#p\/(.+)$/.exec(u.hash);
    if (p) return { kind: 'messenger', service: 'Signal', action: 'chat', phone: safeDecode(p[1]).value, summary: `Signal chat with ${safeDecode(p[1]).value}` };
    if (/^#eu\//.test(u.hash)) return { kind: 'messenger', service: 'Signal', action: 'username', summary: 'Signal username link' };
    return { kind: 'messenger', service: 'Signal', summary: 'Signal link' };
  }

  // WhatsApp
  if (host === 'wa.me' || reg === 'whatsapp.com' || scheme === 'whatsapp') {
    const text = get('text');
    if (host === 'chat.whatsapp.com') return { kind: 'messenger', service: 'WhatsApp', action: 'group-invite', summary: 'WhatsApp group invite', text };
    const phone = host === 'wa.me' ? path.slice(1).split('/')[0] : get('phone');
    if (phone && /^\+?\d{5,15}$/.test(phone)) {
      const digits = phone.replace(/^\+/, '');
      return { kind: 'messenger', service: 'WhatsApp', action: 'chat', phone: `+${digits}`, text, summary: `WhatsApp chat with +${digits}` };
    }
    return { kind: 'messenger', service: 'WhatsApp', text, summary: 'WhatsApp link' };
  }

  // Telegram
  if (host === 't.me' || host === 'telegram.me' || host === 'telegram.dog' || scheme === 'tg') {
    const seg = path.slice(1).split('/');
    if ((scheme === 'tg' && (host === 'proxy' || host === 'socks')) || seg[0] === 'proxy' || seg[0] === 'socks') {
      w('caution', `Configures a Telegram proxy${get('server') ? ` (${get('server')})` : ''} — all your Telegram traffic would go through it`);
      return { kind: 'messenger', service: 'Telegram', action: 'proxy', server: get('server'), summary: 'Telegram proxy settings' };
    }
    if (scheme === 'tg' && host === 'join') return { kind: 'messenger', service: 'Telegram', action: 'group-invite', summary: 'Telegram group invite' };
    if (seg[0].startsWith('+') || seg[0] === 'joinchat') return { kind: 'messenger', service: 'Telegram', action: 'group-invite', summary: 'Telegram group invite' };
    const user = scheme === 'tg' ? get('domain') : seg[0];
    const start = get('start');
    if (user) {
      return {
        kind: 'messenger', service: 'Telegram', action: start !== undefined ? 'bot' : 'chat', user, start,
        summary: start !== undefined ? `Telegram: bot @${user} with start parameter "${start}"` : `Telegram: @${user}`,
      };
    }
    return { kind: 'messenger', service: 'Telegram', summary: 'Telegram link' };
  }

  // App stores
  if ((reg === 'apple.com' && (host === 'apps.apple.com' || host === 'itunes.apple.com')) || scheme === 'itms-apps' || scheme === 'itms-appss' || scheme === 'macappstore') {
    const m = /\/app\/(?:([^/]+)\/)?id(\d+)/.exec(path) || /\/id(\d+)/.exec(path);
    if (m) {
      const slug = m.length === 3 ? m[1] : undefined;
      const id = m.length === 3 ? m[2] : m[1];
      return { kind: 'appstore', store: 'App Store', slug, appId: id, summary: `App Store: ${slug ? `${slug} ` : ''}(id ${id})` };
    }
    if (scheme !== 'https' && scheme !== 'http') return { kind: 'appstore', store: 'App Store', summary: 'App Store link' };
  }
  if ((host === 'play.google.com' && path.startsWith('/store/apps')) || scheme === 'market') {
    const id = get('id');
    return { kind: 'appstore', store: 'Google Play', packageName: id, summary: id ? `Google Play: ${id}` : 'Google Play link' };
  }

  // Meetings
  if (reg === 'zoom.us' || reg === 'zoom.com' || scheme === 'zoommtg' || scheme === 'zoomus') {
    const m = /\/(?:j|wc\/join|s)\/(\d{9,11})/.exec(path);
    const id = m ? m[1] : get('confno');
    const pretty = id ? id.replace(/^(\d{3})(\d{3,4})(\d{4})$/, '$1 $2 $3') : null;
    const pwd = q.find((p) => p.decodedName === 'pwd');
    if (pwd) pwd.sensitive = true;
    return { kind: 'meeting', service: 'Zoom', meetingId: id, hasPassword: !!pwd, summary: pretty ? `Zoom meeting ${pretty}` : 'Zoom link' };
  }
  if (host === 'meet.google.com') {
    const code = /^\/([a-z]{3}-[a-z]{4}-[a-z]{3})/.exec(path)?.[1];
    return { kind: 'meeting', service: 'Google Meet', meetingCode: code, summary: code ? `Google Meet ${code}` : 'Google Meet link' };
  }
  if ((host === 'teams.microsoft.com' && path.startsWith('/l/meetup-join')) || (host === 'teams.live.com' && path.startsWith('/meet')) || scheme === 'msteams') {
    return { kind: 'meeting', service: 'Microsoft Teams', summary: 'Microsoft Teams meeting' };
  }
  if (reg === 'webex.com' && (path.startsWith('/meet') || path.includes('j.php') || path.startsWith('/join'))) {
    return { kind: 'meeting', service: 'Webex', summary: 'Webex meeting' };
  }

  // Maps
  const map = detectMap(u, q, label);
  if (map) {
    const summary = map.geo
      ? `Map: ${map.geo.lat.toFixed(6)}, ${map.geo.lon.toFixed(6)} (${map.service})`
      : map.shortened ? `Short link to ${map.service} (location unknown until opened)`
        : `Map link (${map.service})${map.label ? `: ${map.label}` : ''}`;
    return { kind: 'map', ...map, summary };
  }

  // GS1 Digital Link (/01/<gtin>[/10/<batch>][/21/<serial>] ?17=YYMMDD)
  const gs1 = /\/(?:01|gtin)\/(\d{8,14})((?:\/[^/]+\/[^/]+)*)/.exec(path);
  if (gs1 && (scheme === 'https' || scheme === 'http')) {
    const gtin = gs1[1].padStart(14, '0');
    const ais = Object.create(null);
    const segs = gs1[2].split('/').filter(Boolean);
    for (let i = 0; i + 1 < segs.length; i += 2) ais[segs[i]] = segs[i + 1];
    for (const p of q) if (/^\d{2,4}$/.test(p.decodedName)) ais[p.decodedName] ??= p.decoded;
    const valid = gtinValid(gtin);
    if (!valid) w('caution', `GTIN ${gtin} has an invalid check digit`);
    let expiry;
    if (/^\d{6}$/.test(ais['17'] || '')) {
      const [yy, mm, dd] = [ais['17'].slice(0, 2), ais['17'].slice(2, 4), ais['17'].slice(4, 6)];
      const year = 2000 + Number(yy);
      const day = dd === '00' ? new Date(Date.UTC(year, Number(mm), 0)).getUTCDate() : Number(dd);
      expiry = `${year}-${mm}-${String(day).padStart(2, '0')}`;
    }
    const parts = [`Product GTIN ${gtin}`];
    if (ais['10']) parts.push(`batch ${ais['10']}`);
    if (ais['21']) parts.push(`serial ${ais['21']}`);
    if (expiry) parts.push(`expiry ${expiry}`);
    return { kind: 'gs1', gtin, gtinValid: valid, batch: ais['10'], serial: ais['21'], expiry, summary: parts.join(', ') };
  }
  return null;
}

/** Known redirectors (§2.4): returns { service, target } or null. */
function detectRedirector(u, q, dom) {
  const host = u.hostname;
  const reg = dom?.registrableDomain || '';
  const label = reg.split('.')[0];
  const get = (...names) => {
    for (const n of names) {
      const p = q.find((x) => x.decodedName === n);
      if (p) return p.decoded;
    }
    return undefined;
  };
  const path = u.pathname;
  let service = null;
  let target;
  if (label === 'google' && path === '/url') { service = 'Google'; target = get('q', 'url'); }
  else if ((host === 'l.facebook.com' || host === 'lm.facebook.com') && path === '/l.php') { service = 'Facebook'; target = get('u'); }
  else if (host === 'l.instagram.com') { service = 'Instagram'; target = get('u'); }
  else if (reg === 'youtube.com' && path === '/redirect') { service = 'YouTube'; target = get('q'); }
  else if (reg === 'linkedin.com' && path.startsWith('/redir/redirect')) { service = 'LinkedIn'; target = get('url'); }
  else if (host === 't.umblr.com') { service = 'Tumblr'; target = get('z'); }
  else if (host === 'slack-redir.net') { service = 'Slack'; target = get('url'); }
  else if (host.endsWith('.safelinks.protection.outlook.com')) { service = 'Microsoft Safe Links'; target = get('url'); }
  else if (reg === 'urldefense.com') {
    service = 'Proofpoint URL Defense';
    const m = /\/v3\/__(.+?)__/.exec(u.href);
    if (m) target = m[1];
  } else if (host === 'href.li') { service = 'href.li'; target = safeDecode(u.search.slice(1)).value; }
  else if (host === 'away.vk.com') { service = 'VK'; target = get('to'); }
  else if (reg === 'steamcommunity.com' && path.startsWith('/linkfilter')) { service = 'Steam'; target = get('url', 'u'); }
  else if (host === 'exit.sc') { service = 'SoundCloud'; target = get('url'); }
  if (!service) return null;
  return { service, target: target && LOOKS_LIKE_URL.test(target) ? target : target ? findNestedUrl(target) : null };
}

// ---------------------------------------------------------------------------
// Scheme-specific extras
// ---------------------------------------------------------------------------

function parseDataUrl(text) {
  const body = text.slice(text.indexOf(':') + 1);
  const comma = body.indexOf(',');
  const meta = comma < 0 ? body : body.slice(0, comma);
  const payload = comma < 0 ? '' : body.slice(comma + 1);
  const base64 = /;base64$/i.test(meta.trim());
  const mediaType = (base64 ? meta.trim().slice(0, -7) : meta.trim()).split(';')[0] || 'text/plain';
  let size = null;
  let preview = null;
  if (base64) {
    const clean = payload.replace(/\s/g, '');
    try {
      const bin = atob(safeDecode(clean).value);
      size = bin.length;
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      // stream: an incomplete UTF-8 sequence at the 4 KB cut is held back, not an error.
      const more = bytes.length > 4096;
      try {
        preview = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, 4096), { stream: more });
        if (more) preview += '…';
      } catch { preview = null; }
    } catch {
      size = null;
    }
  } else {
    const decoded = safeDecode(payload).value;
    preview = truncateDisplay(decoded, 4096, { units: 'utf16' });
    size = new TextEncoder().encode(decoded).length;
  }
  return { mediaType, base64, size, preview };
}

function parseMagnet(u, q) {
  const xt = q.filter((p) => /^xt(\.\d+)?$/.test(p.decodedName)).map((p) => p.decoded);
  let infoHash = null;
  for (const v of xt) {
    const m = /^urn:bt(?:ih|mh):(.+)$/i.exec(v);
    if (m) { infoHash = m[1]; break; }
  }
  const trackers = q.filter((p) => /^tr(\.\d+)?$/.test(p.decodedName)).map((p) => safeDecode(p.value).value);
  const name = q.find((p) => p.decodedName === 'dn');
  const size = q.find((p) => p.decodedName === 'xl')?.decoded;
  return {
    infoHash, name: name ? safeDecode(name.value).value : undefined, trackers,
    size: size && /^\d+$/.test(size) ? Number(size) : undefined,
    webSeeds: q.filter((p) => /^ws(\.\d+)?$/.test(p.decodedName)).map((p) => safeDecode(p.value).value),
  };
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

/**
 * Analyses a link.
 * @param {string} input payload (normalised: trimmed, BOM stripped). Wrappers
 *   (`MEBKM:`, `URLTO:`, bare `www.`) are recognised.
 * @param {{ depth?: number }} [opts] recursion depth for nested URLs (max 2).
 * @returns {object} Analysis without `raw`.
 */
export function analyzeUrl(input, opts = {}) {
  const depth = opts.depth ?? 0;
  const warnings = [];
  const w = (level, message) => warnings.push({ level, message });
  const fields = [];
  const actions = [];

  const detected = detectUrl(String(input)) || { kind: 'url', url: String(input) };
  let text = detected.url;
  const wrapper = detected.kind === 'mebkm' || detected.kind === 'urlto' ? detected.kind : null;
  if (wrapper) {
    if (detected.title) fields.push({ label: 'Title', value: detected.title });
    text = text.trim();
  }
  const assumedScheme = detected.kind === 'www' || (wrapper && /^www\./i.test(text));
  if (assumedScheme) {
    text = `https://${text}`;
    w('info', 'No scheme; treated as https');
  }

  const rawScheme = SCHEME_RE.exec(text)?.[1];
  const pre = whatwgPreprocess(text);
  const preScheme = SCHEME_RE.exec(pre)?.[1];
  const scheme = asciiLower(preScheme || rawScheme || '');
  let differential = false;
  const reasons = [];

  if (rawScheme === undefined && preScheme) {
    w('danger', `The link type is disguised with hidden characters; it is really a "${scheme}:" link`);
    differential = true;
  }

  // ---- WHATWG parse
  let u = null;
  try {
    u = new URL(text);
  } catch {
    u = null;
  }
  const base = {
    format: 'url', wrapper, title: wrapper ? detected.title ?? null : null, assumedScheme,
    href: u ? u.href : text, scheme, username: '', password: '', host: '', hostUnicode: '',
    hostKind: null, registrableDomain: null, registrableDomainUnicode: null, publicSuffix: null,
    subdomain: '', subdomainUnicode: '', port: '', path: '', pathDecoded: '', query: [], fragment: '',
    fragmentDecoded: '', cleanHref: u ? u.href : text, nested: [], special: null, rawHost: null,
    differential: false, openable: false, notOpenableReason: null,
  };

  if (!u) {
    w('danger', 'Malformed link — it cannot be parsed reliably');
    const data = { ...base, notOpenableReason: 'The link is malformed' };
    fields.unshift({ label: 'Link', value: text, mono: true, copy: true });
    actions.push({ kind: 'copy', label: 'Copy link', value: text });
    return finish({ type: 'url', title: 'Link', summary: `Malformed ${scheme || 'link'}`, fields, warnings, actions, data });
  }

  const special = SPECIAL_SCHEMES.has(scheme);
  const ra = rawAuthority(text, scheme);
  const data = { ...base, rawHost: ra.host };
  data.username = u.username ? safeDecode(u.username).value : '';
  data.password = u.password ? '••••••••' : '';
  data.host = u.hostname;
  data.port = u.port;
  data.path = u.pathname;
  data.pathDecoded = safeDecode(u.pathname).value;
  data.fragment = u.hash ? u.hash.slice(1) : '';
  data.fragmentDecoded = safeDecode(data.fragment).value;

  // ---- Parser-differential checks (§2.1 step 4)
  if (/[\t\n\r]/.test(text)) {
    w('danger', 'Link contains line breaks or tabs; browsers silently remove them, so it may go somewhere other than it appears');
    differential = true;
  }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f ]/.test(text)) {
    w('danger', 'Link contains spaces or control characters; apps disagree on where such a link ends');
    differential = true;
  }
  const beforeQuery = text.split(/[?#]/)[0];
  if (special && beforeQuery.includes('\\')) {
    const alt = ra.naiveHost && asciiLower(ra.naiveHost) !== u.hostname ? `; other apps may read the host as "${ra.naiveHost}"` : '';
    w('danger', `Link contains a backslash — browsers treat it as "/", so this opens "${u.hostname}"${alt}`);
    differential = true;
  } else if (special && scheme !== 'file' && ra.slashes !== '//') {
    w('caution', `Unusual slashes after "${scheme}:"`);
  }
  if (ra.host !== null) {
    if (ra.host.includes('%')) {
      w('danger', `Host is percent-encoded ("${ra.host}"), which hides the real destination "${u.hostname}"`);
      differential = true;
    }
    const hostSafety = textSafety(ra.host, { context: 'url' });
    if (hostSafety.findings.length) {
      w('danger', `Host contains invisible characters (${hostSafety.escaped}); it actually opens "${u.hostname}"`);
      differential = true;
    }
    if (special) {
      const canon = canonicalHost(ra.host, u.protocol);
      if (canon === null || canon !== u.hostname) {
        w('danger', `The host appears as "${ra.host}" but the link opens "${u.hostname}"`);
        differential = true;
      } else if (ra.host.normalize('NFKC') !== ra.host) {
        w('caution', `Host is written with unusual (full-width or compatibility) characters: "${ra.host}"`);
      }
    } else if (asciiLower(ra.host) !== asciiLower(safeDecode(u.hostname).value) && ra.host !== u.hostname) {
      w('danger', `The host appears as "${ra.host}" but the link opens "${u.hostname}"`);
      differential = true;
    }
  }
  data.differential = differential;
  if (differential) reasons.push('the link is ambiguous (different apps would open different places)');

  // ---- Host
  let dom = null;
  const h = u.hostname;
  if (h) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
      data.hostKind = 'ipv4';
      data.hostUnicode = h;
      w('caution', 'Link points to a raw IP address, not a domain name');
      if (special && ra.host !== null && asciiLower(ra.host) !== h) {
        w('danger', `Obfuscated IP address: written as "${ra.host}", which is ${h}`);
        data.rawIp = ra.host;
      }
      if (ipv4Local(h)) w('info', `Local network address (${h})`);
    } else if (h.startsWith('[')) {
      data.hostKind = 'ipv6';
      data.hostUnicode = h;
      w('caution', 'Link points to a raw IP address, not a domain name');
      const v6 = analyzeIpv6(h);
      if (v6.mappedIpv4) {
        data.ipv4Mapped = v6.mappedIpv4;
        w('info', `IPv4-mapped address: ${v6.mappedIpv4}`);
      }
      if (v6.local) w('info', `Local network address (${v6.mappedIpv4 || h})`);
    } else {
      data.hostKind = special ? 'domain' : 'opaque';
      const domainLike = special || /^[A-Za-z0-9.-]+$/.test(h);
      if (domainLike) {
        dom = analyzeDomain(special ? h : asciiLower(h));
        warnings.push(...dom.warnings);
        data.hostUnicode = dom.hostUnicode;
        data.registrableDomain = dom.registrableDomain;
        data.registrableDomainUnicode = dom.registrableDomainUnicode;
        data.publicSuffix = dom.publicSuffix;
        data.subdomain = dom.subdomain;
        data.subdomainUnicode = dom.subdomainUnicode;
        data.brand = dom.brand;
      } else {
        data.hostUnicode = safeDecode(h).value;
      }
      const lh = asciiLower(h).replace(/\.$/, '');
      if (special && (lh === 'localhost' || /\.(local|internal|lan|home\.arpa|localhost)$/.test(lh))) {
        w('info', `Local network host (${lh})`);
      }
    }
  }

  if (u.username || u.password || (ra.userinfo !== null && ra.authority !== null)) {
    w('danger', `Text before "@" is not the website. This link goes to ${data.hostUnicode || u.hostname}`);
  }
  if (u.port) w('caution', `Non-standard port ${u.port}`);

  // ---- Scheme policy (§2.2)
  let title = 'Link';
  let unsafe = false;
  if (scheme === 'https') title = 'Website link';
  else if (scheme === 'http') {
    title = 'Website link';
    w('caution', 'Not encrypted (http)');
  } else if (UNSAFE_SCHEMES.has(scheme)) {
    unsafe = true;
    title = 'Unsafe link';
    w('danger', 'This link type can run code or access local files');
    reasons.push(`"${scheme}:" links can run code or access local files`);
  } else if (scheme === 'itms-services') {
    unsafe = true;
    title = 'App install link';
    w('danger', 'Installs an app outside the App Store');
    reasons.push('it installs an app outside the App Store');
    const manifest = parseQuery(u.search, { formEncoding: false }).find((p) => p.decodedName === 'url');
    if (manifest) data.manifestUrl = manifest.decoded;
  } else if (LOCAL_APP_SCHEMES.has(scheme)) {
    title = 'App link';
    const share = scheme === 'smb' || scheme === 'afp' || scheme === 'nfs';
    w('caution', share ? 'Opens a network share; Finder may send your credentials to it'
      : scheme === 'shortcuts' ? 'Opens Shortcuts and can run an automation' : 'Opens a local app or network service');
    reasons.push('it opens a local app or network service');
  } else if (APPSTORE_SCHEMES.has(scheme) || APP_LINK_SCHEMES.has(scheme)) {
    title = 'App link';
    reasons.push(`"${scheme}:" links are copy-only`);
  } else if (scheme === 'ws' || scheme === 'wss') {
    title = 'WebSocket address';
    w('info', 'WebSocket address — not a web page');
    reasons.push('WebSocket addresses are not web pages');
  } else if (scheme === 'magnet') {
    title = 'BitTorrent magnet link';
    w('info', 'Opening starts a peer-to-peer download; your IP is visible to peers');
    reasons.push('magnet links are copy-only');
  } else if (!OPENABLE_SCHEMES.has(scheme)) {
    title = 'Link';
    if (!OWN_PARSER_SCHEMES.has(scheme)) w('info', `Unknown link type "${scheme}:"`);
    reasons.push(`"${scheme}:" links are copy-only`);
  }

  // ---- Path / length / downloads (§2.4)
  const href = u.href;
  if (href.length > 2000) w('caution', `Very long link (${href.length} characters); it could hide the real destination`);
  else if (href.length > 200) w('info', `Long link (${href.length} characters)`);
  if (special || scheme === 'itms-services') {
    const lastSeg = data.pathDecoded.split('/').pop().toLowerCase();
    const ext = lastSeg.includes('.') ? lastSeg.split('.').pop() : '';
    if (PROFILE_EXTS.includes(ext)) w('danger', 'Installs a configuration profile — it can change system settings, VPN or certificates');
    else if (DOWNLOAD_EXTS.includes(ext)) w('caution', `Link downloads a file (.${ext})`);
  }
  if (/%25[0-9A-Fa-f]{2}/.test(href)) w('info', 'Contains double percent-encoding');

  // ---- Query (§2.4)
  const formEncoding = scheme === 'http' || scheme === 'https';
  const query = parseQuery(u.search, { formEncoding });
  if (query.some((p) => p.malformed)) w('info', 'Contains malformed percent-encoding');
  const trackCtx = {
    host: asciiLower(h), reg: (dom?.registrableDomain || '').replace(/\.$/, ''),
    label: (dom?.registrableDomain || '').split('.')[0],
  };
  if (formEncoding) for (const p of query) p.tracking = isTrackingParam(p.decodedName, trackCtx);
  const tracked = query.filter((p) => p.tracking);
  if (tracked.length) {
    const names = [...new Set(tracked.map((p) => p.decodedName))];
    w('info', `Contains tracking parameters (${names.slice(0, 6).join(', ')}${names.length > 6 ? ', …' : ''})`);
    const kept = query.filter((p) => !p.tracking).map((p) => p.raw);
    const prefix = href.slice(0, href.length - u.hash.length - u.search.length);
    data.cleanHref = prefix + (kept.length ? `?${kept.join('&')}` : '') + u.hash;
  } else {
    data.cleanHref = href;
  }
  // ---- Special families, redirectors, shorteners (§2.7, §2.8)
  const outerReg = dom?.registrableDomain?.replace(/\.$/, '') || h;
  let summaryOverride = null;
  if (scheme === 'magnet') {
    data.magnet = parseMagnet(u, query);
    summaryOverride = `Magnet: ${data.magnet.name || data.magnet.infoHash || 'torrent'}`;
  }
  const fam = detectSpecial(u, scheme, query, dom, w);
  if (fam) {
    const { summary, ...rest } = fam;
    data.special = rest;
    summaryOverride = summary;
    if (fam.kind === 'map' && fam.geo) data.geo = { ...fam.geo, label: fam.label };
  }
  // After family detection (which may mark parameters sensitive).
  data.query = query.map(({ raw, malformed, ...rest }) => rest);

  const redirector = detectRedirector(u, query, dom);
  if (redirector && !data.special) {
    data.special = { kind: 'redirector', service: redirector.service, target: redirector.target };
  }

  const shortHost = SHORTENERS.has(h) ? h : SHORTENERS.has(outerReg) ? outerReg : null;
  if (shortHost && (special)) {
    const firstParty = FIRST_PARTY_SHORT[shortHost];
    if (firstParty) w('info', `Short link to ${firstParty}`);
    else w('caution', 'Shortened link — the real destination is unknown until opened');
    if (!data.special) {
      data.special = { kind: 'shortener', service: shortHost, firstParty: firstParty || null };
      summaryOverride = firstParty ? `Short link to ${firstParty}` : `Short link (${shortHost}) — destination hidden`;
    }
  }

  // ---- Nested URLs (§2.4)
  const candidates = [];
  if (redirector?.target) candidates.push({ param: '(redirect)', url: redirector.target });
  for (const p of query) {
    const nested = findNestedUrl(p.value);
    if (!nested) continue;
    const dq = data.query.find((x) => x.name === p.name && x.value === p.value);
    if (dq) dq.nestedUrl = nested;
    if (!candidates.some((c) => c.url === nested)) candidates.push({ param: p.decodedName, url: nested });
  }
  const redirectTargets = new Set();
  for (const c of candidates.slice(0, 5)) {
    const entry = { param: c.param, url: c.url, analysis: null };
    if (depth < 2) {
      const nested = analyzeUrl(c.url, { depth: depth + 1 });
      entry.analysis = nested;
      const nd = nested.data;
      const nreg = nd.registrableDomain?.replace(/\.$/, '') || nd.host;
      if (nreg && nreg !== outerReg && !redirectTargets.has(nreg)) {
        redirectTargets.add(nreg);
        const likely = NESTED_PARAM_NAMES.has(c.param.toLowerCase()) || redirector;
        w('caution', `${likely ? 'Redirects' : 'May redirect'} to ${nd.registrableDomainUnicode || nd.hostUnicode || nreg}`);
      }
      for (const nw of nested.warnings) {
        if (nw.level === 'danger') w('danger', `Redirect target: ${nw.message}`);
      }
    }
    data.nested.push(entry);
  }

  // ---- Scheme-specific details
  if (scheme === 'javascript') {
    const code = safeDecode(text.slice(text.indexOf(':') + 1)).value;
    data.code = code;
    fields.push({ label: 'Code', value: code, mono: true });
  } else if (scheme === 'data') {
    data.dataUrl = parseDataUrl(text);
    fields.push({ label: 'Media type', value: data.dataUrl.mediaType });
    if (data.dataUrl.size !== null) fields.push({ label: 'Size', value: `${data.dataUrl.size} bytes` });
    if (data.dataUrl.preview) fields.push({ label: 'Decoded content', value: data.dataUrl.preview, mono: true });
  } else if (scheme === 'ssh' && h) {
    const user = data.username ? `${data.username}@` : '';
    const cmd = `ssh ${u.port ? `-p ${u.port} ` : ''}${user}${h}`;
    actions.push({ kind: 'copy', label: 'Copy ssh command', value: cmd });
  }

  // ---- Openability
  if (!OPENABLE_SCHEMES.has(scheme) && !reasons.length) reasons.push(`"${scheme}:" links are copy-only`);
  data.openable = OPENABLE_SCHEMES.has(scheme) && !differential && !unsafe;
  data.notOpenableReason = data.openable ? null : `Not offered because ${reasons[0] || 'this link type is copy-only'}`;

  // ---- Fields
  fields.unshift({ label: 'Link', value: href, mono: true, copy: true });
  if (data.hostUnicode) {
    fields.push({ label: 'Host', value: data.hostUnicode, mono: true });
    if (data.hostUnicode !== h) fields.push({ label: 'Host (ACE)', value: h, mono: true, copy: true });
  }
  if (data.rawIp) fields.push({ label: 'Written as', value: data.rawIp, mono: true });
  if (data.registrableDomainUnicode && data.registrableDomainUnicode !== data.hostUnicode) {
    fields.push({ label: 'Registrable domain', value: data.registrableDomainUnicode, mono: true });
  }
  if (data.username) fields.push({ label: 'User name', value: data.username, mono: true });
  if (u.password) fields.push({ label: 'Password', value: safeDecode(u.password).value, mono: true, sensitive: true });
  if (data.port) fields.push({ label: 'Port', value: data.port, mono: true });
  if (data.pathDecoded && data.pathDecoded !== '/') fields.push({ label: 'Path', value: data.pathDecoded, mono: true });
  for (const p of data.query) {
    fields.push({ label: `Parameter ${p.decodedName}`, value: p.decoded, mono: true, ...(p.sensitive ? { sensitive: true } : {}) });
  }
  if (data.fragment) fields.push({ label: 'Fragment', value: data.fragmentDecoded, mono: true });

  // ---- Actions
  if (data.openable) actions.unshift({ kind: 'open', label: 'Open…', value: href });
  actions.push({ kind: 'copy', label: 'Copy link', value: href });
  if (data.cleanHref !== href) actions.push({ kind: 'copy', label: 'Copy without tracking', value: data.cleanHref });
  if (data.hostKind === 'domain' && h) actions.push({ kind: 'copy', label: 'Copy domain', value: h });

  // ---- Title / summary
  let summary;
  const where = data.registrableDomainUnicode || data.hostUnicode || h;
  if (summaryOverride) summary = summaryOverride;
  else if (scheme === 'https' || scheme === 'http') summary = `Website: ${where}`;
  else if (unsafe) summary = `"${scheme}:" link — can run code or access local files`;
  else summary = where ? `${scheme}: link to ${where}` : `${scheme}: link`;

  return finish({ type: 'url', title, summary, fields, warnings, actions, data });
}

/** Sorts warnings by severity (stable) and removes exact duplicates. */
function finish(analysis) {
  const seen = new Set();
  analysis.warnings = analysis.warnings
    .filter((x) => {
      const k = `${x.level}|${x.message}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
  return analysis;
}

/** Registry-style parser object (used by the dispatcher). */
export const urlParser = {
  id: 'url',
  detect: (text) => detectUrl(text) !== null,
  parse: (text) => analyzeUrl(text),
};

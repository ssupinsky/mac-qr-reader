// Wi-Fi network codes (PAYLOADS.md §3): `WIFI:` in both the ZXing (backslash-escaped)
// and the WPA3-spec (percent-encoded) dialects, and Wi-Fi Easy Connect `DPP:` URIs.

import { createReport, hasPrefix, prep, splitUnescaped, unescapeBackslash, pctDecodeStrict, utf8Length, truncate } from './util.js';
import { base64ToBytes, bytesToHex, hexToBytes, utf8Decode } from './codecs.js';
import { sha256 } from './hash.js';

const KNOWN_KEYS = new Set(['T', 'S', 'P', 'H', 'R', 'K', 'I', 'E', 'A', 'PH2']);
const EAP_TYPES = /^(WPA|WPA2|WPA3)-EAP$|^EAP$/;

/** Human label for the `T:` value. */
function securityLabel(auth) {
  switch (auth.toUpperCase()) {
    case 'WPA': return 'WPA2/WPA3-Personal';
    case 'WPA2': return 'WPA2-Personal';
    case 'WPA3':
    case 'SAE': return 'WPA3-Personal (SAE)';
    case 'WEP': return 'WEP';
    case 'NOPASS': return 'Open (no password)';
    case 'WPA-EAP': return 'WPA-Enterprise';
    case 'WPA2-EAP':
    case 'EAP': return 'WPA2-Enterprise';
    case 'WPA3-EAP': return 'WPA3-Enterprise';
    default: return auth;
  }
}

/** Strips ZXing's quoting of a raw (still escaped) value: `"…"` with an unescaped closing quote. */
function unquote(raw) {
  if (raw.length >= 2 && raw[0] === '"' && raw.endsWith('"')) {
    const inner = raw.slice(1, -1);
    let trailingBackslashes = 0;
    while (trailingBackslashes < inner.length && inner[inner.length - 1 - trailingBackslashes] === '\\') trailingBackslashes++;
    if (trailingBackslashes % 2 === 0) return { raw: inner, quoted: true };
  }
  return { raw, quoted: false };
}

/** SHA-256 fingerprint (first 16 hex chars) of base64 key material, or null. */
function keyFingerprint(b64) {
  const bytes = base64ToBytes(b64);
  if (!bytes || !bytes.length) return null;
  return bytesToHex(sha256(bytes)).slice(0, 16);
}

/** Elliptic curve named in a DER SubjectPublicKeyInfo (by OID byte pattern). */
function curveName(b64) {
  const bytes = base64ToBytes(b64);
  if (!bytes) return null;
  const hex = bytesToHex(bytes);
  const oids = {
    '06082a8648ce3d030107': 'P-256',
    '06052b81040022': 'P-384',
    '06052b81040023': 'P-521',
    '06092b2403030208010107': 'brainpoolP256r1',
    '06092b240303020801010b': 'brainpoolP384r1',
    '06092b240303020801010d': 'brainpoolP512r1',
  };
  for (const [oid, name] of Object.entries(oids)) if (hex.includes(oid)) return name;
  return null;
}

export const wifi = {
  id: 'wifi',
  label: 'Wi-Fi',
  detect(text) {
    return hasPrefix(prep(text), 'WIFI:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const body = prep(text).slice(5);
    const parts = splitUnescaped(body, ';');
    const terminated = parts.length >= 3 && parts.at(-1) === '' && parts.at(-2) === '';
    const raw = {};
    const extra = {};
    for (const part of parts) {
      if (part === '') continue;
      const colon = part.indexOf(':');
      if (colon <= 0) {
        r.warn('info', `Ignored text without a field name: "${truncate(part, 20)}"`);
        continue;
      }
      const key = part.slice(0, colon).toUpperCase();
      const value = part.slice(colon + 1);
      if (!KNOWN_KEYS.has(key)) {
        if (!(key in extra)) extra[key] = unescapeBackslash(value);
        r.warn('info', `Unknown field "${key}"`);
        continue;
      }
      if (key in raw) {
        r.warn('caution', `Duplicate field ${key} (the first one is used)`);
        continue;
      }
      raw[key] = value;
    }
    if (!terminated) r.warn('info', 'Not properly terminated (missing ";;")');

    // Dialect: WPA3 percent-encoding vs ZXing backslash escaping (§3.2).
    const wpa3Style = 'R' in raw || 'K' in raw || (!body.includes('\\') && /%[0-9A-Fa-f]{2}/.test(body));
    const format = wpa3Style ? 'wifi-wpa3' : 'wifi-zxing';

    const decodeValue = (key, label) => {
      if (!(key in raw)) return { value: undefined, quoted: false };
      const { raw: v, quoted } = unquote(raw[key]);
      const zx = unescapeBackslash(v);
      const pct = pctDecodeStrict(v);
      const primary = wpa3Style && pct !== null ? pct : zx;
      const other = primary === zx ? pct : zx;
      // Only %XX escapes make the reading genuinely ambiguous; backslash escaping is the norm.
      if (other !== null && other !== primary && /%[0-9A-Fa-f]{2}/.test(v)) {
        const shown = key === 'P' ? 'a different password' : `"${other}"`;
        r.warn('caution', `${label}: ambiguous encoding — could also be ${shown}`);
      }
      return { value: primary, quoted };
    };

    const ssidRes = decodeValue('S', 'Network name');
    const passRes = decodeValue('P', 'Password');
    const ssid = ssidRes.value ?? '';
    const password = passRes.value ?? '';
    let auth = (raw.T !== undefined ? unescapeBackslash(raw.T) : '').trim();
    if (!auth) auth = password ? 'WPA' : 'nopass';
    const AUTH = auth.toUpperCase();
    const hidden = /^(true|1)$/i.test(raw.H ?? '');
    const isEap = EAP_TYPES.test(AUTH) || 'E' in raw;

    const data = { format, ssid, auth, password, hidden };

    // Security.
    const known = ['WPA', 'WPA2', 'WPA3', 'SAE', 'WEP', 'NOPASS', 'WPA-EAP', 'WPA2-EAP', 'WPA3-EAP', 'EAP'];
    if (!known.includes(AUTH)) r.warn('caution', `Unknown security type "${auth}"`);
    if (AUTH === 'WEP') r.warn('danger', 'WEP is broken; traffic on this network can be decrypted');
    if (AUTH === 'NOPASS') {
      r.warn('caution', 'Open network — traffic is not encrypted (unless it uses Enhanced Open/OWE)');
      r.warn('info', 'Only join networks from codes you trust (fake hotspot risk)');
      if (password) r.warn('caution', 'An open network should not have a password');
    }

    // SSID checks.
    if (!('S' in raw) || ssid === '') r.warn('caution', 'Missing network name (SSID)');
    if (utf8Length(ssid) > 32) r.warn('caution', `Network name is ${utf8Length(ssid)} bytes; the maximum is 32`);
    if (ssid && !ssidRes.quoted && /^(?:[0-9A-Fa-f]{2}){1,32}$/.test(ssid)) {
      const bytes = hexToBytes(ssid);
      const asText = utf8Decode(bytes, true);
      const asBytes = asText !== null && /^[\x20-\x7e -￿]*$/u.test(asText) ? asText : bytesToHex(bytes, ' ');
      r.warn('info', `Network name may be hex-encoded: as text it is "${ssid}", as bytes "${asBytes}"`);
      data.ssidHexDecoded = asBytes;
    }

    // Password checks.
    if (password) {
      if (['WPA', 'WPA2', 'WPA3', 'SAE'].includes(AUTH)) {
        if (!passRes.quoted && /^[0-9A-Fa-f]{64}$/.test(password)) {
          r.warn('info', 'Password is a raw 64-hex-digit pre-shared key');
          data.rawPsk = true;
        } else if (password.length < 8 || password.length > 63) {
          r.warn('caution', `Invalid WPA password length (${password.length}; must be 8–63 characters)`);
        }
        if (/[^\x20-\x7e]/.test(password)) r.warn('info', 'Password contains non-ASCII characters; some devices cannot use it');
      } else if (AUTH === 'WEP' && !/^(.{5}|.{13}|[0-9A-Fa-f]{10}|[0-9A-Fa-f]{26})$/s.test(password)) {
        r.warn('caution', 'Invalid WEP key length');
      }
    } else if (['WPA', 'WPA2', 'WPA3', 'SAE', 'WEP'].includes(AUTH)) {
      r.warn('caution', 'Missing password for a protected network');
    }

    // WPA3 extras.
    if ('R' in raw) {
      const bits = /^[0-9A-Fa-f]+$/.test(raw.R) ? parseInt(raw.R, 16) : NaN;
      if (Number.isNaN(bits)) {
        r.warn('caution', `Invalid transition-disable value "${raw.R}"`);
      } else {
        data.transitionDisable = `0x${bits.toString(16)}`;
      }
    }
    if ('K' in raw) {
      data.saePk = true;
      data.saePkKey = raw.K;
      data.saePkFingerprint = keyFingerprint(raw.K);
      if (!data.saePkFingerprint) r.warn('caution', 'SAE-PK public key is not valid base64');
    }

    // Identity: EAP identity (ZXing) or SAE password identifier (WPA3).
    const idRes = decodeValue('I', 'Identity');
    if (isEap) {
      const anon = decodeValue('A', 'Anonymous identity').value;
      data.eap = {
        method: raw.E !== undefined ? unescapeBackslash(raw.E) : undefined,
        phase2: raw.PH2 !== undefined ? unescapeBackslash(raw.PH2) : undefined,
        anonymousIdentity: anon,
        identity: idRes.value,
      };
    } else if (idRes.value !== undefined) {
      data.saeIdentifier = idRes.value;
    }
    if (Object.keys(extra).length) data.extra = extra;

    // Fields.
    const security = securityLabel(auth);
    r.field('Network', ssid, { mono: true, copy: true, check: false });
    if (r.check('Network name', ssid, { singleLine: true, name: true })) {
      r.warn('caution', 'Network name contains hidden or mixed-script characters — it could imitate another network');
    }
    r.field('Security', security, { check: false });
    r.field('Password', password, { sensitive: true, mono: true, copy: true });
    if (hidden) r.field('Hidden network', 'Yes', { check: false });
    if (data.eap) {
      r.field('EAP method', data.eap.method);
      r.field('Phase 2', data.eap.phase2);
      r.field('Identity', data.eap.identity, { mono: true });
      r.field('Anonymous identity', data.eap.anonymousIdentity, { mono: true });
    }
    r.field('Password identifier', data.saeIdentifier, { mono: true });
    if (data.transitionDisable) {
      const names = ['WPA3-Personal', 'SAE-PK', 'WPA3-Enterprise', 'Enhanced Open'];
      const bits = parseInt(data.transitionDisable, 16);
      const on = names.filter((_, i) => bits & (1 << i));
      r.field('Transition disable', `${data.transitionDisable}${on.length ? ` (${on.join(', ')})` : ''}`, { check: false });
      r.warn('info', 'Devices should disable older WPA2 fallback for this network');
    }
    if (data.saePkFingerprint) r.field('SAE-PK key fingerprint', data.saePkFingerprint, { mono: true, check: false });

    if (password) r.copy('Copy password', password, { sensitive: true });
    if (ssid) r.copy('Copy network name', ssid);

    return r.result({
      type: 'wifi',
      title: 'Wi-Fi network',
      summary: `Wi-Fi: ${ssid || '(no name)'} (${security})`,
      data,
    });
  },
};

export const dpp = {
  id: 'dpp',
  label: 'Wi-Fi Easy Connect',
  detect(text) {
    return hasPrefix(prep(text), 'DPP:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const body = prep(text).slice(4);
    const data = { format: 'dpp', channels: [] };
    const seen = new Set();
    for (const tok of body.split(';')) {
      if (!tok) continue;
      const colon = tok.indexOf(':');
      if (colon <= 0) continue;
      const key = tok.slice(0, colon).toUpperCase();
      const value = tok.slice(colon + 1);
      if (seen.has(key)) {
        r.warn('caution', `Duplicate field ${key} (the first one is used)`);
        continue;
      }
      seen.add(key);
      switch (key) {
        case 'C': data.channels = value.split(',').filter(Boolean); break;
        case 'M':
          if (/^[0-9A-Fa-f]{12}$/.test(value)) data.mac = value.toLowerCase().match(/../g).join(':');
          else r.warn('caution', `Invalid MAC address "${value}"`);
          break;
        case 'I': data.info = value; break;
        case 'V': data.version = /^\d+$/.test(value) ? Number(value) : value; break;
        case 'H': data.host = value; break;
        case 'B': data.bands = value; break;
        case 'K': data.publicKeyB64 = value; break;
        default: (data.extra ??= {})[key] = value;
      }
    }
    if (!body.endsWith(';;')) r.warn('info', 'Not properly terminated (missing ";;")');
    if (!data.publicKeyB64) {
      r.warn('caution', 'Invalid Easy Connect code: the public key (K) is missing');
    } else {
      data.publicKeyFingerprint = keyFingerprint(data.publicKeyB64);
      data.curve = curveName(data.publicKeyB64);
      if (!data.publicKeyFingerprint) r.warn('caution', 'Public key is not valid base64');
    }
    r.warn('info', 'This code is for setting up a device with a phone or router; there is no network to join here');

    const version = data.version ? ` v${data.version}` : '';
    r.field('Kind', `Wi-Fi Easy Connect (DPP${version}) device bootstrap`, { check: false });
    r.field('Device info', data.info);
    r.field('MAC address', data.mac, { mono: true });
    r.field('Channels', data.channels.join(', '), { mono: true });
    r.field('Host', data.host, { mono: true });
    r.field('Bands', data.bands, { mono: true });
    r.field('Key curve', data.curve, { check: false });
    r.field('Key fingerprint (SHA-256)', data.publicKeyFingerprint, { mono: true, check: false });
    r.field('Public key', data.publicKeyB64, { mono: true });
    r.copy('Copy code', prep(text));

    return r.result({
      type: 'wifi',
      title: 'Wi-Fi Easy Connect',
      summary: `Wi-Fi Easy Connect device (DPP${version})${data.info ? `: ${data.info}` : ''}`,
      data,
    });
  },
};

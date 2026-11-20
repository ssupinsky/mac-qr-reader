// Miscellaneous payloads (PAYLOADS.md §11): `magnet:` links, remote-access URLs
// (ssh/sftp/smb/afp/vnc/rdp/telnet), health certificates (HC1 / SMART Health Card /
// NZ COVID Pass — identified, never verified), JWT/JWE, PEM blocks and other keys,
// wallet recovery phrases, base64 blobs. All of these use `type: 'text'` + `data.format`.

import { createReport, hasPrefix, matchPrefix, prep, parseQuery, pctDecode, truncate, group } from './util.js';
import { base45Decode, base58CheckDecode, base64ToBytes, bytesToBase64, bytesToHex, utf8Decode } from './codecs.js';
import { sha256 } from './hash.js';

/** Same as /[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(s) in linear time. */
function hasSchemeLink(s) {
  const isScheme = (c) => /[A-Za-z0-9+.-]/.test(c);
  for (let i = s.indexOf('://'); i !== -1; i = s.indexOf('://', i + 1)) {
    for (let j = i - 1; j >= 0 && isScheme(s[j]); j--) if (/[A-Za-z]/.test(s[j])) return true;
  }
  return false;
}

const isoSeconds = (s) => new Date(s * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

// ---------------------------------------------------------------------------
// magnet: (§11.2)
// ---------------------------------------------------------------------------

export const magnet = {
  id: 'magnet',
  label: 'magnet link',
  detect(text) {
    return hasPrefix(prep(text), 'magnet:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const query = t.slice(7).replace(/^\/*\?/, '');
    const params = parseQuery(query, { plusAsSpace: true });
    const all = (re) => params.filter((p) => re.test(p.name)).map((p) => p.value);
    const xts = all(/^xt(\.\d+)?$/);
    const data = { format: 'magnet', infoHash: null, infoHashV2: null, name: all(/^dn(\.\d+)?$/)[0], trackers: all(/^tr(\.\d+)?$/), webSeeds: all(/^ws(\.\d+)?$/), size: undefined };
    for (const xt of xts) {
      const v1 = /^urn:btih:([0-9a-f]{40}|[A-Z2-7]{32})$/i.exec(xt);
      const v2 = /^urn:btmh:1220([0-9a-f]{64})$/i.exec(xt);
      if (v1 && !data.infoHash) data.infoHash = v1[1].length === 40 ? v1[1].toLowerCase() : v1[1].toUpperCase();
      else if (v2 && !data.infoHashV2) data.infoHashV2 = v2[1].toLowerCase();
      else (data.otherTopics ??= []).push(xt);
    }
    const xl = all(/^xl$/)[0];
    if (xl !== undefined) {
      if (/^\d+$/.test(xl)) data.size = Number(xl);
      else r.warn('caution', `Invalid size "${xl}"`);
    }
    if (!data.infoHash && !data.infoHashV2) r.warn('caution', 'No BitTorrent info-hash found');
    r.warn('info', 'Opening starts a peer-to-peer download; your IP address is visible to other peers');

    const fmtSize = (n) => (n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${(n / 1e3).toFixed(1)} KB` : `${n} bytes`);
    r.field('Name', data.name);
    r.field('Info-hash', data.infoHash, { mono: true, copy: true });
    r.field('Info-hash (v2)', data.infoHashV2, { mono: true });
    r.field('Size', data.size !== undefined ? fmtSize(data.size) : '', { check: false });
    data.trackers.forEach((tr, i) => {
      let host = tr;
      try { host = new URL(tr).host || tr; } catch { /* keep raw */ }
      r.field(data.trackers.length > 1 ? `Tracker ${i + 1}` : 'Tracker', host, { mono: true });
    });
    data.webSeeds.forEach((ws) => r.field('Web seed', ws, { mono: true }));
    r.copy('Copy magnet link', t);
    if (data.infoHash) r.copy('Copy info-hash', data.infoHash);
    return r.result({ type: 'text', title: 'Torrent (magnet link)', summary: `Torrent: ${data.name || data.infoHash || 'unnamed'}`, data });
  },
};

// ---------------------------------------------------------------------------
// Remote access URLs (§11.3, §2.2)
// ---------------------------------------------------------------------------

const REMOTE = {
  ssh: { title: 'SSH connection', port: 22 },
  sftp: { title: 'SFTP connection', port: 22 },
  smb: { title: 'Network share (SMB)', port: 445 },
  afp: { title: 'Network share (AFP)', port: 548 },
  vnc: { title: 'Screen sharing (VNC)', port: 5900 },
  rdp: { title: 'Remote desktop (RDP)', port: 3389 },
  telnet: { title: 'Telnet connection', port: 23 },
};

export const remoteAccess = {
  id: 'remote-access',
  label: 'remote access link',
  detect(text) {
    return !!matchPrefix(prep(text), Object.keys(REMOTE).map((s) => `${s}://`));
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const scheme = t.slice(0, t.indexOf(':')).toLowerCase();
    const info = REMOTE[scheme];
    const rest = t.slice(scheme.length + 3);
    const authEnd = rest.search(/[/?#]/);
    const authority = authEnd < 0 ? rest : rest.slice(0, authEnd);
    const path = authEnd < 0 ? '' : rest.slice(authEnd);
    const at = authority.lastIndexOf('@');
    const userinfo = at < 0 ? '' : authority.slice(0, at);
    const hostport = at < 0 ? authority : authority.slice(at + 1);
    const hp = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(hostport) || [hostport, hostport, ''];
    const [userAndParams, ...pass] = userinfo.split(':');
    const [user, ...userParams] = userAndParams.split(';');
    const data = {
      format: scheme, scheme, host: pctDecode(hp[1]).value, port: hp[2] || '', user: pctDecode(user).value || undefined,
      password: pass.length ? pctDecode(pass.join(':')).value : undefined, path: pctDecode(path).value || undefined,
    };
    const fp = userParams.find((p) => /^fingerprint=/i.test(p));
    if (fp) data.fingerprint = pctDecode(fp.slice(12)).value;

    if (!data.host) r.warn('caution', 'No host given');
    if (/[\s\\]/.test(authority)) r.warn('danger', 'The address contains spaces or backslashes — apps may read it differently');
    if (data.password) r.warn('caution', 'Contains a password in the link');
    if (scheme === 'smb' || scheme === 'afp') r.warn('caution', 'Opens a network share — Finder may send your credentials to this server');
    else if (scheme === 'telnet') r.warn('caution', 'Telnet is not encrypted');
    else r.warn('caution', 'Opens a remote connection in a local app');
    if (data.port && Number(data.port) !== info.port) r.warn('info', `Non-standard port ${data.port}`);

    r.field('Host', data.host, { mono: true, singleLine: true, copy: true });
    r.field('Port', data.port, { mono: true });
    r.field('User', data.user, { mono: true, singleLine: true });
    r.field('Password', data.password, { sensitive: true, mono: true });
    r.field('Path', data.path, { mono: true });
    r.field('Host key fingerprint', data.fingerprint, { mono: true });

    const target = `${data.user ? `${data.user}@` : ''}${data.host}`;
    if (scheme === 'ssh' && data.host) r.copy('Copy ssh command', `ssh ${data.port ? `-p ${data.port} ` : ''}${target}`);
    if (scheme === 'sftp' && data.host) r.copy('Copy sftp command', `sftp ${data.port ? `-P ${data.port} ` : ''}${target}`);
    r.copy('Copy link', t, { sensitive: !!data.password });
    return r.result({ type: 'text', title: info.title, summary: `${info.title}: ${target}${data.port ? `:${data.port}` : ''}`, data });
  },
};

// ---------------------------------------------------------------------------
// Health certificates (§11.4)
// ---------------------------------------------------------------------------

export const healthCert = {
  id: 'healthcert',
  label: 'health certificate',
  detect(text) {
    return !!matchPrefix(prep(text), ['HC1:', 'shc:/', 'NZCP:/']);
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const unverified = 'Signature not verified (that needs online trust lists); contains personal health data';
    r.warn('info', unverified);

    if (hasPrefix(t, 'HC1:')) {
      const bytes = base45Decode(t.slice(4));
      const data = { format: 'hc1', scheme: 'EU Digital COVID Certificate' };
      if (!bytes) r.warn('caution', 'Malformed certificate data (not valid Base45)');
      else {
        data.byteLength = bytes.length;
        const zlib = bytes.length >= 2 && (bytes[0] & 0x0f) === 8 && ((bytes[0] << 8) | bytes[1]) % 31 === 0;
        data.compression = zlib ? 'zlib' : 'none';
        data.coseTagged = !zlib && bytes[0] === 0xd2;
        if (!zlib && bytes[0] !== 0xd2 && bytes[0] !== 0x84) r.warn('caution', 'Certificate data is neither compressed nor a COSE message');
      }
      r.field('Kind', 'EU Digital COVID Certificate (HC1)', { check: false });
      r.field('Encoding', bytes ? `Base45, ${data.compression === 'zlib' ? 'zlib-compressed ' : ''}COSE (${bytes.length} bytes)` : '', { check: false });
      r.copy('Copy certificate data', t, { sensitive: true });
      return r.result({ type: 'text', title: 'Health certificate', summary: 'EU Digital COVID Certificate (signature not verified)', data });
    }

    if (hasPrefix(t, 'shc:/')) {
      const data = { format: 'shc', scheme: 'SMART Health Card' };
      let body = t.slice(5);
      const chunk = /^(\d+)\/(\d+)\/(.*)$/s.exec(body);
      if (chunk) {
        data.chunk = { index: Number(chunk[1]), total: Number(chunk[2]) };
        body = chunk[3];
        r.warn('info', `Part ${chunk[1]} of ${chunk[2]} — scan every part`);
      }
      let jws = '';
      let ok = /^\d*$/.test(body) && body.length % 2 === 0;
      for (let i = 0; ok && i < body.length; i += 2) {
        const n = Number(body.slice(i, i + 2));
        if (n > 77) ok = false;
        else jws += String.fromCharCode(n + 45);
      }
      if (!ok) r.warn('caution', 'Malformed SMART Health Card data');
      else {
        data.jws = jws;
        const [headerB64, payload, sig] = jws.split('.');
        const headerBytes = base64ToBytes(headerB64 || '');
        const headerText = headerBytes ? utf8Decode(headerBytes) : null;
        try {
          data.header = JSON.parse(headerText);
        } catch {
          data.headerPreview = headerText;
        }
        if (payload === undefined || sig === undefined || !data.header) r.warn('info', 'The signed data is incomplete (truncated or a partial chunk)');
        if (data.header?.zip === 'DEF') data.compression = 'deflate-raw';
      }
      r.field('Kind', 'SMART Health Card', { check: false });
      r.field('Header', data.header ? JSON.stringify(data.header) : data.headerPreview, { mono: true });
      r.copy('Copy certificate data', t, { sensitive: true });
      return r.result({ type: 'text', title: 'Health certificate', summary: 'SMART Health Card (signature not verified)', data });
    }

    const m = /^NZCP:\/(\d+)\/([A-Z2-7]+)$/i.exec(t);
    const data = { format: 'nzcp', scheme: 'NZ COVID Pass', version: m ? Number(m[1]) : undefined };
    if (!m) r.warn('caution', 'Malformed NZ COVID Pass data');
    r.field('Kind', 'NZ COVID Pass', { check: false });
    r.field('Version', data.version, { check: false });
    r.copy('Copy certificate data', t, { sensitive: true });
    return r.result({ type: 'text', title: 'Health certificate', summary: 'NZ COVID Pass (signature not verified)', data });
  },
};

// ---------------------------------------------------------------------------
// JWT / JWE (§11.5)
// ---------------------------------------------------------------------------

const JWT_RE = /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/;
const JWE_RE = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/;

function decodeJsonPart(b64) {
  const bytes = base64ToBytes(b64);
  const text = bytes ? utf8Decode(bytes, true) : null;
  if (text === null) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

export const jwt = {
  id: 'jwt',
  phase: 'late', // §0.3 rows 23–24: after the dispatcher's URL and JSON handling
  label: 'token',
  detect(text) {
    const t = prep(text);
    return JWT_RE.test(t) || JWE_RE.test(t);
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const parts = t.split('.');
    const isJwe = parts.length === 5;
    const header = decodeJsonPart(parts[0]);
    const data = { format: isJwe ? 'jwe' : 'jwt', header, payload: null };
    r.warn('caution', 'Looks like an access token — treat it like a password');
    if (!header) r.warn('caution', 'The token header is not valid JSON');
    if (isJwe) {
      r.warn('info', 'Encrypted token (JWE): the contents cannot be read without the key');
    } else {
      data.payload = decodeJsonPart(parts[1]);
      if (!data.payload) r.warn('caution', 'The token payload is not valid JSON');
      r.warn('info', 'Signature not verified');
      if (String(header?.alg).toLowerCase() === 'none') r.warn('info', 'Unsigned token (alg: none)');
    }
    const p = data.payload || {};
    for (const k of ['exp', 'iat', 'nbf']) if (typeof p[k] === 'number' && Number.isFinite(p[k]) && Math.abs(p[k]) < 1e11) data[k] = isoSeconds(p[k]);
    const now = (ctx.now ?? Date.now()) / 1000;
    if (typeof p.exp === 'number' && p.exp < now) {
      data.expired = true;
      r.warn('info', `Expired on ${data.exp}`);
    }

    r.field('Algorithm', header?.alg, { mono: true });
    r.field('Type', header?.typ, { mono: true });
    r.field('Key id', header?.kid, { mono: true });
    if (isJwe) r.field('Encryption', header?.enc, { mono: true });
    r.field('Issuer', typeof p.iss === 'string' ? p.iss : undefined, { mono: true });
    r.field('Subject', p.sub !== undefined ? String(p.sub) : undefined, { mono: true });
    r.field('Audience', p.aud !== undefined ? [].concat(p.aud).join(', ') : undefined, { mono: true });
    r.field('Issued at', data.iat, { check: false });
    r.field('Not before', data.nbf, { check: false });
    r.field('Expires', data.exp, { check: false });
    if (data.payload) r.field('Payload', JSON.stringify(data.payload, null, 2), { mono: true });
    r.field('Token', t, { sensitive: true, mono: true, check: false });
    r.copy('Copy token', t, { sensitive: true });
    if (data.payload) r.copy('Copy payload JSON', JSON.stringify(data.payload, null, 2));
    return r.result({
      type: 'text',
      title: isJwe ? 'Encrypted token (JWE)' : 'Token (JWT)',
      summary: `${isJwe ? 'Encrypted token' : 'JSON Web Token'}${p.iss ? ` from ${truncate(String(p.iss), 40)}` : ''}${header?.alg ? ` (${header.alg})` : ''}`,
      data,
    });
  },
};

// ---------------------------------------------------------------------------
// Keys and certificates (§11.6)
// ---------------------------------------------------------------------------

const PEM_RE = /^-----BEGIN ([A-Z0-9 ]+)-----/;
const SSH_PUB_RE = /^(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) (AAAA[0-9A-Za-z+/=]+)(?: (.*))?$/s;
const AGE_PUB_RE = /^age1[0-9a-z]{58}$/;
const AGE_SECRET_RE = /^AGE-SECRET-KEY-1[0-9A-Z]{58}$/;
const WIF_RE = /^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/;
const HEX_KEY_RE = /^0x[0-9a-fA-F]{64}$/;

export const keys = {
  id: 'keys',
  phase: 'late', // §0.3 rows 23–24: after the dispatcher's URL and JSON handling
  label: 'key',
  detect(text) {
    const t = prep(text);
    return PEM_RE.test(t) || SSH_PUB_RE.test(t) || AGE_PUB_RE.test(t) || AGE_SECRET_RE.test(t) || WIF_RE.test(t) || HEX_KEY_RE.test(t);
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    let m;

    if ((m = PEM_RE.exec(t))) {
      const label = m[1];
      const isPrivate = /PRIVATE KEY/.test(label);
      const end = t.includes(`-----END ${label}-----`);
      const body = t.replace(/-----(BEGIN|END) [A-Z0-9 ]+-----/g, '').replace(/^[A-Za-z-]+: .*$/gm, '').replace(/\s+/g, '');
      const bytes = /^[A-Za-z0-9+/=]*$/.test(body) ? base64ToBytes(body) : null;
      const data = { format: 'pem', label, private: isPrivate, byteLength: bytes?.length };
      if (isPrivate) r.warn('danger', 'Contains a private key — anyone who sees this code can use it');
      else r.warn('info', `Contains a ${label.toLowerCase()}`);
      if (!end) r.warn('info', 'The block seems truncated (missing END line)');
      if (/ENCRYPTED/.test(label) || /Proc-Type: 4,ENCRYPTED/.test(t)) r.warn('info', 'The private key is password-protected');
      if (bytes && !isPrivate) data.sha256 = bytesToHex(sha256(bytes));
      r.field('Kind', `PEM ${label}`, { check: false });
      r.field('Size', bytes ? `${bytes.length} bytes` : '', { check: false });
      r.field('SHA-256 fingerprint', data.sha256 ? group(data.sha256, 2).replace(/ /g, ':') : '', { mono: true, check: false });
      r.field(isPrivate ? 'Private key' : 'Data', t, { sensitive: isPrivate, mono: true, check: false });
      r.copy(isPrivate ? 'Copy private key' : 'Copy', t, { sensitive: isPrivate });
      r.save('Save as file…', `${t}\n`, isPrivate ? 'key.pem' : /CERTIFICATE/.test(label) ? 'certificate.pem' : 'key.pem', 'txt');
      return r.result({ type: 'text', title: isPrivate ? 'Private key' : /CERTIFICATE/.test(label) ? 'Certificate' : 'Public key', summary: `PEM ${label.toLowerCase()}`, data });
    }

    if ((m = SSH_PUB_RE.exec(t))) {
      const blob = base64ToBytes(m[2]);
      const fingerprint = blob ? `SHA256:${bytesToBase64(sha256(blob), { pad: false })}` : null;
      const data = { format: 'ssh-public-key', keyType: m[1], comment: m[3], fingerprint };
      if (!blob) r.warn('caution', 'The key data is not valid base64');
      r.warn('info', 'SSH public key — safe to share; adding it to authorized_keys grants its owner access');
      r.field('Key type', m[1], { mono: true });
      r.field('Comment', m[3]);
      r.field('Fingerprint', fingerprint, { mono: true, copy: true, check: false });
      r.copy('Copy key', t);
      return r.result({ type: 'text', title: 'SSH public key', summary: `SSH ${m[1]} key${m[3] ? ` (${truncate(m[3], 40)})` : ''}`, data });
    }

    if (AGE_PUB_RE.test(t)) {
      r.warn('info', 'age encryption public key — safe to share');
      r.field('Public key', t, { mono: true, copy: true });
      r.copy('Copy key', t);
      return r.result({ type: 'text', title: 'age public key', summary: 'age encryption public key', data: { format: 'age-public-key' } });
    }

    if (AGE_SECRET_RE.test(t)) {
      r.warn('danger', 'Contains an age secret key — anyone who sees this code can decrypt your files');
      r.field('Secret key', t, { sensitive: true, mono: true, check: false });
      r.copy('Copy secret key', t, { sensitive: true });
      return r.result({ type: 'text', title: 'age secret key', summary: 'age encryption secret key', data: { format: 'age-secret-key' } });
    }

    // WIF / raw hex private keys.
    const wif = WIF_RE.test(t) ? base58CheckDecode(t) : null;
    const isWif = !!wif?.valid && wif.version === 0x80;
    if (isWif) r.warn('danger', 'This is a Bitcoin private key (WIF) — anyone who sees it controls the funds');
    else r.warn('caution', 'May be a crypto private key — anyone who sees it may control the funds');
    r.field('Key', t, { sensitive: true, mono: true, check: false });
    r.copy('Copy key', t, { sensitive: true });
    return r.result({
      type: 'text',
      title: 'Possible private key',
      summary: isWif ? 'Bitcoin private key (WIF)' : 'Possible crypto private key',
      data: { format: isWif ? 'wif' : HEX_KEY_RE.test(t) ? 'hex-private-key' : 'wif-like', checksumValid: wif ? wif.valid : undefined },
    });
  },
};

// ---------------------------------------------------------------------------
// Wallet recovery phrases (§11.7)
// ---------------------------------------------------------------------------

const SEED_RE = /^[a-z]{3,8}( [a-z]{3,8}){11,23}$/;

export const seedPhrase = {
  id: 'seed-phrase',
  phase: 'late', // §0.3 rows 23–24: after the dispatcher's URL and JSON handling
  label: 'recovery phrase',
  detect(text) {
    const t = prep(text).replace(/\s+/g, ' ');
    return SEED_RE.test(t) && [12, 15, 18, 21, 24].includes(t.split(' ').length);
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const words = prep(text).split(/\s+/);
    r.warn('danger', 'May be a wallet recovery phrase — anyone who sees it controls the funds. Never enter it on a website.');
    r.warn('info', 'Not checked against the BIP-39 word list; it may also be ordinary text');
    r.field('Words', String(words.length), { check: false });
    r.field('Phrase', words.join(' '), { sensitive: true, mono: true, check: false });
    r.copy('Copy phrase', words.join(' '), { sensitive: true });
    return r.result({ type: 'text', title: 'Possible recovery phrase', summary: `Possible ${words.length}-word wallet recovery phrase`, data: { format: 'seed-phrase', wordCount: words.length } });
  },
};

// ---------------------------------------------------------------------------
// base64 blobs (§11.8)
// ---------------------------------------------------------------------------

const MAGIC = [
  [[0x1f, 0x8b], 'gzip', 'gzip-compressed data'],
  [[0x89, 0x50, 0x4e, 0x47], 'png', 'PNG image'],
  [[0xff, 0xd8, 0xff], 'jpeg', 'JPEG image'],
  [[0x47, 0x49, 0x46, 0x38], 'gif', 'GIF image'],
  [[0x25, 0x50, 0x44, 0x46], 'pdf', 'PDF document'],
  [[0x50, 0x4b, 0x03, 0x04], 'zip', 'ZIP archive'],
  [[0xd2, 0x84], 'cose', 'COSE signed message (CBOR)'],
  [[0x78, 0x01], 'zlib', 'zlib-compressed data'],
  [[0x78, 0x5e], 'zlib', 'zlib-compressed data'],
  [[0x78, 0x9c], 'zlib', 'zlib-compressed data'],
  [[0x78, 0xda], 'zlib', 'zlib-compressed data'],
];

/** Guesses the kind of a byte blob from magic bytes. */
export function sniffBytes(bytes) {
  for (const [sig, kind, label] of MAGIC) if (sig.every((b, i) => bytes[i] === b)) return { kind, label };
  if (bytes[0] === 0x84) return { kind: 'cbor', label: 'CBOR array (maybe COSE)' };
  if (bytes[0] === 0x0a && bytes.length > 2 && bytes[1] < 0x80 && bytes[1] + 2 <= bytes.length) return { kind: 'protobuf', label: 'Possibly protobuf data' };
  return null;
}

function hexDump(bytes, max = 256) {
  const rows = [];
  for (let off = 0; off < Math.min(bytes.length, max); off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, bytes.length, max));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    rows.push(`${off.toString(16).padStart(8, '0')}  ${hex}  |${ascii}|`);
  }
  if (bytes.length > max) rows.push(`… ${bytes.length - max} more bytes`);
  return rows.join('\n');
}

function looksLikeBase64(t) {
  const std = /^[A-Za-z0-9+/]{20,}={0,2}$/.test(t) && t.length % 4 === 0;
  const url = /^[A-Za-z0-9_-]{22,}$/.test(t);
  if (!std && !url) return false;
  if (/^[0-9a-fA-F]+$/.test(t)) return false; // hex strings belong to plain text
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/].filter((re) => re.test(t)).length;
  return classes >= 2 && t.length % 4 !== 1;
}

export const base64Blob = {
  id: 'base64',
  phase: 'late', // §0.3 rows 23–24: after the dispatcher's URL and JSON handling
  label: 'base64 data',
  detect(text) {
    return looksLikeBase64(prep(text));
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const bytes = base64ToBytes(t);
    const variant = /[-_]/.test(t) ? 'url' : 'standard';
    const data = { format: 'base64', variant, byteLength: bytes?.length ?? 0 };
    if (!bytes) {
      r.warn('caution', 'Looks like base64 but cannot be decoded');
      return r.result({ type: 'text', title: 'Encoded data', summary: 'Undecodable base64-like text', data });
    }
    const textOut = utf8Decode(bytes, true);
    const printable = textOut !== null && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(textOut) && textOut.length > 0;
    const magic = sniffBytes(bytes);
    r.field('Encoding', `Base64${variant === 'url' ? ' (URL-safe)' : ''}, ${bytes.length} bytes decoded`, { check: false });
    if (printable && !magic) {
      let json = null;
      if (/^\s*[{[]/.test(textOut)) {
        try { json = JSON.parse(textOut); } catch { /* not JSON */ }
      }
      data.decodedKind = json !== null ? 'json' : 'text';
      data.decodedText = textOut;
      const shown = json !== null ? JSON.stringify(json, null, 2) : textOut;
      r.field(json !== null ? 'Decoded JSON' : 'Decoded text', shown, { mono: json !== null });
      if (hasSchemeLink(textOut)) r.warn('info', 'The decoded text contains a link');
      r.copy('Copy decoded text', shown);
    } else {
      data.decodedKind = magic?.kind || 'binary';
      data.bytesHex = bytesToHex(bytes.subarray(0, 4096));
      r.field('Content', magic ? magic.label : 'Binary data', { check: false });
      r.field('Hex dump', hexDump(bytes), { mono: true, check: false });
      r.copy('Copy hex', bytesToHex(bytes));
      r.save('Save decoded bytes…', bytesToBase64(bytes), `decoded.${magic && ['png', 'jpeg', 'gif', 'pdf', 'zip', 'gzip'].includes(magic.kind) ? { jpeg: 'jpg', gzip: 'gz' }[magic.kind] || magic.kind : 'bin'}`, 'bin');
    }
    r.copy('Copy base64', t);
    const what = data.decodedKind === 'text' ? 'text' : data.decodedKind === 'json' ? 'JSON' : magic ? magic.label : 'binary data';
    return r.result({ type: 'text', title: 'Encoded data', summary: `Base64-encoded ${what} (${bytes.length} bytes)`, data });
  },
};

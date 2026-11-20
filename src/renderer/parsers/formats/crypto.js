// Cryptocurrency payment URIs (PAYLOADS.md §10.7): BIP21 `bitcoin:` (bech32/bech32m and
// base58check validation), BOLT11 Lightning invoices and LNURL, EIP-681 `ethereum:`
// (EIP-55 checksum, token transfer/approve detection), Monero, Solana Pay, TON and
// other BIP21-like schemes. Address checks are *format* checks only.

import {
  createReport, hasPrefix, matchPrefix, prep, parseQuery, pctDecode, groupAddress, ends, thousands,
  decimalToUnits, unitsToDecimal, embeddedUrlWarnings, truncate,
} from './util.js';
import { base58CheckDecode, base58Decode, bech32Decode, convertBits, decodeSegwit, utf8Decode } from './codecs.js';
import { keccak256 } from './hash.js';
import { getOwn, hasOwn, setOwn } from '../dict.js';

const IRREVERSIBLE = 'Crypto payments are irreversible; verify the whole address, not just the start and end.';

/** Adds the common address fields (grouped address + highlighted ends). */
function addressFields(r, label, address) {
  if (!address) return;
  r.field(label, groupAddress(address), { mono: true, singleLine: true, copy: true });
  if (address.length > 14) r.field('Starts / ends with', ends(address, 6), { mono: true, check: false });
}

function commonActions(r, address, amount, uri) {
  if (address) r.copy('Copy address', address);
  if (amount) r.copy('Copy amount', amount);
  r.copy('Copy URI', uri);
}

/** Splits `scheme:target?query` (also `scheme://target`). */
function splitUri(t, scheme) {
  let rest = t.slice(scheme.length + 1);
  if (rest.startsWith('//')) rest = rest.slice(2);
  const qi = rest.indexOf('?');
  return { target: qi < 0 ? rest : rest.slice(0, qi), query: qi < 0 ? '' : rest.slice(qi + 1) };
}

// ---------------------------------------------------------------------------
// Bitcoin-family addresses
// ---------------------------------------------------------------------------

const BTC_BASE58 = {
  0x00: ['P2PKH (legacy)', 'mainnet'], 0x05: ['P2SH', 'mainnet'],
  0x6f: ['P2PKH (legacy)', 'testnet'], 0xc4: ['P2SH', 'testnet'],
};
const SEGWIT_HRP = { bc: 'mainnet', tb: 'testnet', bcrt: 'regtest', ltc: 'mainnet', tltc: 'testnet' };

/**
 * Validates a Bitcoin(-family) address.
 * @returns {{ kind: string, network: string|null, valid: boolean|null, reason?: string }}
 *   `valid: null` when the format isn't recognised (no checksum known).
 */
export function checkBitcoinAddress(address, { family = 'bitcoin' } = {}) {
  if (!address) return { kind: 'none', network: null, valid: null };
  const segwitHrps = family === 'litecoin' ? ['ltc', 'tltc'] : ['bc', 'tb', 'bcrt'];
  const lower = address.toLowerCase();
  if (segwitHrps.some((h) => lower.startsWith(`${h}1`))) {
    const s = decodeSegwit(address);
    if (!s) return { kind: 'SegWit', network: null, valid: false, reason: 'not a valid bech32 string' };
    const kind = s.version === 0 ? (s.programLength === 20 ? 'SegWit v0 (P2WPKH)' : 'SegWit v0 (P2WSH)') : s.version === 1 ? 'Taproot (SegWit v1)' : `SegWit v${s.version}`;
    if (s.valid && !segwitHrps.includes(s.hrp)) return { kind, network: null, valid: false, reason: 'wrong network prefix' };
    return { kind, network: getOwn(SEGWIT_HRP, s.hrp) ?? null, valid: s.valid, reason: s.reason };
  }
  if (/^[1-9A-HJ-NP-Za-km-z]{25,35}$/.test(address)) {
    const d = base58CheckDecode(address);
    if (!d) return { kind: 'base58', network: null, valid: false, reason: 'not base58' };
    if (d.payload.length !== 21) return { kind: 'base58', network: null, valid: false, reason: 'wrong length' };
    if (family === 'bitcoin') {
      const info = BTC_BASE58[d.version];
      if (!info) return { kind: 'base58', network: null, valid: false, reason: `unknown version byte 0x${d.version.toString(16)}` };
      return { kind: info[0], network: info[1], valid: d.valid, reason: d.valid ? undefined : 'checksum mismatch' };
    }
    return { kind: 'base58', network: null, valid: d.valid, reason: d.valid ? undefined : 'checksum mismatch' };
  }
  return { kind: 'unknown', network: null, valid: null };
}

// ---------------------------------------------------------------------------
// Lightning (BOLT11) and LNURL
// ---------------------------------------------------------------------------

const LN_NETWORKS = { bc: 'mainnet', tb: 'testnet', tbs: 'signet', bcrt: 'regtest' };
const MULTIPLIERS = { m: 8n, u: 5n, n: 2n, p: -1n }; // power of ten in millisatoshi per unit

/**
 * Decodes a BOLT11 invoice's human-readable part (amount, network) and, when the
 * checksum is valid, the timestamp and the `d` (description) / `x` (expiry) fields.
 * @returns {null | { network: string, currencyPrefix: string, amountMsat: bigint|null,
 *   checksumValid: boolean, timestamp?: number, description?: string, expiry?: number }}
 */
export function decodeBolt11(invoice) {
  const s = String(invoice).trim();
  const lower = s.toLowerCase();
  const sep = lower.lastIndexOf('1');
  if (sep < 3) return null;
  const hrp = lower.slice(0, sep);
  const m = /^ln(bcrt|tbs|tb|bc|[a-z]+?)(\d+)?([munp])?$/.exec(hrp);
  if (!m) return null;
  const [, cur, digits, mult] = m;
  let amountMsat = null;
  if (digits) {
    const n = BigInt(digits);
    if (!mult) amountMsat = n * 100000000000n;
    else if (mult === 'p') amountMsat = n % 10n === 0n ? n / 10n : null;
    else amountMsat = n * 10n ** MULTIPLIERS[mult];
  }
  const out = { network: getOwn(LN_NETWORKS, cur) || `unknown (${cur})`, currencyPrefix: cur, amountMsat, amountText: digits ? `${digits}${mult || ''}` : null, checksumValid: false };
  const d = bech32Decode(s, { limit: Infinity });
  if (d && d.encoding === 'bech32') {
    out.checksumValid = true;
    const data = d.data;
    if (data.length >= 7 + 104) {
      out.timestamp = data.slice(0, 7).reduce((acc, v) => acc * 32 + v, 0);
      let i = 7;
      const end = data.length - 104; // signature (520 bits = 104 words)
      while (i + 3 <= end) {
        const tag = data[i];
        const len = data[i + 1] * 32 + data[i + 2];
        const words = data.slice(i + 3, i + 3 + len);
        i += 3 + len;
        if (i > end) break;
        if (tag === 13) { // 'd' description
          const bytes = convertBits(words, 5, 8, false);
          if (bytes) out.description = utf8Decode(new Uint8Array(bytes));
        } else if (tag === 6) { // 'x' expiry seconds
          out.expiry = words.reduce((acc, v) => acc * 32 + v, 0);
        } else if (tag === 19) { // 'n' payee node id
          const bytes = convertBits(words, 5, 8, false);
          if (bytes) out.payee = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
        }
      }
    }
  }
  return out;
}

/** "2500 µBTC = 0.0025 BTC = 250,000 sat". */
function describeMsat(msat, amountText) {
  const btc = unitsToDecimal(msat, 11);
  const sat = msat % 1000n === 0n ? `${thousands((msat / 1000n).toString())} sat` : `${thousands(msat.toString())} msat`;
  const unit = amountText?.match(/[munp]$/)?.[0];
  const unitName = { m: 'mBTC', u: 'µBTC', n: 'nBTC', p: 'pBTC' }[unit];
  const head = unitName ? `${amountText.slice(0, -1)} ${unitName} = ` : '';
  return `${head}${btc} BTC = ${sat}`;
}

/** Decodes an LNURL (bech32 of a URL) → URL string, or null. */
export function decodeLnurl(str) {
  const d = bech32Decode(str, { limit: Infinity });
  if (!d || d.hrp !== 'lnurl' || !d.encoding) return null;
  const bytes = convertBits(d.data, 5, 8, false);
  return bytes ? utf8Decode(new Uint8Array(bytes)) : null;
}

const BOLT11_RE = /^ln(bc|tb|tbs|bcrt)[0-9]*[munp]?1[02-9ac-hj-np-z]{6,}$/i;

// ---------------------------------------------------------------------------
// Ethereum (EIP-681, EIP-55)
// ---------------------------------------------------------------------------

const CHAINS = {
  1: ['Ethereum', 'ETH'], 10: ['OP Mainnet', 'ETH'], 56: ['BNB Smart Chain', 'BNB'], 100: ['Gnosis', 'xDAI'],
  137: ['Polygon', 'POL'], 8453: ['Base', 'ETH'], 42161: ['Arbitrum One', 'ETH'], 43114: ['Avalanche C-Chain', 'AVAX'],
  11155111: ['Sepolia (testnet)', 'SepoliaETH'], 17000: ['Holesky (testnet)', 'ETH'],
};

/**
 * EIP-55 checksum check.
 * @returns {'valid'|'invalid'|'none'} `none` when the address is all one case (no checksum).
 */
export function checkEip55(address) {
  const hex = address.slice(2);
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return 'none';
  const hash = keccak256(new TextEncoder().encode(hex.toLowerCase()));
  for (let i = 0; i < 40; i++) {
    const nibble = (hash[i >> 1] >> (i % 2 ? 0 : 4)) & 0x0f;
    const c = hex[i];
    if (/[a-f]/i.test(c) && (nibble >= 8) !== (c === c.toUpperCase())) return 'invalid';
  }
  return 'valid';
}

function ethAddressWarnings(r, address, label) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    if (/\.[a-z]{2,}$/i.test(address)) r.warn('info', `${label} "${address}" is a name; your wallet resolves it to an address`);
    else r.warn('caution', `${label} "${truncate(address, 50)}" is not a valid Ethereum address`);
    return;
  }
  const cs = checkEip55(address);
  if (cs === 'invalid') r.warn('danger', `${label} checksum (EIP-55) is invalid — likely mistyped or altered`);
  else if (cs === 'none') r.warn('info', `${label} has no checksum (all one letter case)`);
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

const BIP21_LIKE = {
  bitcoin: { name: 'Bitcoin', ticker: 'BTC', decimals: 8, unit: 'sat', family: 'bitcoin' },
  litecoin: { name: 'Litecoin', ticker: 'LTC', decimals: 8, unit: 'litoshi', family: 'litecoin' },
  dogecoin: { name: 'Dogecoin', ticker: 'DOGE', decimals: 8, unit: 'koinu', family: 'base58' },
  dash: { name: 'Dash', ticker: 'DASH', decimals: 8, unit: 'duff', family: 'base58' },
  zcash: { name: 'Zcash', ticker: 'ZEC', decimals: 8, unit: 'zatoshi', family: 'base58' },
  bitcoincash: { name: 'Bitcoin Cash', ticker: 'BCH', decimals: 8, unit: 'sat', family: 'cashaddr' },
};

const GENERIC = {
  tron: 'TRON', xrpl: 'XRP Ledger', ripple: 'XRP Ledger', 'web+stellar': 'Stellar', 'web+cardano': 'Cardano',
  algorand: 'Algorand', cosmos: 'Cosmos',
};

const SCHEMES = ['bitcoin', 'litecoin', 'dogecoin', 'dash', 'zcash', 'bitcoincash', 'lightning', 'ethereum', 'monero', 'solana', 'ton', 'lnurlp', 'lnurlw', 'lnurlc', ...Object.keys(GENERIC)];
const SCHEME_PREFIXES = SCHEMES.map((s) => `${s}:`).sort((a, b) => b.length - a.length);

function parseBip21(t, scheme, ctx) {
  const coin = BIP21_LIKE[scheme];
  const r = createReport(ctx);
  const { target, query } = splitUri(t, scheme);
  const params = parseQuery(query);
  const data = { format: scheme === 'bitcoin' ? 'bip21' : scheme, network: coin.name, address: pctDecode(target).value, params: {} };

  // Address validation.
  if (!target) {
    if (!params.some((p) => p.name === 'lightning')) r.warn('caution', 'No address in this payment request');
  } else if (coin.family === 'bitcoin' || coin.family === 'litecoin') {
    const a = checkBitcoinAddress(data.address, { family: coin.family });
    data.addressKind = a.kind;
    data.addressValid = a.valid;
    if (a.valid === false) r.warn('danger', `Address checksum invalid (${a.reason}) — likely mistyped or altered`);
    else if (a.valid === null) r.warn('caution', `Unrecognised ${coin.name} address format`);
    if (a.network && a.network !== 'mainnet') r.warn('info', `${a.network[0].toUpperCase()}${a.network.slice(1)} address (not real money)`);
    data.testnet = a.network && a.network !== 'mainnet' ? true : undefined;
  } else if (coin.family === 'base58') {
    const d = base58CheckDecode(data.address);
    data.addressValid = d ? d.valid : false;
    if (!d) r.warn('caution', `Unrecognised ${coin.name} address format`);
    else if (!d.valid) r.warn('danger', 'Address checksum invalid — likely mistyped or altered');
  } else {
    r.warn('info', 'Address checksum not verified');
  }

  // Parameters.
  for (const p of params) {
    if (hasOwn(data.params, p.name)) {
      r.warn('caution', `Duplicate parameter "${p.name}"`);
      continue;
    }
    setOwn(data.params, p.name, p.value);
  }
  const amountStr = data.params.amount;
  if (amountStr !== undefined) {
    const units = decimalToUnits(amountStr, coin.decimals);
    if (units === null || !/^\d*\.?\d+$|^\d+\.?$/.test(amountStr)) r.warn('caution', `Invalid amount "${amountStr}"`);
    else {
      data.amount = unitsToDecimal(units, coin.decimals);
      data.amountUnits = units.toString();
      if (scheme === 'bitcoin') data.sats = units.toString();
    }
  }
  data.label = data.params.label;
  data.message = data.params.message;
  for (const name of Object.keys(data.params)) {
    if (name.startsWith('req-')) r.warn('caution', `Unknown required parameter "${name}" — a wallet must refuse this request`);
  }
  if (data.params.lightning) {
    data.lightning = data.params.lightning;
    const ln = decodeBolt11(data.lightning);
    if (ln) {
      data.lightningInvoice = { network: ln.network, amountMsat: ln.amountMsat?.toString() ?? null, checksumValid: ln.checksumValid, description: ln.description };
      if (!ln.checksumValid) r.warn('caution', 'The included Lightning invoice is damaged or truncated (checksum invalid)');
    } else {
      r.warn('caution', 'The lightning parameter is not a valid invoice');
    }
  }
  if (data.params.pj) {
    data.payjoin = data.params.pj;
    r.warn('info', 'Payjoin: your wallet will contact a server to build the transaction');
    r.warnAll(embeddedUrlWarnings(data.params.pj, ctx, 'Payjoin endpoint'));
  }
  if (data.params.sp) r.warn('info', 'Includes a silent-payment address');
  r.warn('info', IRREVERSIBLE);

  const amount = data.amount ? `${data.amount} ${coin.ticker}` : '';
  r.field('Network', coin.name + (data.testnet ? ' (testnet)' : ''), { check: false });
  r.field('Amount', amount ? `${amount}${data.amountUnits ? ` (${thousands(data.amountUnits)} ${coin.unit})` : ''}` : 'Not set (you enter it)', { check: false });
  addressFields(r, 'Address', data.address);
  r.field('Address type', data.addressKind && data.addressKind !== 'unknown' ? data.addressKind : '', { check: false });
  r.field('Label', data.label, { singleLine: true });
  r.field('Message', data.message);
  if (data.lightning) {
    const ln = data.lightningInvoice;
    r.field('Lightning invoice', data.lightning, { mono: true, copy: true });
    if (ln?.amountMsat) r.field('Lightning amount', describeMsat(BigInt(ln.amountMsat), decodeBolt11(data.lightning).amountText), { check: false });
  }
  r.field('Payjoin endpoint', data.payjoin, { mono: true });
  for (const [k, v] of Object.entries(data.params)) {
    if (!['amount', 'label', 'message', 'lightning', 'pj'].includes(k)) r.field(`Parameter ${k}`, v, { mono: true });
  }
  commonActions(r, data.address, data.amount, t);
  if (data.lightning) r.copy('Copy Lightning invoice', data.lightning);

  return r.result({
    type: 'crypto',
    title: `${coin.name} payment`,
    summary: `${amount ? `Send ${amount}` : `${coin.name} payment`} to ${data.address ? ends(data.address, 6) : 'a Lightning invoice'}${data.label ? ` (${data.label})` : ''}`,
    data,
  });
}

function parseLightning(t, invoice, ctx, format = 'bolt11') {
  const r = createReport(ctx);
  const data = { format, network: 'Lightning', invoice };
  // LNURL (bech32-encoded URL) and lnurlp:// / lnurlw:// forms.
  if (/^lnurl1/i.test(invoice) || /^lnurl[pwc]:/i.test(t)) {
    let url;
    if (/^lnurl1/i.test(invoice)) url = decodeLnurl(invoice);
    else {
      const rest = t.replace(/^lnurl[pwc]:(\/\/)?/i, '');
      const host = rest.split(/[/?#]/)[0];
      url = `${/\.onion(:\d+)?$/i.test(host) ? 'http' : 'https'}://${rest}`;
    }
    data.format = 'lnurl';
    data.url = url;
    if (!url) r.warn('caution', 'Invalid LNURL (checksum or encoding error)');
    else {
      r.warn('info', `Your wallet will contact ${url.replace(/^https?:\/\//, '').split(/[/?#]/)[0]} to get the payment details`);
      r.warnAll(embeddedUrlWarnings(url, ctx, 'LNURL server'));
    }
    r.warn('info', IRREVERSIBLE);
    r.field('Kind', 'LNURL (Lightning payment link)', { check: false });
    r.field('Server URL', url, { mono: true, copy: true });
    r.copy('Copy LNURL', invoice);
    return r.result({ type: 'crypto', title: 'Lightning payment link', summary: `Lightning payment link via ${url ? url.replace(/^https?:\/\//, '').split(/[/?#]/)[0] : 'an unreadable LNURL'}`, data });
  }

  const ln = decodeBolt11(invoice);
  if (!ln) {
    r.warn('caution', 'Not a valid Lightning invoice');
  } else {
    data.network = ln.network;
    data.amountMsat = ln.amountMsat?.toString() ?? null;
    data.checksumValid = ln.checksumValid;
    if (ln.timestamp !== undefined) data.timestamp = ln.timestamp;
    if (ln.description !== undefined) data.description = ln.description;
    if (ln.expiry !== undefined) data.expiry = ln.expiry;
    if (ln.payee) data.payee = ln.payee;
    if (!ln.checksumValid) r.warn('caution', 'Invoice checksum invalid — the invoice is damaged or truncated');
    if (ln.network !== 'mainnet') r.warn('info', `${ln.network} invoice (not real money)`);
    if (ln.amountText && ln.amountMsat === null) r.warn('caution', 'Invalid invoice amount');
    if (ln.timestamp !== undefined) {
      const expiresAt = (ln.timestamp + (ln.expiry ?? 3600)) * 1000;
      data.expiresAt = new Date(expiresAt).toISOString().replace(/\.\d{3}Z$/, 'Z');
      if (expiresAt < (ctx.now ?? Date.now())) r.warn('info', 'This invoice has expired');
    }
  }
  r.warn('info', IRREVERSIBLE);

  const amount = ln?.amountMsat != null ? describeMsat(ln.amountMsat, ln.amountText) : 'Any amount (you enter it)';
  r.field('Network', `Lightning (${data.network})`, { check: false });
  r.field('Amount', amount, { check: false });
  r.field('Description', data.description);
  r.field('Expires', data.expiresAt, { check: false });
  r.field('Payee node', data.payee, { mono: true });
  r.field('Invoice', invoice, { mono: true, copy: true });
  r.copy('Copy invoice', invoice);

  const btc = ln?.amountMsat != null ? `${unitsToDecimal(ln.amountMsat, 11)} BTC` : 'any amount';
  return r.result({ type: 'crypto', title: 'Lightning invoice', summary: `Lightning invoice for ${btc}${data.description ? ` — ${truncate(data.description, 40)}` : ''}`, data });
}

function parseEthereum(t, ctx) {
  const r = createReport(ctx);
  const rest = t.slice('ethereum:'.length);
  const m = /^(pay-)?([^@/?]+)(?:@(\d+))?(?:\/([^?]+))?(?:\?(.*))?$/s.exec(rest);
  const data = { format: 'eip681', network: 'Ethereum', params: {} };
  if (!m) {
    r.warn('caution', 'Malformed Ethereum payment request');
    r.copy('Copy URI', t);
    return r.result({ type: 'crypto', title: 'Ethereum request', summary: 'Malformed Ethereum payment request', data });
  }
  const [, , target, chain, fn, query] = m;
  data.target = target;
  data.chainId = chain ? Number(chain) : 1;
  const [chainName, native] = CHAINS[data.chainId] || [`Chain ${data.chainId}`, 'native coin'];
  data.network = chainName;
  if (fn) data.functionName = fn;
  for (const p of parseQuery(query || '')) if (!hasOwn(data.params, p.name)) setOwn(data.params, p.name, p.value);
  if (!CHAINS[data.chainId]) r.warn('info', `Unknown chain id ${data.chainId} — check which network your wallet uses`);
  if (/testnet/.test(chainName)) r.warn('info', 'Testnet (not real money)');

  const toWei = (v) => decimalToUnits(v, 0, { allowExponent: true });
  ethAddressWarnings(r, target, fn ? 'Contract address' : 'Address');

  let summary;
  if (!fn) {
    data.address = target;
    if (data.params.value !== undefined) {
      const wei = toWei(data.params.value);
      if (wei === null) r.warn('caution', `Invalid value "${data.params.value}" (must be a whole number of wei)`);
      else {
        data.valueWei = wei.toString();
        data.amount = unitsToDecimal(wei, 18);
      }
    }
    const amount = data.amount ? `${data.amount} ${native}` : '';
    r.field('Network', `${chainName} (chain ${data.chainId})`, { check: false });
    r.field('Amount', amount ? `${amount} (${thousands(data.valueWei)} wei)` : 'Not set (you enter it)', { check: false });
    addressFields(r, 'To', target);
    summary = `${amount ? `Send ${amount}` : `${chainName} payment`} to ${ends(target, 6)}`;
  } else if (fn === 'transfer') {
    const recipient = data.params.address;
    const units = data.params.uint256 !== undefined ? toWei(data.params.uint256) : null;
    data.tokenContract = target;
    data.recipient = recipient;
    data.tokenAmount = units?.toString();
    if (!recipient) r.warn('caution', 'Token transfer without a recipient (address parameter)');
    else ethAddressWarnings(r, recipient, 'Recipient address');
    if (data.params.uint256 !== undefined && units === null) r.warn('caution', `Invalid token amount "${data.params.uint256}"`);
    r.warn('caution', `Token transfer: the tokens go to ${recipient ? ends(recipient, 6) : '(missing)'} — the first address (${ends(target, 6)}) is the token contract, not the recipient`);
    r.field('Network', `${chainName} (chain ${data.chainId})`, { check: false });
    r.field('Action', 'Token transfer (ERC-20)', { check: false });
    addressFields(r, 'Recipient', recipient);
    r.field('Token amount (raw units)', data.tokenAmount ? thousands(data.tokenAmount) : '', { mono: true, check: false });
    r.field('Token contract', target, { mono: true });
    summary = `Token transfer: send ${data.tokenAmount ?? '?'} units of token ${ends(target, 4)} to ${recipient ? ends(recipient, 4) : '(missing recipient)'}`;
  } else {
    data.contract = target;
    const isApproval = /^(approve|setApprovalForAll|increaseAllowance|permit)$/i.test(fn);
    if (isApproval) r.warn('danger', `Grants someone permission to spend your tokens (${fn}${data.params.address ? ` to ${ends(data.params.address, 6)}` : ''})`);
    else r.warn('caution', `Calls the contract function "${fn}"`);
    if (data.params.address) ethAddressWarnings(r, data.params.address, 'Address parameter');
    r.field('Network', `${chainName} (chain ${data.chainId})`, { check: false });
    r.field('Action', isApproval ? `Token approval (${fn})` : `Contract call: ${fn}`, { check: false });
    r.field('Contract', target, { mono: true, copy: true });
    summary = isApproval ? `Token approval (${fn}) on contract ${ends(target, 4)}` : `Contract call ${fn} on ${ends(target, 4)}`;
  }
  for (const [k, v] of Object.entries(data.params)) {
    if (!(fn === 'transfer' && ['address', 'uint256'].includes(k)) && !(!fn && k === 'value')) r.field(`Parameter ${k}`, v, { mono: true });
  }
  if (data.params.gasPrice || data.params.gasLimit || data.params.gas) r.warn('info', 'Sets gas parameters; your wallet may override them');
  r.warn('info', IRREVERSIBLE);
  commonActions(r, data.recipient || data.address || target, data.amount, t);
  return r.result({ type: 'crypto', title: fn ? 'Ethereum contract request' : 'Ethereum payment', summary, data });
}

function parseMonero(t, ctx) {
  const r = createReport(ctx);
  const { target, query } = splitUri(t, 'monero');
  const params = Object.fromEntries(parseQuery(query).map((p) => [p.name, p.value]));
  const address = pctDecode(target).value;
  const data = { format: 'monero', network: 'Monero', address, params };
  const okShape = /^[48][1-9A-HJ-NP-Za-km-z]{94}$|^4[1-9A-HJ-NP-Za-km-z]{105}$/.test(address);
  if (!okShape) r.warn('caution', 'Unrecognised Monero address format');
  else r.warn('info', 'Address checksum not verified');
  if (address.startsWith('8')) data.addressKind = 'subaddress';
  else if (address.length === 106) data.addressKind = 'integrated';
  else if (okShape) data.addressKind = 'standard';
  if (params.tx_amount !== undefined) {
    const units = decimalToUnits(params.tx_amount, 12);
    if (units === null) r.warn('caution', `Invalid amount "${params.tx_amount}"`);
    else data.amount = unitsToDecimal(units, 12);
  }
  if (params.tx_payment_id) r.warn('info', 'Uses a payment ID (deprecated in Monero)');
  r.warn('info', IRREVERSIBLE);
  r.field('Network', 'Monero', { check: false });
  r.field('Amount', data.amount ? `${data.amount} XMR` : 'Not set (you enter it)', { check: false });
  addressFields(r, 'Address', address);
  r.field('Address type', data.addressKind, { check: false });
  r.field('Recipient name', params.recipient_name, { singleLine: true });
  r.field('Description', params.tx_description);
  r.field('Payment ID', params.tx_payment_id, { mono: true });
  commonActions(r, address, data.amount, t);
  return r.result({ type: 'crypto', title: 'Monero payment', summary: `${data.amount ? `Send ${data.amount} XMR` : 'Monero payment'} to ${ends(address, 6)}`, data });
}

function parseSolana(t, ctx) {
  const r = createReport(ctx);
  const { target, query } = splitUri(t, 'solana');
  const decodedTarget = pctDecode(target).value;
  const params = Object.fromEntries(parseQuery(query).map((p) => [p.name, p.value]));
  const data = { format: 'solana-pay', network: 'Solana', params };
  r.warn('info', IRREVERSIBLE);
  if (/^https:/i.test(decodedTarget)) {
    // Transaction request: wallet fetches a transaction from this server.
    data.kind = 'transaction-request';
    data.url = decodedTarget;
    const host = decodedTarget.replace(/^https:\/\//i, '').split(/[/?#]/)[0];
    r.warn('caution', `Your wallet will load a transaction from ${host} — check what it asks you to sign`);
    r.warnAll(embeddedUrlWarnings(decodedTarget, ctx, 'Transaction server'));
    r.field('Network', 'Solana', { check: false });
    r.field('Kind', 'Transaction request (Solana Pay)', { check: false });
    r.field('Server', decodedTarget, { mono: true, copy: true });
    r.field('Label', params.label);
    r.field('Message', params.message);
    r.copy('Copy URI', t);
    return r.result({ type: 'crypto', title: 'Solana transaction request', summary: `Solana transaction request from ${host}`, data });
  }
  data.kind = 'transfer';
  data.address = decodedTarget;
  const raw = base58Decode(decodedTarget);
  if (!raw || raw.length !== 32) r.warn('caution', 'Unrecognised Solana address format');
  if (params.amount !== undefined) {
    const units = decimalToUnits(params.amount, params['spl-token'] ? 18 : 9);
    if (units === null) r.warn('caution', `Invalid amount "${params.amount}"`);
    else data.amount = params.amount.replace(/^0+(?=\d)/, '');
  }
  if (params['spl-token']) data.token = params['spl-token'];
  const unit = data.token ? 'tokens' : 'SOL';
  r.field('Network', 'Solana', { check: false });
  r.field('Amount', data.amount ? `${data.amount} ${unit}` : 'Not set (you enter it)', { check: false });
  addressFields(r, 'Recipient', decodedTarget);
  r.field('Token (mint)', data.token, { mono: true });
  r.field('Label', params.label, { singleLine: true });
  r.field('Message', params.message);
  r.field('Memo', params.memo);
  r.field('Reference', params.reference, { mono: true });
  commonActions(r, decodedTarget, data.amount, t);
  return r.result({ type: 'crypto', title: 'Solana payment', summary: `${data.amount ? `Send ${data.amount} ${unit}` : 'Solana payment'} to ${ends(decodedTarget, 6)}`, data });
}

function parseTon(t, ctx) {
  const r = createReport(ctx);
  const { target, query } = splitUri(t, 'ton');
  const params = Object.fromEntries(parseQuery(query).map((p) => [p.name, p.value]));
  const [action, ...rest] = target.split('/');
  const address = pctDecode(rest.join('/')).value;
  const data = { format: 'ton', network: 'TON', action, address, params };
  if (action !== 'transfer') r.warn('caution', `Unknown TON action "${action}"`);
  if (!/^[A-Za-z0-9_-]{48}$|^-?\d+:[0-9a-fA-F]{64}$/.test(address)) r.warn('caution', 'Unrecognised TON address format');
  if (params.amount !== undefined) {
    if (!/^\d+$/.test(params.amount)) r.warn('caution', `Invalid amount "${params.amount}" (nanoton expected)`);
    else data.amount = unitsToDecimal(BigInt(params.amount), 9);
  }
  if (params.bin) r.warn('caution', 'Includes a raw message payload (bin) — your wallet will send it to the contract');
  if (params.jetton) r.warn('info', 'Jetton (token) transfer');
  r.warn('info', IRREVERSIBLE);
  r.field('Network', 'TON', { check: false });
  r.field('Amount', data.amount ? `${data.amount} TON (${thousands(params.amount)} nanoton)` : 'Not set (you enter it)', { check: false });
  addressFields(r, 'Address', address);
  r.field('Comment', params.text);
  r.field('Jetton', params.jetton, { mono: true });
  commonActions(r, address, data.amount, t);
  return r.result({ type: 'crypto', title: 'TON payment', summary: `${data.amount ? `Send ${data.amount} TON` : 'TON payment'} to ${ends(address, 6)}`, data });
}

function parseGeneric(t, scheme, ctx) {
  const r = createReport(ctx);
  const name = GENERIC[scheme];
  const { target, query } = splitUri(t, scheme);
  const params = Object.fromEntries(parseQuery(query).map((p) => [p.name, p.value]));
  const address = pctDecode(target).value;
  const data = { format: scheme.replace('web+', ''), network: name, address, params };
  r.warn('info', IRREVERSIBLE);
  r.warn('info', 'Address format not verified');
  r.field('Network', name, { check: false });
  addressFields(r, scheme === 'web+stellar' ? 'Request' : 'Address', address);
  for (const [k, v] of Object.entries(params)) r.field(k === 'amount' ? 'Amount' : `Parameter ${k}`, v, { mono: true });
  commonActions(r, params.destination || address, params.amount, t);
  return r.result({ type: 'crypto', title: `${name} payment`, summary: `${name}${params.amount ? ` payment of ${params.amount}` : ' payment'} to ${ends(params.destination || address, 6)}`, data });
}

function parseBareEvm(t, ctx) {
  const r = createReport(ctx);
  ethAddressWarnings(r, t, 'Address');
  r.warn('info', 'EVM address (network unknown) — Ethereum, Polygon, BNB Chain and others share this format');
  r.warn('info', IRREVERSIBLE);
  r.field('Kind', 'EVM address (Ethereum-compatible)', { check: false });
  addressFields(r, 'Address', t);
  r.copy('Copy address', t);
  return r.result({ type: 'crypto', title: 'Ethereum-style address', summary: `EVM address ${ends(t, 6)}`, data: { format: 'evm-address', network: null, address: t } });
}

export const cryptoUri = {
  id: 'crypto',
  label: 'crypto payment',
  detect(text) {
    const t = prep(text);
    if (matchPrefix(t, SCHEME_PREFIXES)) return true;
    if (BOLT11_RE.test(t) || /^lnurl1[02-9ac-hj-np-z]{6,}$/i.test(t)) return true;
    return /^0x[0-9a-fA-F]{40}$/.test(t);
  },
  parse(text, ctx = {}) {
    const t = prep(text);
    const prefix = matchPrefix(t, SCHEME_PREFIXES);
    if (!prefix) {
      if (/^0x/i.test(t)) return parseBareEvm(t, ctx);
      return parseLightning(t, t, ctx);
    }
    const scheme = prefix.slice(0, -1).toLowerCase();
    if (hasOwn(BIP21_LIKE, scheme)) return parseBip21(t, scheme, ctx);
    if (scheme === 'lightning') return parseLightning(t, splitUri(t, 'lightning').target, ctx);
    if (scheme.startsWith('lnurl')) return parseLightning(t, t, ctx, 'lnurl');
    if (scheme === 'ethereum') return parseEthereum(t, ctx);
    if (scheme === 'monero') return parseMonero(t, ctx);
    if (scheme === 'solana') return parseSolana(t, ctx);
    if (scheme === 'ton') return parseTon(t, ctx);
    return parseGeneric(t, scheme, ctx);
  },
};

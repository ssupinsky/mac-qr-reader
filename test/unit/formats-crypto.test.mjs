import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, field, action, fuzz } from './_formats-helper.mjs';
import { checkBitcoinAddress, checkEip55, decodeBolt11, decodeLnurl } from '../../src/renderer/parsers/formats/crypto.js';
import { bech32Encode, convertBits, decodeSegwit } from '../../src/renderer/parsers/formats/codecs.js';
import { keccak256, sha256 } from '../../src/renderer/parsers/formats/hash.js';
import { bytesToHex } from '../../src/renderer/parsers/formats/codecs.js';

const IRREV = /irreversible/;
const enc = (s) => new TextEncoder().encode(s);

/** Builds a syntactically valid BOLT11 invoice (zero signature) for tests. */
function makeInvoice(hrp, { timestamp = 1496314658, description, expiry } = {}) {
  const words = [];
  for (let i = 6; i >= 0; i--) words.push(Math.floor(timestamp / 32 ** i) % 32);
  const tag = (t, data) => words.push(t, data.length >> 5, data.length & 31, ...data);
  if (description !== undefined) tag(13, convertBits([...enc(description)], 8, 5, true));
  if (expiry !== undefined) tag(6, [Math.floor(expiry / 32), expiry % 32]);
  words.push(...new Array(104).fill(0));
  return bech32Encode(hrp, words);
}

test('hash and address primitives', () => {
  assert.equal(bytesToHex(keccak256(enc(''))), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(bytesToHex(sha256(enc('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  for (const a of ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb']) {
    assert.equal(checkEip55(a), 'valid', a);
  }
  assert.equal(checkEip55('0x52908400098527886E0F7030069857D2E4169EE7'), 'none');
  assert.equal(checkEip55('0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed'), 'invalid');
  assert.equal(decodeSegwit('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4').valid, true);
  assert.equal(decodeSegwit('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y').valid, true);
  assert.equal(decodeSegwit('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0').valid, true);
  assert.equal(decodeSegwit('bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du').valid, false, 'bech32 checksum for v2');
  assert.equal(decodeSegwit('bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4').valid, false, 'mixed case');
  assert.equal(checkBitcoinAddress('1BoatSLRHtKNngkdXEeobR76b53LETtpyT').valid, true);
  assert.equal(checkBitcoinAddress('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy').kind, 'P2SH');
  assert.equal(checkBitcoinAddress('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn').network, 'testnet');
});

test('BIP21: amount, label, message (spec example address has a bad checksum)', () => {
  const a = analyze('bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz');
  assert.equal(a.type, 'crypto');
  assert.equal(a.data.format, 'bip21');
  assert.equal(a.data.amount, '50');
  assert.equal(a.data.sats, '5000000000');
  assert.equal(a.data.label, 'Luke-Jr');
  assert.equal(a.data.message, 'Donation for project xyz');
  // The address in the BIP-21 text really fails base58check (independently verified).
  assertWarning(a, 'danger', /checksum invalid/);
  assertWarning(a, 'info', IRREV);
  const ok = analyze('bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=50');
  assertNoWarning(ok, 'danger');
  assert.equal(ok.data.addressKind, 'P2PKH (legacy)');
  assert.equal(field(ok, 'Starts / ends with').value, '1BoatS … ETtpyT');
});

test('BIP21: uppercase bech32 + lightning parameter', () => {
  const inv = makeInvoice('lnbc10u', { description: 'coffee' });
  const a = analyze(`BITCOIN:BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ?amount=0.00001&lightning=${inv.toUpperCase()}`);
  assert.equal(a.data.addressValid, true);
  assert.equal(a.data.addressKind, 'SegWit v0 (P2WPKH)');
  assert.equal(a.data.amount, '0.00001');
  assert.equal(a.data.sats, '1000');
  assert.equal(a.data.lightningInvoice.amountMsat, '1000000');
  assert.equal(a.data.lightningInvoice.checksumValid, true);
  assert.equal(a.data.lightningInvoice.description, 'coffee');
  assertNoWarning(a, 'danger');
  assertNoWarning(a, 'caution');
  // Truncated invoice as written in the spec ("LNBC10U1P…").
  assertWarning(analyze('BITCOIN:BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ?amount=0.00001&lightning=LNBC10U1P…'), 'caution', /Lightning invoice/);
});

test('BIP21: unknown req- parameter, payjoin, testnet, invalid amount, bad bech32', () => {
  assertWarning(analyze('bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?req-somethingyoudontunderstand=50'), 'caution', /must refuse/);
  assertWarning(analyze('bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?pj=https://pj.example/x'), 'info', /Payjoin/);
  assertWarning(analyze('bitcoin:tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'), 'info', /Testnet/);
  assertWarning(analyze('bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=1,5'), 'caution', /Invalid amount/);
  assertWarning(analyze('bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.000000001'), 'caution', /Invalid amount/);
  assertWarning(analyze('bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx'), 'danger', /checksum/);
  assertWarning(analyze('bitcoin:hello'), 'caution', /Unrecognised/);
  assertWarning(analyze('bitcoin:?amount=1'), 'caution', /No address/);
});

test('Lightning invoices', () => {
  const inv = makeInvoice('lnbc2500u', { description: '1 cup coffee', expiry: 60 });
  const a = analyze(`lightning:${inv}`);
  assert.equal(a.data.format, 'bolt11');
  assert.equal(a.data.network, 'mainnet');
  assert.equal(a.data.amountMsat, '250000000');
  assert.equal(a.data.description, '1 cup coffee');
  assert.equal(a.data.expiry, 60);
  assert.equal(field(a, 'Amount').value, '2500 µBTC = 0.0025 BTC = 250,000 sat');
  assertWarning(a, 'info', /expired/);
  // Bare invoice, testnet, no amount.
  const t = analyze(makeInvoice('lntb1u').toUpperCase());
  assert.equal(t.data.network, 'testnet');
  assert.equal(t.data.amountMsat, '100000');
  const none = analyze(makeInvoice('lnbc'));
  assert.equal(none.data.amountMsat, null);
  assert.match(field(none, 'Amount').value, /Any amount/);
  // Truncated spec examples keep the HRP information.
  const spec = analyze('lightning:lnbc2500u1pvjluez…');
  assert.equal(spec.data.amountMsat, '250000000');
  assertWarning(spec, 'caution', /damaged or truncated/);
  assert.equal(decodeBolt11('lnbc1pvjluez').amountMsat, null);
  assert.equal(decodeBolt11('lnbc10p1x').amountMsat, 1n);
  assert.equal(decodeBolt11('lnbc11p1x').amountMsat, null, 'sub-millisatoshi');
});

test('LNURL', () => {
  const url = 'https://service.example/api?q=3fc3';
  const lnurl = bech32Encode('lnurl', convertBits([...enc(url)], 8, 5, true)).toUpperCase();
  assert.equal(decodeLnurl(lnurl), url);
  const a = analyze(lnurl);
  assert.equal(a.data.format, 'lnurl');
  assert.equal(a.data.url, url);
  assertWarning(a, 'info', /service\.example/);
  assert.equal(analyze(`lightning:${lnurl}`).data.url, url);
  assert.equal(analyze('lnurlp://pay.example/u/alice').data.url, 'https://pay.example/u/alice');
  assert.equal(analyze('lnurlw://abc.onion/w').data.url, 'http://abc.onion/w');
});

test('EIP-681 native payment with scientific notation', () => {
  const a = analyze('ethereum:0xfb6916095ca1df60bb79Ce92cE3Ea74c37c5d359?value=2.014e18');
  assert.equal(a.data.format, 'eip681');
  assert.equal(a.data.chainId, 1);
  assert.equal(a.data.valueWei, '2014000000000000000');
  assert.equal(a.data.amount, '2.014');
  assert.equal(a.summary, 'Send 2.014 ETH to 0xfb69 … c5d359');
  // EIP-681's example mixes case without a valid EIP-55 checksum (the checksummed form is 0xfB69…bB79…).
  assertWarning(a, 'danger', /EIP-55/);
  assertNoWarning(analyze('ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1'), 'danger');
});

test('EIP-681 ERC-20 transfer: recipient is the address parameter', () => {
  const a = analyze('ethereum:0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7/transfer?address=0x8e23ee67d1332ad560396262c48ffbb01f93d052&uint256=1');
  assert.equal(a.data.tokenContract, '0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7');
  assert.equal(a.data.recipient, '0x8e23ee67d1332ad560396262c48ffbb01f93d052');
  assert.equal(a.data.tokenAmount, '1');
  assertWarning(a, 'caution', /token contract, not the recipient/);
  assert.equal(action(a, /Copy address/).value, '0x8e23ee67d1332ad560396262c48ffbb01f93d052');
  assert.match(a.summary, /^Token transfer: send 1 units of token .* to 0x8e/);
});

test('EIP-681 chain id, approve danger, other calls, ENS, bare address', () => {
  const p = analyze('ethereum:pay-0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359@137?value=1e18');
  assert.equal(p.data.chainId, 137);
  assert.equal(p.data.network, 'Polygon');
  assert.equal(p.data.amount, '1');
  assert.match(p.summary, /1 POL/);
  assertWarning(analyze('ethereum:0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7/approve?address=0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef&uint256=1e77'), 'danger', /permission to spend/);
  assertWarning(analyze('ethereum:0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7/mint?uint256=1'), 'caution', /"mint"/);
  assertWarning(analyze('ethereum:vitalik.eth?value=1'), 'info', /resolves it/);
  assertWarning(analyze('ethereum:0x123?value=1'), 'caution', /not a valid Ethereum address/);
  assertWarning(analyze('ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1.5'), 'caution', /whole number of wei/);
  assertWarning(analyze('ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359@999?value=1'), 'info', /Unknown chain/);
  const bare = analyze('0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
  assert.equal(bare.data.format, 'evm-address');
  assertWarning(bare, 'info', /network unknown/);
});

test('Monero, Solana, TON, Litecoin, Dogecoin, generic schemes', () => {
  const xmrAddr = '4' + 'A'.repeat(94);
  const m = analyze(`monero:${xmrAddr}?tx_amount=0.25&recipient_name=Shop&tx_payment_id=abc`);
  assert.equal(m.data.amount, '0.25');
  assertWarning(m, 'info', /payment ID/);

  const sol = analyze('solana:9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM?amount=1.5&label=Shop&memo=x');
  assert.equal(sol.data.kind, 'transfer');
  assert.equal(sol.data.amount, '1.5');
  assertNoWarning(sol, 'caution');
  const req = analyze('solana:https%3A%2F%2Fpay.example%2Ftx%3Fid%3D1');
  assert.equal(req.data.kind, 'transaction-request');
  assertWarning(req, 'caution', /load a transaction from pay\.example/);

  const ton = analyze('ton://transfer/EQD4FPq-PRDieyQKkizFTRtSDyucUIqrj0v_zXJmqaDp6_0t?amount=1500000000&text=hi');
  assert.equal(ton.data.amount, '1.5');
  assertNoWarning(ton, 'caution');

  const ltc = analyze('litecoin:ltc1qg42tkwuuxefutzxezdkdel39gfstuap288mfea?amount=1');
  assert.equal(ltc.data.network, 'Litecoin');
  assert.equal(ltc.data.amount, '1');
  assertNoWarning(ltc, 'danger');
  assert.equal(analyze('dogecoin:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L?amount=10').data.addressValid, true);
  const xrp = analyze('xrpl:rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY?amount=5');
  assert.equal(xrp.data.network, 'XRP Ledger');
  assertWarning(xrp, 'info', /not verified/);
});

test('crypto parser never throws on malformed input', () => {
  fuzz('bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.1&label=a&req-x=1&lightning=lnbc1x&pj=https://x');
  fuzz('ethereum:pay-0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359@137/transfer?address=0x8e23ee67d1332ad560396262c48ffbb01f93d052&uint256=1e3');
  fuzz(`lightning:${makeInvoice('lnbc2500u', { description: 'x', expiry: 9 })}`, { step: 9 });
  fuzz('solana:https%3A%2F%2Fpay.example%2Ftx');
  fuzz('ton://transfer/EQD4FPq-PRDieyQKkizFTRtSDyucUIqrj0v_zXJmqaDp6_0t?amount=15');
});

test('address grouping: 0x + 10 groups of 4 for EVM, no 1–2 character fragments', async () => {
  const { groupAddress, groupBalanced, group } = await import('../../src/renderer/parsers/formats/util.js');
  const erc20 = analyze('ethereum:0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7/transfer?address=0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed&uint256=1');
  assert.equal(field(erc20, 'Recipient').value, '0x 5aAe b605 3F3E 94C9 b9A0 9f33 6694 35E7 Ef1B eAed');
  assert.equal(field(analyze('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'), 'To').value, '0x 5aAe b605 3F3E 94C9 b9A0 9f33 6694 35E7 Ef1B eAed');
  // bech32: hrp + separator split off, then 4s (39 data chars → 9×4 + 3).
  assert.equal(field(analyze('bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'), 'Address').value, 'bc1 qar0 srrr 7xfk vy5l 643l ydnw 9re5 9gtz zwf5 mdq');
  assert.equal(groupAddress('BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ'), 'BC1 QAR0 SRRR 7XFK VY5L 643L YDNW 9RE5 9GTZ ZWF5 MDQ');
  // base58 (34 chars → remainder 2 → two groups of 3 at the end, not "… pyT" + "T").
  assert.equal(groupAddress('1BoatSLRHtKNngkdXEeobR76b53LETtpyT'), '1Boa tSLR HtKN ngkd XEeo bR76 b53L ETt pyT');
  for (const s of ['A'.repeat(33), 'A'.repeat(34), 'A'.repeat(35), 'A'.repeat(44), 'A'.repeat(95), 'A'.repeat(7), 'A'.repeat(5)]) {
    const parts = groupBalanced(s).split(' ');
    assert.equal(parts.join(''), s);
    assert.ok(parts.every((p) => p.length >= 3 && p.length <= 4) || s.length <= 6, `${s.length}: ${parts.map((p) => p.length)}`);
  }
  assert.equal(groupBalanced('ABCDEF'), 'ABCD EF'); // too short to rebalance
  // IBAN stays plain groups of 4 with the remainder at the end.
  assert.equal(group('DE89370400440532013000', 4), 'DE89 3704 0044 0532 0130 00');
});

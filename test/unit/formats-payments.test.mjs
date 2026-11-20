import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, assertClean, field, action, fuzz } from './_formats-helper.mjs';
import { checkIban, checkRfReference, checkQrReference, mod10Recursive, normalizeAmount, isBic } from '../../src/renderer/parsers/formats/banking.js';
import { crc16ccitt } from '../../src/renderer/parsers/formats/codecs.js';

const latin1 = (s) => Uint8Array.from(Array.from(s, (c) => c.charCodeAt(0)));

test('validators: IBAN, RF, QR reference, BIC, amounts, CRC', () => {
  for (const iban of ['DE71110220330123456789', 'FR1420041010050500013M02606', 'DE89370400440532013000', 'CH9300762011623852957', 'CH4431999123000889012']) {
    assert.equal(checkIban(iban).valid, true, iban);
  }
  assert.equal(checkIban('DE89370400440532013001').valid, false);
  assert.equal(checkIban('de89 3704 0044 0532 0130 00').valid, true);
  assert.equal(checkIban('DE8937040044053201300').valid, false, 'wrong length for DE');
  assert.equal(checkIban('DE89370400440532013000').display, 'DE89 3704 0044 0532 0130 00');
  assert.equal(checkRfReference('RF18539007547034'), true);
  assert.equal(checkRfReference('RF19539007547034'), false);
  assert.equal(mod10Recursive('21000000000313947143000901'), 7);
  assert.equal(checkQrReference('210000000003139471430009017'), true);
  assert.equal(checkQrReference('210000000003139471430009018'), false);
  assert.equal(isBic('BHBLDEHHXXX'), true);
  assert.equal(isBic('BHBLDEH'), false);
  assert.equal(normalizeAmount('12.3'), '12.30');
  assert.equal(normalizeAmount('9,90', { decimal: ',' }), '9.90');
  assert.equal(normalizeAmount('1.234'), null);
  assert.equal(crc16ccitt(new TextEncoder().encode('123456789')).toString(16).toUpperCase(), '29B1');
});

// --- EPC -------------------------------------------------------------------

test('EPC v001 (UTF-8) — spec example', () => {
  const a = analyze('BCD\n001\n1\nSCT\nBHBLDEHHXXX\nFranz Mustermänn\nDE71110220330123456789\nEUR12.3\nGDDS\nRF18539007547034');
  assert.equal(a.type, 'epc-payment');
  assert.equal(a.data.format, 'epc');
  const pick = (({ version, charset, bic, name, iban, ibanValid, amount, currency, purpose, reference, referenceValid }) => ({ version, charset, bic, name, iban, ibanValid, amount, currency, purpose, reference, referenceValid }))(a.data);
  assert.deepEqual(pick, { version: '001', charset: 1, bic: 'BHBLDEHHXXX', name: 'Franz Mustermänn', iban: 'DE71110220330123456789', ibanValid: true, amount: '12.30', currency: 'EUR', purpose: 'GDDS', reference: 'RF18539007547034', referenceValid: true });
  assertClean(a);
  assertWarning(a, 'info', /banking app/);
  assert.equal(a.summary, 'Pay €12.30 to Franz Mustermänn');
  assert.equal(action(a, /Copy IBAN/).value, 'DE71110220330123456789');
  assert.ok(!a.actions.some((x) => x.kind === 'open'));
});

test('EPC v002 ISO-8859-1 decoded from bytes', () => {
  const payload = "BCD\n002\n2\nSCT\n\nFrançois D'Alsace S.A.\nFR1420041010050500013M02606\nEUR12.3\n\n\nClient:Marie Louise La Lune";
  const bytes = latin1(payload);
  assert.equal(bytes.length, 103);
  const visionText = new TextDecoder('utf-8').decode(bytes); // the wrong guess: "Fran�ois"
  const a = analyze(visionText, { bytes, bytesKind: 'payload' });
  assert.equal(a.data.version, '002');
  assert.equal(a.data.charset, 2);
  assert.equal(a.data.name, "François D'Alsace S.A.");
  assert.equal(a.data.bic, '');
  assert.equal(a.data.amount, '12.30');
  assert.equal(a.data.text, 'Client:Marie Louise La Lune');
  assertClean(a);
  // Without bytes: info that the decoding is unverified.
  assertWarning(analyze(payload), 'info', /not verified/);
  // Raw (non-payload) bytes are ignored.
  assertWarning(analyze(payload, { bytes, bytesKind: 'raw' }), 'info', /not verified/);
});

test('EPC with CRLF, invalid IBAN, both remittance kinds', () => {
  const a = analyze('BCD\r\n002\r\n1\r\nSCT\r\n\r\nShop\r\nDE89370400440532013001\r\nEUR5\r\n\r\nRF18539007547034\r\nalso text');
  assert.equal(a.data.name, 'Shop');
  assert.equal(a.data.amount, '5.00');
  assertWarning(a, 'danger', /IBAN checksum invalid/);
  assertWarning(a, 'caution', /Both a structured reference/);
});

test('EPC v001 missing BIC, non-EUR', () => {
  const a = analyze('BCD\n001\n1\nSCT\n\nX\nDE89370400440532013000\nUSD10');
  assertWarning(a, 'caution', /requires the BIC/);
  assertWarning(a, 'caution', /USD/);
});

test('EPC other validation and detection', () => {
  assert.equal(analyze('BCD\n002\n1\nXCT\n\nX\nDE89370400440532013000'), null, 'line 4 must be SCT');
  assert.equal(analyze('bcd\n002\n1\nSCT'), null, 'BCD must be uppercase');
  assertWarning(analyze('BCD\n003\n9\nSCT\n\nX\nDE89370400440532013000'), 'caution', /version/);
  assertWarning(analyze('BCD\n003\n9\nSCT\n\nX\nDE89370400440532013000'), 'caution', /character set/);
  assertWarning(analyze('BCD\n002\n1\nSCT\n\nX\nDE89370400440532013000\nEUR1,50'), 'caution', /Invalid amount/);
  assertWarning(analyze('BCD\n002\n1\nSCT\n\nX\nDE89370400440532013000\nEUR1\n\nRF00539007547034'), 'caution', /check digits/);
  assertWarning(analyze(`BCD\n002\n1\nSCT\n\n${'N'.repeat(71)}\nDE89370400440532013000`), 'caution', /longer than allowed/);
  assertWarning(analyze('BCD\n002\n1\nSCT\n\nPay​pal\nDE89370400440532013000'), 'caution', /^Beneficiary: /);
  assertWarning(analyze('BCD\n002\n1\nSCT\n\nX\nDE89370400440532013000\n\n\n\n\n\nextra'), 'caution', /extra lines/);
  // The real-world fixture (trailing LF) parses cleanly.
  assertClean(analyze('BCD\n002\n1\nSCT\nBPOTBEB1\nRed Cross of Belgium\nBE72000000001616\nEUR12.50\nCHAR\n\nUrgency fund\n'));
});

// --- Swiss QR-bill ----------------------------------------------------------

const swiss = ({ iban = 'CH4431999123000889012', adrTp = 'S', amount = '1949.75', refType = 'QRR', ref = '210000000003139471430009017', ultimate = ['', '', '', '', '', '', ''], trailer = 'EPD', sep = '\n' } = {}) => [
  'SPC', '0200', '1', iban, adrTp, 'Robert Schneider AG', 'Rue du Lac', '1268', '2501', 'Biel', 'CH',
  ...ultimate, amount, 'CHF',
  'S', 'Pia-Maria Rutschmann-Schnyder', 'Grosse Marktgasse', '28', '9400', 'Rorschach', 'CH',
  refType, ref, 'Order of 15 June 2020', trailer,
  '//S1/10/10201409/11/200701/20/140.000-53/30/102673831/31/200615/32/7.7/33/7.7:5.09/40/0:30',
  'eBill/B/john.doe@example.com',
].join(sep);

test('Swiss QR-bill spec example', () => {
  const a = analyze(swiss());
  assert.equal(a.type, 'swiss-qr-bill');
  const d = a.data;
  assert.equal(d.iban, 'CH4431999123000889012');
  assert.equal(d.qrIban, true);
  assert.equal(d.ibanValid, true);
  assert.deepEqual(d.creditor, { addressType: 'S', name: 'Robert Schneider AG', street: 'Rue du Lac', building: '1268', postcode: '2501', town: 'Biel', country: 'CH' });
  assert.equal(d.amount, '1949.75');
  assert.equal(d.currency, 'CHF');
  assert.equal(d.debtor.name, 'Pia-Maria Rutschmann-Schnyder');
  assert.equal(d.refType, 'QRR');
  assert.equal(d.reference, '210000000003139471430009017');
  assert.equal(d.referenceValid, true);
  assert.equal(d.message, 'Order of 15 June 2020');
  assert.match(d.billInfo, /^\/\/S1\//);
  assert.deepEqual(d.altProcedures, ['eBill/B/john.doe@example.com']);
  assert.equal(field(a, 'QR reference').value, '21 00000 00003 13947 14300 09017');
  assert.equal(a.summary, 'Pay CHF 1,949.75 to Robert Schneider AG');
  assertClean(a);
  assertClean(analyze(swiss({ sep: '\r\n' })));
});

test('Swiss QR-bill tricky variants', () => {
  assertWarning(analyze(swiss({ iban: 'CH9300762011623852957' })), 'danger', /doesn't match the account type/);
  assertClean(analyze(swiss({ iban: 'CH9300762011623852957', refType: 'SCOR', ref: 'RF18539007547034' })));
  assertWarning(analyze(swiss({ refType: 'SCOR', ref: 'RF18539007547034' })), 'danger', /QR-IBAN requires/);
  assertWarning(analyze(swiss({ amount: '' })), 'info', /entered by the payer/);
  assertWarning(analyze(swiss({ adrTp: 'K' })), 'info', /Outdated address format/);
  assertWarning(analyze(swiss({ ref: '210000000003139471430009018' })), 'danger', /check digit/);
  assertWarning(analyze(swiss({ iban: 'CH4431999123000889013' })), 'danger', /IBAN checksum/);
  assertWarning(analyze(swiss({ trailer: '' })), 'caution', /Not a complete QR-bill/);
  assertWarning(analyze(swiss({ ultimate: ['S', 'X', '', '', '1000', 'Bern', 'CH'] })), 'caution', /ultimate creditor/);
  assertWarning(analyze(swiss({ amount: '12.5' })), 'caution', /Invalid amount/);
  assertWarning(analyze(swiss({ iban: 'CH9300762011623852957', refType: 'NON', ref: 'x' })), 'caution', /NON but a reference/);
  assertWarning(analyze(swiss().replace('Biel', 'Biel ✓')), 'caution', /not allowed/);
  assertWarning(analyze('SPC\n0100\n2'), 'caution', /version/);
});

// --- SPD --------------------------------------------------------------------

test('Czech SPD vectors', () => {
  const a = analyze('SPD*1.0*ACC:CZ9106000000000000000123*AM:450.00*CC:CZK*MSG:PLATBA ZA ZBOZI*X-VS:1234567890');
  assert.equal(a.type, 'payment');
  assert.equal(a.data.format, 'spd');
  assert.equal(a.data.iban, 'CZ9106000000000000000123');
  assert.equal(a.data.amount, '450.00');
  assert.equal(a.data.currency, 'CZK');
  assert.equal(a.data.message, 'PLATBA ZA ZBOZI');
  assert.equal(a.data.vs, '1234567890');
  assert.equal(a.data.ibanValid, true);
  assertClean(a);

  const b = analyze('SPD*1.0*ACC:CZ5855000000001265098001+RZBCCZPP*AM:480.50*CC:CZK*RN:FIRMA%2A S.R.O.*DT:20261231');
  assert.equal(b.data.bic, 'RZBCCZPP');
  assert.equal(b.data.name, 'FIRMA* S.R.O.');
  assert.equal(b.data.dueDate, '2026-12-31');
  assertWarning(analyze('SPD*1.0*AM:1.00'), 'caution', /ACC/);
  assertWarning(analyze('SPD*1.0*ACC:CZ9106000000000000000124'), 'danger', /IBAN/);
  assertWarning(analyze('SPD*1.0*ACC:CZ9106000000000000000123*X-URL:http://x.example'), 'caution', /Link/);
  assert.equal(analyze('SPD*1.0*ACC:CZ9106000000000000000123').data.currency, 'CZK');
});

// --- EMVCo / Pix ------------------------------------------------------------

const PIX_STATIC = '00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-4266554400005204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***63041D3D';

test('Pix static (BCB manual example)', () => {
  const a = analyze(PIX_STATIC);
  assert.equal(a.type, 'payment');
  assert.equal(a.data.format, 'pix');
  assert.equal(a.data.dynamic, false);
  assert.equal(a.data.pixKey, '123e4567-e12b-12d1-a456-426655440000');
  assert.equal(a.data.pixKeyKind, 'random');
  assert.equal(a.data.currency, 'BRL');
  assert.equal(a.data.merchantName, 'Fulano de Tal');
  assert.equal(a.data.merchantCity, 'BRASILIA');
  assert.equal(a.data.txid, '***');
  assert.equal(a.data.crcValid, true);
  assert.equal(a.data.crc, '1D3D');
  assertClean(a);
  assertWarning(a, 'info', /entered by the payer/);
});

test('Pix with amount; tampered amount fails CRC', () => {
  const ok = analyze('00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-426655440000520400005303986540510.005802BR5913Fulano de Tal6008BRASILIA62070503***6304288F');
  assert.equal(ok.data.amount, '10.00');
  assert.equal(ok.data.crcValid, true);
  assert.equal(ok.summary, 'Pay R$ 10.00 to Fulano de Tal (Pix)');
  const bad = analyze('00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-426655440000520400005303986540599.005802BR5913Fulano de Tal6008BRASILIA62070503***6304288F');
  assert.equal(bad.data.amount, '99.00');
  assertWarning(bad, 'danger', /Checksum wrong/);
});

test('Pix dynamic with URL', () => {
  const a = analyze('00020101021226830014br.gov.bcb.pix2561qrpix.example.com/qr/v2/cobv/9d36b84fc70b478fb95c12729b90ca25520400005303986540525.505802BR5912EXEMPLO LTDA6009SAO PAULO62070503***63048E28');
  assert.equal(a.data.dynamic, true);
  assert.equal(a.data.pointOfInitiation, 'dynamic');
  assert.equal(a.data.url, 'qrpix.example.com/qr/v2/cobv/9d36b84fc70b478fb95c12729b90ca25');
  assert.equal(a.data.amount, '25.50');
  assert.equal(a.data.crcValid, true);
  assertWarning(a, 'info', /fetched by your bank app from qrpix\.example\.com/);
});

test('EMV detection requires a valid TLV structure; other schemes; lowercase CRC', () => {
  assert.equal(analyze('000201 hello'), null);
  assert.equal(analyze('0002010102'), null, 'no CRC field');
  assert.equal(analyze(PIX_STATIC.slice(0, -1)), null, 'CRC must be 4 chars');
  const lower = analyze(PIX_STATIC.replace(/1D3D$/, '1d3d'));
  assert.equal(lower.data.crcValid, true);
  assertWarning(lower, 'info', /lowercase/);
  // Construct a PayNow-like payload with a correct CRC.
  const tpl = '0009SG.PAYNOW' + '01012' + '0208R1234567';
  const body = '000201010212' + `26${tpl.length}` + tpl + '52040000' + '5303702' + '54041.50' + '5802SG' + '5905SHOPX' + '6009SINGAPORE' + '6304';
  const crc = crc16ccitt(new TextEncoder().encode(body)).toString(16).toUpperCase().padStart(4, '0');
  const a = analyze(body + crc);
  assert.equal(a.data.format, 'emv');
  assert.equal(a.data.scheme, 'PayNow');
  assert.equal(a.data.currency, 'SGD');
  assert.equal(a.data.amount, '1.50');
  assert.equal(a.data.dynamic, true);
});

test('EMV with non-ASCII merchant name (byte-counted lengths) and invisible characters', () => {
  const body = '000201' + '26180014br.gov.bcb.pix' + '5303986' + '5802BR' + '5906João' + '6304';
  // LEN 06 counts UTF-8 bytes of "João" + nothing: 'Jo' 2 + 'ã' 2 + 'o' 1 = 5 → use 6 chars incorrectly? Build both forms.
  const cp = '000201' + '26180014br.gov.bcb.pix' + '5303986' + '5802BR' + '5904João' + '6304';
  const crc = (s) => crc16ccitt(new TextEncoder().encode(s)).toString(16).toUpperCase().padStart(4, '0');
  const a = analyze(cp + crc(cp));
  assert.equal(a.data.merchantName, 'João');
  const bytes = '000201' + '26180014br.gov.bcb.pix' + '5303986' + '5802BR' + '5905João' + '6304';
  const b = analyze(bytes + crc(bytes));
  assert.equal(b.data.merchantName, 'João');
  assertWarning(b, 'info', /count bytes/);
  const inv = '000201' + '26180014br.gov.bcb.pix' + '5303986' + '5802BR' + '5905Sh​op' + '6304';
  assertWarning(analyze(inv + crc(inv)), 'caution', /^Merchant: /);
});

// --- UPI --------------------------------------------------------------------

test('UPI vectors', () => {
  const a = analyze('upi://pay?pa=merchant@okaxis&pn=Example%20Store&am=150.00&cu=INR&tn=Order%2042&tr=ORD42');
  assert.equal(a.type, 'payment');
  const { vpa, name, amount, currency, note, ref } = a.data;
  assert.deepEqual({ vpa, name, amount, currency, note, ref }, { vpa: 'merchant@okaxis', name: 'Example Store', amount: '150.00', currency: 'INR', note: 'Order 42', ref: 'ORD42' });
  assertClean(a);
  assertWarning(a, 'info', /registered name/);
  assertWarning(a, 'info', /SENDS money/);
  assert.equal(a.summary, 'Pay ₹150.00 to Example Store (merchant@okaxis)');

  assertWarning(analyze('UPI://PAY?pa=a.b-c@ybl'), 'info', /entered by the payer/);
  assertWarning(analyze('upi://pay?pn=X'), 'caution', /missing/);
  assertWarning(analyze('upi://mandate?pa=a@ybl&am=100'), 'caution', /recurring/);
  assertWarning(analyze('upi://pay?pa=a@ybl&am=1&cu=USD'), 'caution', /INR/);
  assertWarning(analyze('upi://pay?pa=a@ybl&url=http://x.example'), 'caution', /Info link/);
});

// --- Bezahlcode -------------------------------------------------------------

test('Bezahlcode vector', () => {
  const a = analyze('bank://singlepaymentsepa?name=Max%20Muster&reason=Rechnung%2012&iban=DE89370400440532013000&bic=COBADEFFXXX&amount=9,90');
  assert.equal(a.data.format, 'bezahlcode');
  const { name, iban, bic, amount, currency, reason } = a.data;
  assert.deepEqual({ name, iban, bic, amount, currency, reason }, { name: 'Max Muster', iban: 'DE89370400440532013000', bic: 'COBADEFFXXX', amount: '9.90', currency: 'EUR', reason: 'Rechnung 12' });
  assertClean(a);
  assertWarning(analyze('bank://singledirectdebitsepa?name=X&iban=DE89370400440532013000'), 'caution', /direct debit/);
  assertWarning(analyze('bank://singlepaymentsepa?iban=DE89370400440532013001'), 'danger', /IBAN/);
  assert.equal(analyze('bank://singlepayment?name=X&account=123&bnc=37040044&executiondate=31122026').data.executionDate, '2026-12-31');
});

test('payment parsers never throw on malformed input', () => {
  fuzz('BCD\n001\n1\nSCT\nBHBLDEHHXXX\nFranz Mustermänn\nDE71110220330123456789\nEUR12.3\nGDDS\nRF18539007547034', { step: 3 });
  fuzz(swiss(), { step: 11 });
  fuzz('SPD*1.0*ACC:CZ5855000000001265098001+RZBCCZPP*AM:480.50*CC:CZK*RN:FIRMA%2A*DT:20261231*CRC32:1234ABCD');
  fuzz(PIX_STATIC, { step: 2 });
  fuzz('upi://pay?pa=merchant@okaxis&pn=Example%20Store&am=150.00&cu=INR');
  fuzz('bank://singlepaymentsepa?name=Max%20Muster&iban=DE89370400440532013000&amount=9,90&executiondate=01012026');
});

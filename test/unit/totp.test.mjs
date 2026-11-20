import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateOtp, otpTimeStep } from '../../src/renderer/parsers/totp.js';

const enc = (s) => new TextEncoder().encode(s);

test('RFC 4226 Appendix D (HOTP, SHA-1, 6 digits, counters 0–9)', async () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  for (let c = 0; c < 10; c++) {
    assert.equal(await generateOtp({ secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', counter: c }), expected[c]);
    assert.equal(await generateOtp({ secret: enc('12345678901234567890'), counter: BigInt(c) }), expected[c]);
  }
});

test('RFC 6238 Appendix B (TOTP, 8 digits, SHA-1/256/512)', async () => {
  const keys = {
    SHA1: enc('12345678901234567890'),
    SHA256: enc('12345678901234567890123456789012'),
    SHA512: enc('1234567890123456789012345678901234567890123456789012345678901234'),
  };
  const table = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [t, sha1, sha256, sha512] of table) {
    assert.equal(await generateOtp({ secret: keys.SHA1, algorithm: 'SHA1', digits: 8 }, t * 1000), sha1, `SHA1 t=${t}`);
    assert.equal(await generateOtp({ secret: keys.SHA256, algorithm: 'SHA256', digits: 8 }, t * 1000), sha256, `SHA256 t=${t}`);
    assert.equal(await generateOtp({ secret: keys.SHA512, algorithm: 'SHA512', digits: 8 }, t * 1000), sha512, `SHA512 t=${t}`);
  }
});

test('extra vectors for JBSWY3DPEHPK3PXP', async () => {
  const secret = 'JBSWY3DPEHPK3PXP';
  assert.equal(await generateOtp({ secret }, 0), '282760');
  assert.equal(await generateOtp({ secret }, 59000), '996554');
  assert.equal(await generateOtp({ secret }, 1700000000000), '324550');
  assert.equal(await generateOtp({ secret, digits: 8 }, 1700000000000), '02324550');
  assert.equal(await generateOtp({ secret, period: 60 }, 1700000000000), '508648');
  assert.equal(await generateOtp({ secret: 'jbsw y3dp ehpk 3pxp====' }, 59000), '996554', 'lenient base32');
  assert.equal(await generateOtp({ secret, algorithm: 'sha-1' }, 59000), '996554');
});

test('time step helper', () => {
  assert.deepEqual(otpTimeStep(30, 59000), { counter: 1, secondsRemaining: 1 });
  assert.deepEqual(otpTimeStep(30, 60000), { counter: 2, secondsRemaining: 30 });
  assert.deepEqual(otpTimeStep(0, 60000), { counter: 2, secondsRemaining: 30 }, 'invalid period falls back to 30');
});

test('errors for unsupported input', async () => {
  await assert.rejects(generateOtp({ secret: 'JBSWY3DPEHPK3PXP', algorithm: 'MD5' }), /Unsupported OTP algorithm/);
  await assert.rejects(generateOtp({ secret: 'ABC1' }), /base32/);
  await assert.rejects(generateOtp({ secret: '' }), /Empty/);
  await assert.rejects(generateOtp({ secret: 'JBSWY3DP', digits: 0 }), /digit/);
  await assert.rejects(generateOtp({ secret: 'JBSWY3DP', counter: -1 }), /Counter/);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, assertClean, field, action, fuzz } from './_formats-helper.mjs';

test('WIFI basic (ZXing dialect)', () => {
  const a = analyze('WIFI:T:WPA;S:mynetwork;P:mypass;;');
  assert.equal(a.type, 'wifi');
  assert.equal(a.data.format, 'wifi-zxing');
  assert.equal(a.data.ssid, 'mynetwork');
  assert.equal(a.data.auth, 'WPA');
  assert.equal(a.data.password, 'mypass');
  assert.equal(a.data.hidden, false);
  assert.equal(field(a, 'Password').sensitive, true);
  assert.equal(action(a, /password/).sensitive, true);
  assert.ok(action(a, /network name/));
  assert.ok(!a.actions.some((x) => x.kind === 'open'), 'no join/open action');
  assertWarning(a, 'caution', /password length/); // 6 chars is too short for WPA
  assert.match(a.summary, /mynetwork/);
});

test('WIFI backslash escapes, any field order, hidden', () => {
  const a = analyze('WIFI:S:My\\;Net\\\\;T:WPA;P:pa\\:ss\\,\\"word;H:true;;');
  assert.equal(a.data.ssid, 'My;Net\\');
  assert.equal(a.data.password, 'pa:ss,"word');
  assert.equal(a.data.hidden, true);
  assertClean(a);
});

test('WIFI T:SAE is WPA3-Personal without warnings', () => {
  const a = analyze('WIFI:T:SAE;S:Home;P:correct horse;;');
  assert.equal(a.data.auth, 'SAE');
  assert.match(field(a, 'Security').value, /WPA3-Personal/);
  assertClean(a);
});

test('WIFI WPA3 percent-encoding dialect', () => {
  const a = analyze('WIFI:T:WPA;R:1;S:Caf%C3%A9;P:p%3Bss;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAD;;');
  assert.equal(a.data.format, 'wifi-wpa3');
  assert.equal(a.data.ssid, 'Café');
  assert.equal(a.data.password, 'p;ss');
  assert.equal(a.data.transitionDisable, '0x1');
  assert.equal(a.data.saePk, true);
  assert.match(a.data.saePkFingerprint, /^[0-9a-f]{16}$/);
  assertWarning(a, 'caution', /ambiguous.*Caf%C3%A9/);
});

test('WIFI quoted SSID is text, unquoted hex SSID gets a note', () => {
  const q = analyze('WIFI:S:"4142";T:WPA;P:12345678;;');
  assert.equal(q.data.ssid, '4142');
  assertNoWarning(q, 'info', /hex/);
  const h = analyze('WIFI:S:4142;T:nopass;;');
  assert.equal(h.data.ssid, '4142');
  assertWarning(h, 'info', /hex-encoded.*"AB"/);
  assertWarning(h, 'caution', /Open network/);
  assertWarning(h, 'info', /trust/);
});

test('WIFI WEP is danger', () => {
  const a = analyze('WIFI:T:WEP;S:old;P:abcde;;');
  assertWarning(a, 'danger', /WEP/);
  assertNoWarning(a, 'caution', /WEP key length/);
});

test('WIFI enterprise (EAP) fields', () => {
  const a = analyze('WIFI:T:WPA2-EAP;S:corp;E:PEAP;PH2:MSCHAPV2;A:anon;I:alice;P:pw;;');
  assert.deepEqual(a.data.eap, { method: 'PEAP', phase2: 'MSCHAPV2', anonymousIdentity: 'anon', identity: 'alice' });
  assert.match(field(a, 'Security').value, /Enterprise/);
  assertNoWarning(a, 'caution', /password length/);
});

test('WIFI SSID with zero-width space; unterminated', () => {
  const a = analyze('WIFI:T:WPA;S:Free​WiFi;P:12345678');
  assert.equal(a.data.ssid, 'Free​WiFi');
  assertWarning(a, 'caution', /Network name.*(zero-width|hidden)/i);
  assertWarning(a, 'info', /terminated/);
});

test('WIFI mixed-script SSID is flagged', () => {
  const a = analyze('WIFI:T:WPA;S:Stаrbucks;P:12345678;;'); // Cyrillic а
  assertWarning(a, 'caution', /mixes Latin and Cyrillic/);
});

test('WIFI edge cases: missing T, duplicate keys, SSID > 32 bytes, raw PSK, lowercase prefix', () => {
  assert.equal(analyze('wifi:S:x;P:12345678;;').data.auth, 'WPA');
  assert.equal(analyze('WIFI:S:x;;').data.auth, 'nopass');
  assertWarning(analyze('WIFI:S:a;S:b;T:nopass;;'), 'caution', /Duplicate field S/);
  assertWarning(analyze(`WIFI:S:${'é'.repeat(17)};T:nopass;;`), 'caution', /34 bytes/);
  assertWarning(analyze(`WIFI:S:x;T:WPA;P:${'ab'.repeat(32)};;`), 'info', /pre-shared key/);
  assertWarning(analyze('WIFI:T:WPA;P:12345678;;'), 'caution', /Missing network name/);
  assertWarning(analyze('WIFI:T:WPA;S:x;Z:1;;'), 'info', /Unknown field "Z"/);
  assertWarning(analyze('WIFI:T:WPA;S:x;;'), 'caution', /Missing password/);
});

test('DPP bootstrap URI', () => {
  const a = analyze('DPP:C:81/1;M:44d43771bb2e;V:2;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAD5ANLCEXDDO7vnLVgSDoiJJ5H2Mo7aPXVriSVZ0ygP7M=;;');
  assert.equal(a.type, 'wifi');
  assert.equal(a.data.format, 'dpp');
  assert.deepEqual(a.data.channels, ['81/1']);
  assert.equal(a.data.mac, '44:d4:37:71:bb:2e');
  assert.equal(a.data.version, 2);
  assert.match(a.data.publicKeyB64, /^MDkw/);
  assert.equal(a.data.curve, 'P-256');
  assert.equal(a.summary, 'Wi-Fi Easy Connect device (DPP v2)');
  assertWarning(a, 'info', /setting up a device/);
  assertWarning(analyze('DPP:C:81/1;M:44d43771bb2e;;'), 'caution', /public key/);
});

test('Wi-Fi parsers never throw on malformed input', () => {
  fuzz('WIFI:T:WPA;R:1;S:Caf%C3%A9;P:p%3Bss;K:MDkw;H:true;;');
  fuzz('WIFI:S:"q\\"x";T:WEP;P:abcde;I:id;E:TLS;;', { step: 2 });
  fuzz('DPP:C:81/1,115/36;M:44d43771bb2e;I:SN=4774;V:2;K:MDkwEwYHKoZIzj0CAQ==;;');
});

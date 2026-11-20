// URL analysis (PAYLOADS.md §2): every spec vector plus adversarial cases.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, detectUrl, analyzeDomain, gtinValid, KNOWN_SCHEMES } from '../../src/renderer/parsers/url.js';

const has = (a, level, re) => a.warnings.some((w) => w.level === level && re.test(w.message));
const none = (a, level) => !a.warnings.some((w) => w.level === level);
const opens = (a) => a.actions.some((x) => x.kind === 'open');

// ---- spec vectors (§2.8 table)
test('https://example.com/ → clean, openable', () => {
  const a = analyzeUrl('https://example.com/');
  assert.equal(a.type, 'url');
  assert.equal(a.data.registrableDomain, 'example.com');
  assert.deepEqual(a.warnings, []);
  assert.ok(opens(a));
  assert.ok(a.actions.some((x) => x.kind === 'copy' && x.value === 'https://example.com/'));
  assert.equal(a.data.openable, true);
  assert.equal(a.data.notOpenableReason, null);
  assert.equal(a.data.hostKind, 'domain');
  assert.equal(a.data.scheme, 'https');
});

test('uppercase scheme/host normalised, path/query case kept', () => {
  const a = analyzeUrl('HTTPS://EXAMPLE.COM/A?b=C');
  assert.equal(a.data.href, 'https://example.com/A?b=C');
  assert.deepEqual(a.data.query.map((q) => [q.name, q.value]), [['b', 'C']]);
});

test('Cyrillic а in paypal → mixed script + imitates paypal', () => {
  const a = analyzeUrl('https://pаypal.com/login');
  assert.equal(a.data.host, 'xn--pypal-4ve.com');
  assert.equal(a.data.hostUnicode, 'pаypal.com');
  assert.ok(has(a, 'danger', /mixes .*Latin.*Cyrillic|mixes .*Cyrillic.*Latin/));
  assert.ok(has(a, 'danger', /imitates paypal/));
  assert.ok(has(a, 'info', /Internationalised/));
  assert.ok(a.fields.some((f) => f.label === 'Host (ACE)' && f.value === 'xn--pypal-4ve.com'));
});

test('all-Cyrillic аррӏе.com → whole-script confusable "apple"', () => {
  const a = analyzeUrl('https://аррӏе.com/');
  assert.equal(a.data.host, 'xn--80ak6aa92e.com');
  assert.ok(has(a, 'danger', /looks like the Latin word "apple"/));
});

test('userinfo before @ → danger, host is evil.example', () => {
  const a = analyzeUrl('https://www.paypal.com@evil.example/');
  assert.equal(a.data.host, 'evil.example');
  assert.equal(a.data.username, 'www.paypal.com');
  assert.ok(has(a, 'danger', /before "@".*evil\.example/));
});

test('CVE-2018-4187 backslash differential → danger, no Open', () => {
  const a = analyzeUrl('https://xxx\\@facebook.com:443@infosec.rm-it.com/');
  assert.equal(a.data.host, 'xxx');
  assert.ok(has(a, 'danger', /backslash/));
  assert.ok(has(a, 'danger', /infosec\.rm-it\.com/));
  assert.equal(a.data.openable, false);
  assert.ok(!opens(a));
  assert.ok(a.data.differential);
});

test('decimal IPv4 → obfuscated + IP + local + http', () => {
  const a = analyzeUrl('http://3232235777/');
  assert.equal(a.data.host, '192.168.1.1');
  assert.equal(a.data.hostKind, 'ipv4');
  assert.ok(has(a, 'danger', /Obfuscated IP/));
  assert.ok(has(a, 'caution', /raw IP/));
  assert.ok(has(a, 'info', /Local network/));
  assert.ok(has(a, 'caution', /Not encrypted/));
});

test('hex/short IPv4 → obfuscated', () => {
  const a = analyzeUrl('http://0x7f.1/');
  assert.equal(a.data.host, '127.0.0.1');
  assert.ok(has(a, 'danger', /Obfuscated IP/));
  for (const raw of ['http://0300.0250.0.01/', 'http://0xC0.0250.1/', 'http://192.168.257/', 'http://192.168.0.1./', 'http://0xC0A80101/']) {
    assert.ok(has(analyzeUrl(raw), 'danger', /Obfuscated IP/), raw);
  }
  assert.ok(none(analyzeUrl('http://8.8.8.8/'), 'danger'));
  assert.ok(!has(analyzeUrl('http://8.8.8.8/'), 'info', /Local/));
});

test('non-standard port → caution', () => {
  const a = analyzeUrl('https://example.com:8443/x');
  assert.equal(a.data.port, '8443');
  assert.ok(has(a, 'caution', /port 8443/));
  assert.equal(analyzeUrl('https://example.com:443/').data.port, '');
});

test('tracking params → cleanHref + info + Copy without tracking', () => {
  const a = analyzeUrl('https://example.com/p?utm_source=qr&id=7&fbclid=abc&UTM_Medium=x#top');
  assert.equal(a.data.cleanHref, 'https://example.com/p?id=7#top');
  assert.ok(has(a, 'info', /tracking parameters/));
  assert.ok(none(a, 'caution'));
  assert.ok(a.actions.some((x) => x.label === 'Copy without tracking' && x.value === 'https://example.com/p?id=7#top'));
  assert.deepEqual(a.data.query.map((q) => q.tracking), [true, false, true, true]);
  assert.equal(analyzeUrl('https://example.com/?utm_source=a').data.cleanHref, 'https://example.com/');
});

test('Google redirect → nested URL, caution redirects to evil.example', () => {
  const a = analyzeUrl('https://www.google.com/url?q=https://evil.example/&sa=D');
  assert.equal(a.data.nested.length, 1);
  assert.equal(a.data.nested[0].url, 'https://evil.example/');
  assert.equal(a.data.nested[0].analysis.data.host, 'evil.example');
  assert.ok(has(a, 'caution', /Redirects to evil\.example/));
  assert.equal(a.data.special.kind, 'redirector');
  assert.equal(a.data.query[0].nestedUrl, 'https://evil.example/');
});

test('bit.ly → shortener caution', () => {
  const a = analyzeUrl('https://bit.ly/3xYz');
  assert.equal(a.data.special.kind, 'shortener');
  assert.ok(has(a, 'caution', /Shortened link/));
});

test('excessive subdomains', () => {
  const a = analyzeUrl('https://a.b.c.d.e.f.example.co.uk/');
  assert.equal(a.data.registrableDomain, 'example.co.uk');
  assert.equal(a.data.subdomain, 'a.b.c.d.e.f');
  assert.ok(has(a, 'caution', /subdomains/));
});

test('javascript: → danger, never openable, code shown', () => {
  const a = analyzeUrl('javascript:alert(document.cookie)');
  assert.equal(a.data.scheme, 'javascript');
  assert.ok(has(a, 'danger', /run code/));
  assert.ok(!opens(a));
  assert.ok(a.fields.some((f) => f.label === 'Code' && f.value === 'alert(document.cookie)' && f.mono));
});

test('data: → danger, media type, decoded preview', () => {
  const a = analyzeUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
  assert.ok(has(a, 'danger', /run code/));
  assert.equal(a.data.dataUrl.mediaType, 'text/html');
  assert.equal(a.data.dataUrl.base64, true);
  assert.equal(a.data.dataUrl.preview, '<script>alert(1)</script>');
  assert.equal(a.data.dataUrl.size, 25);
  assert.ok(!opens(a));
});

test('newline inside host → danger, Open disabled', () => {
  const a = analyzeUrl('https://exa\nmple.com/');
  assert.ok(has(a, 'danger', /line breaks/));
  assert.equal(a.data.openable, false);
  assert.ok(!opens(a));
});

test('www. prefix → assumed https', () => {
  const a = analyzeUrl('www.example.com/menu');
  assert.equal(a.data.href, 'https://www.example.com/menu');
  assert.ok(has(a, 'info', /No scheme/));
  assert.equal(a.data.assumedScheme, true);
});

test('.mobileconfig → danger', () => {
  assert.ok(has(analyzeUrl('https://example.com/app.mobileconfig'), 'danger', /configuration profile/));
  assert.ok(has(analyzeUrl('https://example.com/x.MOBILEPROVISION'), 'danger', /configuration profile/));
});

test('Signal linkdevice → danger', () => {
  const a = analyzeUrl('sgnl://linkdevice?uuid=abc&pub_key=xyz');
  assert.ok(has(a, 'danger', /Links a new device/));
  assert.equal(a.data.special.action, 'link-device');
  assert.ok(!opens(a));
});

// ---- schemes (§2.2)
test('unsafe schemes are never openable', () => {
  for (const s of ['javascript:x', 'vbscript:x', 'data:,x', 'blob:https://a.com/uuid', 'file:///etc/passwd', 'about:blank',
    'view-source:https://a.com', 'chrome://settings', 'jar:file:///x!/y', 'ms-msdt:/id', 'search-ms:query=x', 'intent://x#Intent;end']) {
    const a = analyzeUrl(s);
    assert.ok(has(a, 'danger', /run code or access local files/), s);
    assert.equal(a.data.openable, false, s);
    assert.ok(!opens(a), s);
    assert.match(a.data.notOpenableReason, /run code/, s);
  }
});

test('itms-services → danger, copy-only', () => {
  const a = analyzeUrl('itms-services://?action=download-manifest&url=https://evil.example/m.plist');
  assert.ok(has(a, 'danger', /outside the App Store/));
  assert.ok(!opens(a));
});

test('local app / share schemes → caution, copy-only; ssh suggests command', () => {
  const smb = analyzeUrl('smb://fileserver/share');
  assert.ok(has(smb, 'caution', /network share/));
  assert.ok(!opens(smb));
  const ssh = analyzeUrl('ssh://alice@host.example:2222');
  assert.ok(ssh.actions.some((x) => x.value === 'ssh -p 2222 alice@host.example'));
  assert.ok(!opens(ssh));
  assert.ok(has(analyzeUrl('shortcuts://run-shortcut?name=x'), 'caution', /Shortcuts/));
});

test('http → caution, still openable; ws → info copy-only; unknown → info', () => {
  const a = analyzeUrl('http://example.com/');
  assert.ok(has(a, 'caution', /Not encrypted/));
  assert.ok(opens(a));
  const ws = analyzeUrl('wss://example.com/socket');
  assert.ok(has(ws, 'info', /WebSocket/));
  assert.ok(!opens(ws));
  const unk = analyzeUrl('foo://bar');
  assert.ok(has(unk, 'info', /Unknown link type "foo:"/));
  assert.ok(!opens(unk));
});

test('mailto/tel/sms fall back to openable links', () => {
  assert.ok(opens(analyzeUrl('mailto:a@example.com')));
  assert.ok(opens(analyzeUrl('tel:+15550100')));
});

// ---- detection (§0.3)
test('detectUrl', () => {
  assert.equal(detectUrl('https://a.com')?.kind, 'url');
  assert.equal(detectUrl('foo://bar')?.kind, 'url');
  assert.equal(detectUrl('foo:bar'), null);
  assert.equal(detectUrl('Note: 12:30'), null);
  assert.equal(detectUrl('localhost:8080'), null);
  assert.equal(detectUrl('www.example.com')?.kind, 'www');
  assert.equal(detectUrl('wwwexample'), null);
  assert.equal(detectUrl('MEBKM:TITLE:Example;URL:https\\://example.com/a\\;b;;')?.url, 'https://example.com/a;b');
  assert.deepEqual(detectUrl('URLTO:My page:https://example.com/'), { kind: 'urlto', url: 'https://example.com/', title: 'My page' });
  assert.equal(detectUrl('java\tscript:alert(1)')?.kind, 'url');
  assert.equal(detectUrl('\u0000javascript:alert(1)')?.kind, 'url');
  assert.ok(KNOWN_SCHEMES.has('sgnl'));
});

test('MEBKM / URLTO wrappers keep the title', () => {
  const a = analyzeUrl('MEBKM:TITLE:Shop;URL:https://example.com/;;');
  assert.equal(a.data.wrapper, 'mebkm');
  assert.equal(a.data.title, 'Shop');
  assert.equal(a.data.href, 'https://example.com/');
  assert.ok(a.fields.some((f) => f.label === 'Title' && f.value === 'Shop'));
  const b = analyzeUrl('URLTO:Home:www.example.com');
  assert.equal(b.data.href, 'https://www.example.com/');
});

// ---- adversarial
test('scheme hidden by a tab → danger "really javascript"', () => {
  const a = analyzeUrl('java\tscript:alert(1)');
  assert.equal(a.data.scheme, 'javascript');
  assert.ok(has(a, 'danger', /disguised/));
  assert.ok(!opens(a));
});

test('percent-encoded host → danger, no Open', () => {
  const a = analyzeUrl('https://ex%61mple.com/');
  assert.equal(a.data.host, 'example.com');
  assert.ok(has(a, 'danger', /percent-encoded/));
  assert.ok(!opens(a));
});

test('soft hyphen in host (deleted by IDNA) → danger, no Open', () => {
  const a = analyzeUrl('https://pay­pal.com/');
  assert.equal(a.data.host, 'paypal.com');
  assert.ok(has(a, 'danger', /invisible/));
  assert.ok(!opens(a));
});

test('full-width host → caution', () => {
  const a = analyzeUrl('https://ＥＸＡＭＰＬＥ.com/');
  assert.equal(a.data.host, 'example.com');
  assert.ok(has(a, 'caution', /full-width/));
});

test('space in URL → danger, Open disabled', () => {
  const a = analyzeUrl('https://example.com/a b');
  assert.ok(has(a, 'danger', /spaces or control/));
  assert.ok(!opens(a));
});

test('backslash variants and odd slashes', () => {
  assert.ok(!opens(analyzeUrl('https:\\\\evil.com/a')));
  assert.ok(has(analyzeUrl('https:evil.com'), 'caution', /slashes/));
});

test('malformed URL → danger, not openable', () => {
  const a = analyzeUrl('https://exa mple.com:99999/');
  assert.ok(has(a, 'danger', /Malformed/));
  assert.equal(a.data.openable, false);
  assert.ok(!opens(a));
});

test('invalid punycode label → danger', () => {
  assert.ok(has(analyzeUrl('https://xn--zz.example/'), 'danger', /Malformed/)); // WHATWG rejects it
  assert.ok(analyzeDomain('xn--zz.example').warnings.some((w) => w.level === 'danger' && /punycode/.test(w.message)));
});

test('IPv6 literals: mapped IPv4 decoded, local', () => {
  const a = analyzeUrl('http://[::ffff:192.168.1.1]/');
  assert.equal(a.data.hostKind, 'ipv6');
  assert.equal(a.data.ipv4Mapped, '192.168.1.1');
  assert.ok(has(a, 'info', /Local network/));
  assert.ok(has(analyzeUrl('http://[::1]:8080/'), 'info', /Local/));
  assert.ok(has(analyzeUrl('http://[fe80::1]/'), 'info', /Local/));
  assert.ok(!has(analyzeUrl('http://[2001:db8::1]/'), 'info', /Local/));
});

test('local host names and trailing dot', () => {
  assert.ok(has(analyzeUrl('http://printer.local/'), 'info', /Local network host/));
  assert.ok(has(analyzeUrl('http://localhost:3000/'), 'info', /Local network host/));
  assert.ok(has(analyzeUrl('https://example.com./'), 'info', /Trailing dot/));
});

test('IDN with ß maps to xn--fa-hia, shown as Unicode', () => {
  const a = analyzeUrl('https://faß.de/');
  assert.equal(a.data.host, 'xn--fa-hia.de');
  assert.equal(a.data.hostUnicode, 'faß.de');
  assert.ok(none(a, 'danger'));
});

test('legit IDN (single script) is info only', () => {
  const a = analyzeUrl('https://пример.рф/');
  assert.ok(none(a, 'danger'));
  assert.ok(has(a, 'info', /Internationalised/));
});

test('public suffix host → caution; private suffix site', () => {
  assert.ok(has(analyzeUrl('https://github.io/'), 'caution', /public suffix/));
  const gh = analyzeUrl('https://evil.github.io/login');
  assert.equal(gh.data.registrableDomain, 'evil.github.io');
});

test('long hosts / labels', () => {
  assert.ok(has(analyzeUrl(`https://${'a'.repeat(45)}.example.com/`), 'caution', /long label/));
  assert.ok(has(analyzeUrl(`https://${'abcdefghij.'.repeat(8)}example.com/`), 'caution', /long host/));
});

test('brand lookalikes (§2.6)', () => {
  assert.ok(has(analyzeUrl('https://paypa1.com/'), 'danger', /imitates paypal/));
  assert.ok(has(analyzeUrl('https://rnicrosoft.com/'), 'danger', /imitates microsoft/));
  assert.ok(has(analyzeUrl('https://paypai.com/'), 'caution', /similar to paypal/));
  assert.ok(has(analyzeUrl('https://paypal-login.com/'), 'caution', /brand name paypal/));
  assert.ok(has(analyzeUrl('https://secure-paypal.net/'), 'caution', /brand name paypal/));
  assert.ok(has(analyzeUrl('https://appleid-verify.com/'), 'caution', /brand name apple/));
  assert.ok(has(analyzeUrl('https://paypal.com.account-verify.example/'), 'danger', /"paypal" appears in the subdomain/));
  assert.ok(has(analyzeUrl('https://apple.id.example/'), 'danger', /"apple" appears in the subdomain/));
  assert.ok(has(analyzeUrl('https://dropbox.xyz/'), 'caution', /brand name dropbox/));
  // official domains and ordinary words stay quiet
  for (const ok of ['https://www.paypal.com/', 'https://paypal.de/', 'https://www.google.co.uk/', 'https://signin.apple.com/',
    'https://pineapple-shop.com/', 'https://live-scores.com/', 'https://post.ch/', 'https://mail.google.com/', 'https://x.com/']) {
    const a = analyzeUrl(ok);
    assert.ok(none(a, 'danger') && none(a, 'caution'), `${ok}: ${JSON.stringify(a.warnings)}`);
  }
});

test('download extensions', () => {
  assert.ok(has(analyzeUrl('https://example.com/setup.EXE'), 'caution', /downloads a file \(\.exe\)/));
  assert.ok(has(analyzeUrl('https://example.com/a/app.apk?x=1'), 'caution', /\.apk/));
  assert.ok(!has(analyzeUrl('https://example.com/page.html'), 'caution', /downloads/));
});

test('long links', () => {
  assert.ok(has(analyzeUrl(`https://example.com/?a=${'x'.repeat(300)}`), 'info', /Long link/));
  assert.ok(has(analyzeUrl(`https://example.com/?a=${'x'.repeat(2100)}`), 'caution', /Very long/));
});

test('percent-encoding: decoded for display, malformed and double encoding flagged', () => {
  const a = analyzeUrl('https://example.com/caf%C3%A9?q=a+b%20c');
  assert.equal(a.data.pathDecoded, '/café');
  assert.equal(a.data.query[0].decoded, 'a b c');
  assert.ok(has(analyzeUrl('https://example.com/?q=%E0%A4%A'), 'info', /malformed/));
  assert.ok(has(analyzeUrl('https://example.com/?u=https%253A%252F%252Fevil.example'), 'info', /double/));
});

test('+ kept literally outside http(s) query display', () => {
  const a = analyzeUrl('sgnl://signal.me?x=a+b');
  assert.equal(a.data.query[0].decoded, 'a+b');
});

test('host-scoped tracking params', () => {
  assert.equal(analyzeUrl('https://youtu.be/abc?si=xyz').data.cleanHref, 'https://youtu.be/abc');
  assert.equal(analyzeUrl('https://example.com/?si=xyz').data.cleanHref, 'https://example.com/?si=xyz');
  assert.equal(analyzeUrl('https://www.amazon.de/dp/B0?tag=aff-21&psc=1&th=1').data.cleanHref, 'https://www.amazon.de/dp/B0?th=1');
  assert.equal(analyzeUrl('https://x.com/a/status/1?ref_src=twsrc').data.cleanHref, 'https://x.com/a/status/1');
  assert.equal(analyzeUrl('https://example.com/?_gl=1*abc&a=1').data.cleanHref, 'https://example.com/?a=1');
});

test('nested URLs: encoded, double-encoded, base64; danger propagated; depth limited', () => {
  const enc = analyzeUrl('https://example.com/go?next=https%3A%2F%2Fevil.example%2F');
  assert.ok(has(enc, 'caution', /Redirects to evil\.example/));
  const dbl = analyzeUrl('https://example.com/go?url=https%253A%252F%252Fevil.example%252F');
  assert.equal(dbl.data.nested[0].url, 'https://evil.example/');
  const b64 = Buffer.from('https://evil.example/x').toString('base64');
  assert.equal(analyzeUrl(`https://example.com/r?d=${b64}`).data.nested[0].url, 'https://evil.example/x');
  const js = analyzeUrl('https://example.com/r?u=javascript://%0aalert(1)');
  assert.ok(has(js, 'danger', /Redirect target/));
  const same = analyzeUrl('https://example.com/login?next=https://www.example.com/home');
  assert.ok(!has(same, 'caution', /edirect/));
  const deep = analyzeUrl(`https://a.example/?u=${encodeURIComponent(`https://b.example/?u=${encodeURIComponent('https://c.example/?u=https://d.example/')}`)}`);
  assert.equal(deep.data.nested[0].analysis.data.nested[0].analysis.data.nested[0].analysis, null);
});

test('known redirectors', () => {
  assert.equal(analyzeUrl('https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example%2F').data.special.service, 'Facebook');
  const pp = analyzeUrl('https://urldefense.com/v3/__https://evil.example/x__;!!abc$');
  assert.equal(pp.data.special.kind, 'redirector');
  assert.ok(has(pp, 'caution', /Redirects to evil\.example/));
  assert.ok(has(analyzeUrl('https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example&data=x'), 'caution', /Redirects to evil\.example/));
});

test('first-party short links are info', () => {
  const a = analyzeUrl('https://youtu.be/dQw4w9WgXcQ');
  assert.ok(has(a, 'info', /Short link to YouTube/));
  assert.ok(none(a, 'caution'));
  const m = analyzeUrl('https://maps.app.goo.gl/abc');
  assert.ok(has(m, 'info', /Google Maps/));
  assert.equal(m.data.special.kind, 'map');
  assert.equal(m.data.special.shortened, true);
});

// ---- special families (§2.8, §7.2)
test('maps: Google pin preferred over viewport, Apple, OSM, Waze', () => {
  const g = analyzeUrl('https://www.google.com/maps/place/Eiffel+Tower/@48.85,2.29,17z/data=!3d48.858370!4d2.294481');
  assert.deepEqual([g.data.geo.lat, g.data.geo.lon], [48.85837, 2.294481]);
  assert.equal(g.summary, 'Map: 48.858370, 2.294481 (Google Maps)');
  assert.deepEqual(analyzeUrl('https://www.google.com/maps/@40.7,-74.0,12z').data.geo.lat, 40.7);
  assert.equal(analyzeUrl('https://www.google.com/maps/search/?api=1&query=47.5951518,-122.3316393').data.geo.lon, -122.3316393);
  assert.equal(analyzeUrl('https://maps.google.de/maps?q=52.5,13.4').data.geo.lat, 52.5);
  const ap = analyzeUrl('https://maps.apple.com/?ll=37.33,-122.03&q=Apple+Park');
  assert.equal(ap.data.geo.lat, 37.33);
  assert.equal(ap.data.special.label, 'Apple Park');
  assert.equal(analyzeUrl('https://maps.apple.com/place?coordinate=1.5,2.5&name=X').data.geo.lon, 2.5);
  assert.equal(analyzeUrl('https://www.openstreetmap.org/?mlat=51.5&mlon=-0.12').data.geo.lat, 51.5);
  assert.equal(analyzeUrl('https://www.openstreetmap.org/#map=15/51.5/-0.12').data.geo.lon, -0.12);
  assert.equal(analyzeUrl('https://waze.com/ul?ll=45.6906304,-120.810983').data.geo.lat, 45.6906304);
  assert.equal(analyzeUrl('https://www.google.com/maps/@95,0,12z').data.geo, undefined);
});

test('app stores', () => {
  const a = analyzeUrl('https://apps.apple.com/us/app/signal-private-messenger/id874139669');
  assert.equal(a.data.special.kind, 'appstore');
  assert.equal(a.summary, 'App Store: signal-private-messenger (id 874139669)');
  assert.equal(analyzeUrl('https://play.google.com/store/apps/details?id=org.thoughtcrime.securesms').summary, 'Google Play: org.thoughtcrime.securesms');
  const m = analyzeUrl('market://details?id=com.example.app');
  assert.equal(m.summary, 'Google Play: com.example.app');
  assert.ok(!opens(m));
  assert.equal(analyzeUrl('itms-apps://itunes.apple.com/app/id123').data.special.appId, '123');
});

test('messengers', () => {
  assert.equal(analyzeUrl('https://wa.me/15551234567?text=Hi').summary, 'WhatsApp chat with +15551234567');
  assert.equal(analyzeUrl('https://wa.me/15551234567?text=Hi').data.special.text, 'Hi');
  assert.equal(analyzeUrl('https://api.whatsapp.com/send?phone=15551234567').data.special.phone, '+15551234567');
  assert.equal(analyzeUrl('https://chat.whatsapp.com/AbCdEf').data.special.action, 'group-invite');
  assert.equal(analyzeUrl('whatsapp://send?phone=491701234567').data.special.phone, '+491701234567');
  assert.equal(analyzeUrl('https://t.me/durov').summary, 'Telegram: @durov');
  assert.equal(analyzeUrl('https://t.me/+AbCdEf').data.special.action, 'group-invite');
  assert.equal(analyzeUrl('https://t.me/joinchat/AbC').data.special.action, 'group-invite');
  assert.equal(analyzeUrl('https://t.me/somebot?start=ref123').data.special.action, 'bot');
  assert.equal(analyzeUrl('tg://resolve?domain=durov').data.special.user, 'durov');
  assert.ok(has(analyzeUrl('https://t.me/proxy?server=1.2.3.4&port=443&secret=x'), 'caution', /proxy/));
  assert.ok(has(analyzeUrl('tg://socks?server=1.2.3.4&port=1080'), 'caution', /proxy/));
  assert.equal(analyzeUrl('https://signal.me/#p/+15551234567').data.special.phone, '+15551234567');
  assert.equal(analyzeUrl('https://signal.group/#CjQKI').data.special.action, 'group-invite');
  assert.ok(has(analyzeUrl('sgnl://linkdevice?uuid=a&pub_key=b'), 'danger', /new device/));
});

test('meetings', () => {
  const z = analyzeUrl('https://us02web.zoom.us/j/1234567890?pwd=secret');
  assert.equal(z.summary, 'Zoom meeting 123 456 7890');
  assert.ok(z.data.query.find((q) => q.name === 'pwd').sensitive);
  assert.ok(z.fields.find((f) => f.label === 'Parameter pwd').sensitive);
  assert.equal(analyzeUrl('zoommtg://zoom.us/join?confno=1234567890').data.special.service, 'Zoom');
  assert.equal(analyzeUrl('https://meet.google.com/abc-defg-hij').summary, 'Google Meet abc-defg-hij');
  assert.equal(analyzeUrl('https://teams.microsoft.com/l/meetup-join/19%3ameeting').summary, 'Microsoft Teams meeting');
  assert.equal(analyzeUrl('https://teams.live.com/meet/9876').summary, 'Microsoft Teams meeting');
  assert.equal(analyzeUrl('https://acme.webex.com/meet/alice').summary, 'Webex meeting');
});

test('GS1 Digital Link', () => {
  const a = analyzeUrl('https://id.gs1.org/01/09506000134352/10/ABC?17=270531');
  assert.equal(a.data.special.kind, 'gs1');
  assert.equal(a.summary, 'Product GTIN 09506000134352, batch ABC, expiry 2027-05-31');
  assert.equal(a.data.special.gtinValid, true);
  assert.ok(has(analyzeUrl('https://example.com/01/09506000134353'), 'caution', /check digit/));
  assert.equal(analyzeUrl('https://example.com/gtin/09506000134352?17=270200').data.special.expiry, '2027-02-28');
  assert.equal(gtinValid('9780306406157'), true);
  assert.equal(gtinValid('9780306406158'), false);
});

test('magnet links', () => {
  const a = analyzeUrl('magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=Example%20File&tr=udp%3A%2F%2Ftracker.example.org%3A1337');
  assert.equal(a.data.magnet.infoHash, 'c12fe1c06bba254a9dc9f519b335aa7c1367a88a');
  assert.equal(a.data.magnet.name, 'Example File');
  assert.deepEqual(a.data.magnet.trackers, ['udp://tracker.example.org:1337']);
  assert.ok(has(a, 'info', /peer-to-peer/));
  assert.ok(!opens(a));
});

test('password in userinfo is masked in data and sensitive in fields', () => {
  const a = analyzeUrl('https://user:hunter2@example.com/');
  assert.equal(a.data.password, '••••••••');
  assert.ok(a.fields.find((f) => f.label === 'Password').sensitive);
  assert.ok(has(a, 'danger', /before "@"/));
});

test('analyzeDomain for e-mail domains', () => {
  const d = analyzeDomain('pаypal.com');
  assert.equal(d.host, 'xn--pypal-4ve.com');
  assert.ok(d.warnings.some((w) => w.level === 'danger'));
  const c = analyzeDomain('pаypal.com', { level: 'caution' });
  assert.ok(c.warnings.some((w) => w.level === 'caution' && /mixes/.test(w.message)));
  assert.equal(analyzeDomain('mail.example.co.uk').registrableDomain, 'example.co.uk');
});

test('UI data parts are present', () => {
  const a = analyzeUrl('https://user@sub.example.co.uk:8080/p/a?x=1#frag');
  const d = a.data;
  for (const k of ['scheme', 'host', 'hostUnicode', 'registrableDomain', 'subdomain', 'port', 'path', 'query', 'fragment', 'openable', 'notOpenableReason', 'cleanHref', 'nested', 'publicSuffix', 'hostKind', 'href']) {
    assert.ok(k in d, k);
  }
  assert.equal(d.subdomain, 'sub');
  assert.equal(d.publicSuffix, 'co.uk');
  assert.equal(d.fragment, 'frag');
  assert.equal(d.path, '/p/a');
});

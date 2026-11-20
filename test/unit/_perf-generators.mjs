// Pathological payload generators for perf.test.mjs (not a test file itself).

/** Repeats `unit` until the string is about `n` UTF-16 units long. */
const rep = (unit, n) => unit.repeat(Math.max(1, Math.ceil(n / unit.length))).slice(0, n);

// Bodies: (n) → string of about n chars.
export const BODIES = {
  spaces: (n) => `A${' '.repeat(n - 2)}B`,
  tabsMixed: (n) => `A${rep(' \t\r\n\f\v', n - 2)}B`,
  trailingWs: (n) => `A${' '.repeat(n - 2)}!`,
  semicolons: (n) => rep(';', n),
  commas: (n) => rep(',', n),
  colons: (n) => rep(':', n),
  equals: (n) => rep('=', n),
  ampersands: (n) => rep('&', n),
  questions: (n) => rep('?', n),
  slashes: (n) => rep('/', n),
  ats: (n) => rep('@', n),
  dots: (n) => rep('.', n),
  dashes: (n) => rep('-', n),
  a1: (n) => rep('a1', n),
  a1dots: (n) => rep('a1.', n),
  emailish: (n) => rep('a.', n - 1) + '@',
  emailDomain: (n) => `a@${rep('a.', n - 2)}`,
  phoneish: (n) => `+${rep('1 ', n - 1)}x`,
  phoneParens: (n) => rep('1(', n),
  backslashes: (n) => rep('\\', n),
  backslashSemi: (n) => rep('\\;', n),
  quotes: (n) => rep('"', n),
  quoteBackslash: (n) => rep('\\"', n),
  digits: (n) => rep('1', n),
  digitsDot: (n) => `${rep('1', n - 2)}.x`,
  base64ish: (n) => rep('QUJDRGVmZ2hpams0NTY3+/', n),
  base64url: (n) => rep('eyJhbGciOiJIUzI1NiJ9_-', n),
  hex: (n) => rep('0123456789abcdef', n),
  combining: (n) => `a${rep('́', n - 1)}`,
  crlfLines: (n) => rep('x\r\n', n),
  crlfOnly: (n) => rep('\r\n', n),
  lfFold: (n) => rep('\r\n ', n),
  kv: (n) => rep('k=v;', n),
  kvAmp: (n) => rep('k=v&', n),
  kvColon: (n) => rep('K:v;', n),
  words: (n) => rep('abandon ', n),
  urlish: (n) => `https://${rep('a.', n - 8)}`,
  wwwDots: (n) => `www.${rep('a-', n - 4)}`,
  pctEscapes: (n) => rep('%41', n),
  pctBroken: (n) => rep('%', n),
  parens: (n) => rep('(', n),
  braces: (n) => rep('{', n),
  brackets: (n) => rep('[', n),
  minusDigits: (n) => rep('-1', n),
  geoNums: (n) => rep('1.1,', n),
  zeroWidth: (n) => rep('a\u200B', n),
  dashDigitDot: (n) => rep('-1.', n),
  parenDigitDot: (n) => rep('(1.', n),
  semiBackslash: (n) => rep(';\\', n),
  colonSemi: (n) => rep(':;', n),
  manyUrls: (n) => rep('https://a.b ', n),
  manyEmails: (n) => rep('a@b.co ', n),
  manyPhones: (n) => rep('+1 555 0100 ', n),
  tlvZeros: (n) => rep('0000', n),
  ipLike: (n) => rep('1.', n),
  hostDashes: (n) => `a${rep('-', n - 3)}.b`,
  quotedBackslashes: (n) => `"${rep('\\', n - 3)}a";`,
  zerosThenOne: (n) => `${rep('0', n - 1)}1`,
  base64Letters: (n) => btoa(rep('a', Math.floor((n * 3) / 4))),
  combiningCrlf: (n) => rep('é\r\n', n),
};

// Prefixes routing the body into each parser.
export const PREFIXES = [
  '', 'BEGIN:VCARD\r\nVERSION:3.0\r\nFN:', 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:', 'BEGIN:VEVENT\nDTSTART:',
  'MECARD:N:', 'BIZCARD:N:', 'WIFI:S:', 'WIFI:T:WPA;P:', 'DPP:K:', 'otpauth://totp/', 'otpauth://hotp/x?secret=',
  'otpauth-migration://offline?data=', 'BCD\n002\n1\nSCT\n\n', 'SPC\r\n0200\r\n1\r\n', 'SPD*1.0*', '000201',
  'upi://pay?pa=', 'bank://singlepaymentsepa?name=', 'bitcoin:', 'ethereum:0x', 'lightning:', 'lnbc', '0x',
  'mailto:', 'MATMSG:TO:', 'SMTP:', 'tel:', 'facetime:', 'sms:', 'SMSTO:', 'geo:', 'geo:1,', 'HC1:', 'shc:/',
  'magnet:?', 'rdp://', 'ssh://', 'eyJ', '-----BEGIN PGP PUBLIC KEY BLOCK-----\n', 'https://', 'http://a.com/',
  'https://a.com/?', 'https://user@', '{"a":"', '[', 'Visit ', 'mail a@b.co ', 'bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.',
  'SPD*1.0*ACC:CZ5855000000001265098001*AM:1.', 'ethereum:0x0?value=1.',
];

export function gens(n) {
  const out = [];
  for (const [bname, body] of Object.entries(BODIES)) {
    for (const p of PREFIXES) out.push({ name: `${JSON.stringify(p)}+${bname}`, prefix: p, text: p + body(Math.max(4, n - p.length)) });
  }
  return out;
}


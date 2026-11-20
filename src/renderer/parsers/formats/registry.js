// Ordered list of structured-format parsers (PAYLOADS.md §0.3 dispatcher order).
// The dispatcher (../index.js) iterates this list before its own plain-URL, JSON and
// text handling; the first parser whose detect() returns true wins.
//
// Contract: { id, phase?, detect(text, ctx) → boolean, parse(text, ctx) → Analysis-without-raw }
// with ctx = { bytes: Uint8Array|null, bytesKind, symbology, textSafety, analyzeUrl? };
// `phase: 'late'` entries run after the dispatcher's URL and JSON parsers.
// Every entry is wrapped by `guarded`, so detect() never throws and parse() never throws.

import { guarded } from './util.js';
import { vcard, mecard, bizcard } from './contact.js';
import { ical } from './event.js';
import { wifi, dpp } from './wifi.js';
import { otpauth } from './otp.js';
import { otpMigration } from './otp-migration.js';
import { epc } from './epc.js';
import { swissQrBill } from './swiss-qr-bill.js';
import { spd, emv, upi, bezahlcode } from './payment.js';
import { cryptoUri } from './crypto.js';
import { mailto, matmsg, smtp } from './email.js';
import { tel, facetime, sms } from './phone.js';
import { geo } from './geo.js';
import { apiSecret } from './secrets.js';
import { healthCert, magnet, remoteAccess, jwt, keys, seedPhrase, base64Blob } from './misc.js';

export const structuredParsers = [
  vcard, // 2  BEGIN:VCARD
  ical, // 3  BEGIN:VCALENDAR / BEGIN:VEVENT
  mecard, bizcard, // 4
  wifi, dpp, // 5
  otpauth, otpMigration, // 6
  epc, // 7  BCD
  swissQrBill, // 8  SPC
  spd, // 9  SPD*
  emv, // 10 000201 + valid TLV
  upi, // 11 upi://
  bezahlcode, // 12 bank://
  cryptoUri, // 13 crypto schemes, bare BOLT11 / LNURL / 0x address
  mailto, matmsg, smtp, // 14
  tel, // 15
  facetime, // 16
  sms, // 17
  geo, // 18
  healthCert, // 20 HC1: / shc:/ / NZCP:/
  magnet, remoteAccess, // 21 (URL-like schemes with their own presentation)
  jwt, keys, seedPhrase, // 23 (phase 'late')
  apiSecret, // 23 API secrets / credentials (phase 'late'; before the base64 heuristic)
  base64Blob, // 24 (phase 'late')
].map(guarded);

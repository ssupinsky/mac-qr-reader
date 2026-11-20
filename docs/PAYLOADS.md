# QR payload formats — parser spec

Status: research spec, 2026-11-18. Audience: whoever implements
`src/renderer/parsers/*.js` against the **Parsers contract** in
`docs/ARCHITECTURE.md`. Everything here is meant to be implementable without
further research and without network access or runtime dependencies. Sources are
listed at the end (`[S1]`…); claims marked **(unverified)** came from secondary
sources or memory and should be checked against a real sample before relying on them.

Contents

0. Conventions, dispatcher, contract notes
1. Text safety (applies to every payload)
2. URLs (http/https and other schemes) — the security core
3. Wi-Fi (`WIFI:`) and Wi-Fi Easy Connect (`DPP:`)
4. Contacts: vCard, MECARD, BIZCARD
5. Email: `mailto:`, `MATMSG:`, `SMTP:`
6. Phone / SMS / FaceTime: `tel:`, `sms:`, `SMSTO:`, `MMSTO:`, `facetime:`
7. Geo: `geo:` and map URLs
8. Calendar: `BEGIN:VEVENT` / `BEGIN:VCALENDAR`
9. 2FA: `otpauth://`, TOTP/HOTP, `otpauth-migration://`
10. Payments: EPC (SEPA), Swiss QR-bill, Czech SPD, Bezahlcode, EMVCo / Pix, UPI, crypto
11. Misc: app/messenger links, `magnet:`, `ssh://`, health certificates, JWT, keys, seed phrases, JSON, base64, binary / encodings, product codes
12. How other scanner apps present results, and what fits this app
13. Sources

---

## 0. Conventions, dispatcher, contract notes

### 0.1 Test-vector notation

Inputs are written as JSON string literals (so `\n` is LF, `\r\n` CRLF, `\u202E`
is that code point). "Expected" lists the relevant parts of `Analysis`
(`type`, key `data` fields, warning levels + gist). Warning wording is free; level
and presence are what tests should assert.

### 0.2 Prefix matching

Unless a section says otherwise:

- Scheme/prefix matching is **ASCII case-insensitive** (QR alphanumeric mode
  only has uppercase, so generators emit `WIFI:`, `MECARD:`, `HTTPS://`, `BITCOIN:`…).
  Compare with `text.slice(0, n).toUpperCase() === PREFIX`. Never use
  `toLowerCase()` on the whole payload (Unicode case mapping changes lengths, e.g. `İ`).
- Do **not** trim the payload before detection. If there is leading/trailing
  whitespace (common: a trailing `\n`), detect on the trimmed copy but record
  `info: "Payload has leading/trailing whitespace"` and keep `raw.text` untouched.
- A leading U+FEFF (BOM) is stripped for detection and flagged `info`.

### 0.3 Dispatcher order (first match wins)

The order matters because some formats contain others (vCard contains URLs, Swiss
QR contains an IBAN, `bitcoin:` URIs can contain `lightning=`).

| # | Rule (after 0.2 normalisation) | Parser | `type` |
|---|---|---|---|
| 1 | bytes not decodable as text (see §11.9) | binary | `binary` |
| 2 | `BEGIN:VCARD` | vcard | `contact` |
| 3 | `BEGIN:VCALENDAR` or `BEGIN:VEVENT` | ical | `event` |
| 4 | `MECARD:` / `BIZCARD:` | mecard / bizcard | `contact` |
| 5 | `WIFI:` / `DPP:` | wifi / dpp | `wifi` |
| 6 | `otpauth://` / `otpauth-migration://` | otp / otp-migration | `otp` / `otp-migration` |
| 7 | first line `BCD` (line 1 exactly, see §10.1) | epc | `epc-payment` |
| 8 | first line `SPC` | swissqr | `swiss-qr-bill` |
| 9 | `SPD*` | spd | `payment` (new) |
| 10 | `000201` + valid EMV TLV (§10.5) | emv (Pix, PromptPay, …) | `payment` (new) |
| 11 | `upi://` | upi | `payment` |
| 12 | `bank://` (Bezahlcode) | bezahlcode | `payment` |
| 13 | crypto schemes (§10.7) or bare BOLT11 `ln…1…` | crypto | `crypto` |
| 14 | `mailto:` / `MATMSG:` / `SMTP:` | email | `email` |
| 15 | `tel:` | phone | `phone` |
| 16 | `facetime:` / `facetime-audio:` (incl. `//`) | phone (facetime) | `phone` |
| 17 | `sms:` / `smsto:` / `mms:` / `mmsto:` | sms | `sms` |
| 18 | `geo:` | geo | `geo` |
| 19 | `MEBKM:` / `URLTO:` (DoCoMo bookmark) | url | `url` |
| 20 | `HC1:` / `shc:/` / `NZCP:/` | healthcert | `text` + `data.format` |
| 21 | any `scheme:` matching `^[A-Za-z][A-Za-z0-9+.-]*:` with a known scheme, or `http(s)://`, or `www.` prefix | url | `url` |
| 22 | JSON (`{`/`[` and `JSON.parse` succeeds) | json | `json` |
| 23 | JWT / PEM / SSH key / seed-phrase heuristics (§11.5–11.7) | misc | `text` + `data.format` |
| 23a | API secrets / credentials (Stripe, AWS, GitHub, Slack, Google, OpenAI/Anthropic, npm, GitLab, PyPI, SendGrid, Shopify; see `formats/secrets.js`) | apiSecret | `text` + `data.format: 'api-secret'` (danger, masked) |
| 24 | base64 blob heuristic (§11.8) | base64 | `text` + `data.format: 'base64'` |
| 25 | product code (EAN/UPC/ISBN) when `symbology` is a 1D type (§11.10) | product | `text` + `data.format` |
| 26 | everything else | text | `text` |

Text with an unknown `scheme:` prefix (e.g. `foo:bar`) must not be classified as a URL
just because it has a colon: require the scheme to be in the known list of §2.2,
*or* to contain `://`. `Note: 12:30` is text.

### 0.4 Contract notes (proposals — ARCHITECTURE.md is the owner)

- Add `'payment'` to `Analysis.type` for non-EPC/non-Swiss bank & instant-payment
  formats (SPD, EMV/Pix/PromptPay/…, UPI, Bezahlcode). Put the concrete format in
  `data.format` (`'spd'|'emv'|'pix'|'upi'|'bezahlcode'`).
- Every `Analysis.data` should carry `format` (string, e.g. `'vcard-3.0'`, `'mecard'`,
  `'wifi-zxing'`, `'dpp'`, `'bip21'`, `'eip681'`) so the UI can label the variant.
- `saveAs.kind` could gain `'bin'` for binary payloads (optional).
- `openExternal` allowlist in ARCHITECTURE.md: `https, http, mailto, tel, sms,
  facetime`. Recommend also `facetime-audio`. Everything else: copy-only.

---

## 1. Text safety (every payload)

Run on `raw.text` and separately on every *displayed* parsed field (decoded
percent-escapes, unescaped vCard values etc. can introduce characters that were
not visible in the raw form).

### 1.1 Code points to flag

| Class | Code points | Level |
|---|---|---|
| Bidi embedding/override/isolate (Trojan Source, CVE-2021-42574) | U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO, U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI | **danger** |
| Bidi marks | U+200E LRM, U+200F RLM, U+061C ALM | caution (legit in RTL text; danger inside a URL host/scheme) |
| Zero-width / joiners | U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WJ, U+FEFF ZWNBSP (non-leading) | caution (ZWJ between two emoji = info) |
| Invisible operators / fillers | U+2061–U+2064, U+00AD soft hyphen, U+034F CGJ, U+180E, U+115F, U+1160, U+3164, U+FFA0, U+17B4, U+17B5 | caution |
| Deprecated format chars | U+206A–U+206F, U+FFF9–U+FFFB | caution |
| Tag characters ("ASCII smuggling", invisible text, also used for prompt injection) | U+E0000–U+E007F | **danger** (decode and show the hidden ASCII: tag `U+E00xx` ↔ ASCII `0xxx`) |
| Variation selectors | U+FE00–U+FE0F (info, normal after emoji/CJK), U+E0100–U+E01EF (caution; can smuggle bytes) | info/caution |
| C0 controls | U+0000–U+001F except TAB (09), LF (0A), CR (0D) | **danger** (NUL, ESC = terminal escape injection) |
| DEL + C1 controls | U+007F, U+0080–U+009F (C1 often = mis-decoded Windows-1252) | caution |
| Line/paragraph separators | U+2028, U+2029, U+0085 NEL | caution |
| Unusual spaces | U+00A0, U+1680, U+2000–U+200A, U+202F, U+205F, U+3000 | info (caution in URLs/IBANs/phone numbers/addresses) |
| Private use | U+E000–U+F8FF, U+F0000–U+FFFFD, U+100000–U+10FFFD | caution |
| Noncharacters | U+FDD0–U+FDEF, any U+xxFFFE/U+xxFFFF | caution |
| Lone surrogates | U+D800–U+DFFF not in a valid pair (possible from bad decoding) | danger |
| Replacement char | U+FFFD | info: "text was not valid in its encoding" |
| CR/LF/TAB in single-line contexts (URL, phone, SSID, name, amount) | U+000D, U+000A, U+0009 | caution (danger in URL authority) |

Catch-all safety net in JS (Unicode property escapes are built into V8; no data
tables needed): `/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u` plus the explicit space
list above. `\p{Cf}` covers bidi controls, ZW chars, tags, soft hyphen, BOM.

`raw.hasInvisible` = any code point from the table except TAB/LF/CR (and except
ZWJ inside emoji sequences and U+FE0F after an emoji).

### 1.2 Escaped display format

`raw.escaped` (and the "Escaped" view) is produced by mapping each code point:

- printable, non-flagged → itself
- `\` → `\\`
- LF → `\n`, CR → `\r`, TAB → `\t` (and in multi-line views also keep a real line break after `\n`)
- any flagged code point → `\u{XXXX}` (uppercase hex, min 4 digits), e.g. `\u{202E}`, `\u{E0041}`

UI rendering (recommended): render flagged code points as an inline chip in mono
font, e.g. `⟦U+202E RLO⟧` with a danger background, keep surrounding text visible.
For bidi safety the whole value container should have `unicode-bidi: plaintext`
(per paragraph) or the value should be displayed from `raw.escaped`, never the
original string, whenever a bidi control is present. Names for the chip come from
a small table (RLO, LRO, RLE, LRE, PDF, LRI, RLI, FSI, PDI, LRM, RLM, ALM, ZWSP,
ZWNJ, ZWJ, WJ, BOM, SHY, NBSP, TAG 'x', NUL, ESC, DEL…); fallback `U+XXXX`.

Also show `raw.length` as *code points* and, if bytes are known, byte length.

### 1.3 Mixed scripts & confusables (UTS #39 basics)

Applied to: URL host labels (danger-level), Wi-Fi SSID, contact names, email
domains, payment beneficiary names (caution-level).

Algorithm (per *label* for hosts, per *word* otherwise):

1. For each code point determine its Script_Extensions using JS regex, testing a
   candidate list: `Latin, Cyrillic, Greek, Armenian, Georgian, Hebrew, Arabic,
   Syriac, Thaana, Devanagari, Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu,
   Kannada, Malayalam, Sinhala, Thai, Lao, Tibetan, Myanmar, Khmer, Hangul,
   Hiragana, Katakana, Han, Bopomofo, Ethiopic, Cherokee, Canadian_Aboriginal,
   Mongolian, Tifinagh, Vai, Coptic, Glagolitic, Runic, Ogham, Gothic`
   via `/\p{scx=Cyrillic}/u` etc. Characters matching only `Common` or
   `Inherited` (digits, `-`, `.`, combining marks) are ignored.
2. Resolved script set = intersection of the per-character sets (UTS #39 §5.1).
3. Restriction level (UTS #39 §5.2, "Highly Restrictive"): OK if the label is
   single-script, or its scripts are a subset of one of
   `{Latin, Han, Hiragana, Katakana}`, `{Latin, Han, Bopomofo}`, `{Latin, Han, Hangul}`.
   Otherwise → **mixed script** (danger in hosts: "Domain mixes Latin and Cyrillic letters").
4. **Whole-script confusable** (the `аррӏе.com` case — every letter Cyrillic):
   if a label is entirely Cyrillic or Greek and every character is in the
   Latin-lookalike map below, compute its Latin skeleton; if the TLD is an ASCII
   TLD (`com`, `net`, …) → **danger** "Looks like the Latin word 'apple'". This is
   the rule Chrome uses to fall back to punycode [S30].
5. **Skeleton for lookalike checks**: NFD, drop `\p{M}`, lowercase, then map:

```
Cyrillic → Latin: а a, в b*, е e, ё e, г r*, һ h, і i, ї i, ј j, к k, ӏ l, м m*, н h*,
  о o, п n*, р p, с c, т t*, у y, ү y, х x, ѕ s, ԁ d, ԛ q, ԝ w, ь b*, ɡ g
Greek → Latin: α a, β b*, ε e*, η n*, ι i, κ k, ν v, ο o, ρ p, τ t*, υ u, χ x, ω w*
Latin ext → Latin: ı i, ɩ i, ɑ a, ɡ g, ʟ l, ɴ n, ᴏ o, ꞵ b, ſ s, ƚ l, ꜱ s
Digits/ASCII: 0 o, 1 l, | l, rn m, vv w, cl d   (only for brand lookalike checks, §2.6)
* = weaker resemblance, use only for the brand check, not for whole-script rule
```

The full `confusables.txt` (Unicode) is ~6,000 lines; bundling it is not necessary
for this app — the hand table above covers the realistic attacks (Cyrillic/Greek
homographs). If exact UTS #39 behaviour is ever wanted, bundle a generated subset.

Vectors:

| Input | Expected |
|---|---|
| `"Invoice\u202Etxt.exe"` | `text`; danger bidi override; `raw.escaped` = `Invoice\u{202E}txt.exe` |
| `"hello\u{E0069}\u{E0067}\u{E006E}\u{E006F}\u{E0072}\u{E0065}"` | danger tag chars; hidden text `ignore` shown |
| `"Caf\u00E9 menu"` | no warnings |
| `"pa\u200Bypal"` | caution zero-width space at index 2 |
| `"👩\u200D💻"` | no warning (ZWJ emoji sequence) |

---

## 2. URLs

### 2.1 Parsing pipeline

1. **Detect**: `^[A-Za-z][A-Za-z0-9+.-]*:` with a scheme from §2.2, or `www.` prefix
   (then assume `https://`, warn info "No scheme; treated as https"). Also handle
   DoCoMo bookmarks: `MEBKM:TITLE:<t>;URL:<u>;;` (MECARD escaping, §4.3) and
   `URLTO:<title>:<url>` (ZXing) → parse inner URL, keep title as a field.
2. **Raw authority extraction** (needed because the WHATWG parser normalises away
   the evidence): for `scheme://`, raw authority = substring after `//` up to the
   first of `/ ? #` *or `\`*. Raw userinfo = up to the **last** `@` in that substring.
   Raw host = rest minus `:port` (IPv6 in `[…]`).
3. **Parse** with WHATWG `new URL(text)` (built into Chromium/Node; it is what
   browsers will do). On exception → not openable, `danger: "Malformed URL"`,
   still show raw.
4. **Parser-differential checks** (danger, and disable "Open"): raw contains `\`
   in the authority/path for a special scheme; raw contains TAB/LF/CR anywhere
   (WHATWG silently deletes them: `https://exa\nmple.com` → `example.com`);
   raw contains any C0 control or space; raw host (lowercased, IDNA'd) ≠
   `url.hostname`. Classic case: iOS 11 Camera CVE-2018-4187 showed `facebook.com` but
   Safari opened another host for `https://xxx\@facebook.com:443@infosec.rm-it.com/`.
   WHATWG parses that as host `xxx`, path `/@facebook.com:443@infosec.rm-it.com/` —
   yet another interpretation. **Rule: if the parse is ambiguous, don't offer Open.**
5. **Open** always passes `url.href` (the normalised serialisation) to
   `openExternal`, never the raw text; the confirm dialog (main process) shows
   `url.href` and the Unicode + ACE host.

`data` for URLs:

```ts
{ format: 'url', href, scheme, username, password /*masked*/, host /*ACE*/, hostUnicode,
  hostKind: 'domain'|'ipv4'|'ipv6'|'opaque', registrableDomain, publicSuffix, subdomain,
  port /*'' if default*/, path, query: Array<{name, value, decoded, tracking, nestedUrl?}>,
  fragment, cleanHref /*tracking removed*/, nested: Array<{param, url, analysis}>,
  special?: { kind: 'map'|'appstore'|'messenger'|'meeting'|'gs1'|'shortener'|'redirector', ... } }
```

### 2.2 Schemes

| Scheme | Handling |
|---|---|
| `https` | openable (confirm) |
| `http` | openable; caution "Not encrypted (http)" |
| `mailto`, `tel`, `sms`, `facetime`, `facetime-audio` | own parsers (§5–6); openable |
| `javascript`, `vbscript`, `data`, `blob`, `file`, `filesystem`, `about`, `view-source`, `chrome`, `chrome-extension`, `jar`, `ms-msdt`, `search-ms`, `ms-officecmd`, `intent` | **never openable**; danger "This link type can run code or access local files". For `data:` show the media type and size; for `javascript:` show the decoded code in mono |
| `itms-services` (iOS enterprise app install: `itms-services://?action=download-manifest&url=…`) | danger "Installs an app outside the App Store"; copy-only |
| `shortcuts` (`shortcuts://run-shortcut?name=…`), `x-apple.systempreferences`, `applescript`, `x-man-page`, `smb`, `afp`, `nfs`, `vnc`, `rdp`, `ssh`, `sftp`, `ftp`, `telnet` | copy-only; caution "Opens a local app / network share" (smb/afp can leak credentials, shortcuts can run automations) |
| `market`, `itms-apps`, `itms-appss`, `macappstore` | copy-only + app-store summary (§2.8) |
| `tg`, `sgnl`, `whatsapp`, `signal`, `zoommtg`, `zoomus`, `msteams`, `spotify`, `steam`, `discord`, `slack` | copy-only + label (§2.8) |
| `magnet` | §11.2 |
| `otpauth`, `otpauth-migration`, crypto schemes | own parsers |
| `wss`, `ws` | copy-only, info |
| anything else | copy-only, info "Unknown link type `foo:`" |

### 2.3 Host analysis

**IP literals.** After parsing, `url.hostname` is dotted-decimal IPv4 or `[…]`
IPv6 → `hostKind`. Warnings:

- caution "Link points to a raw IP address, not a domain name".
- **danger** "Obfuscated IP address" if the raw host is not already canonical
  dotted-decimal. WHATWG accepts and normalises: single decimal `3232235777`,
  hex `0xC0A80101`, octal parts `0300.0250.0.01`, mixed `0xC0.0250.1`, short forms
  `192.168.257` (→ `192.168.1.1`), trailing dot `192.168.0.1.`. Show both raw and
  normalised.
- info "Local network address" for 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16,
  100.64/10, 0/8, `::1`, `fc00::/7`, `fe80::/10`, and IPv4-mapped `::ffff:a.b.c.d`
  (WHATWG serialises `[::ffff:192.168.1.1]` as `[::ffff:c0a8:101]` — decode for display).
- hostnames `localhost`, `*.local`, `*.internal`, `*.lan`, `*.home.arpa` → info local.

**IDN / punycode.** WHATWG gives the ACE form (`xn--…`). Browsers' JS has **no
built-in ACE→Unicode** (`url.domainToUnicode` is Node-only), so bundle an RFC 3492
decoder (~60 lines; parameters base 36, tmin 1, tmax 26, skew 38, damp 700,
initial_bias 72, initial_n 128, delimiter `-`). For each label starting with
`xn--`, decode; show **both** "Unicode: `аррӏе.com`" and "ACE: `xn--80ak6aa92e.com`".
Then apply §1.3 per label: mixed script → danger; whole-script confusable with an
ASCII TLD → danger; any non-ASCII label → info "Internationalised domain" (so the
user knows to look). Invalid punycode (decode fails) → danger.
Note: WHATWG IDNA maps `ß` → `xn--fa-hia` (non-transitional), uppercase and
full-width characters are folded; a trailing root dot (`example.com.`) is kept —
flag info "Trailing dot in domain".

**Registrable domain.** Show `subdomain` dimmed and `registrableDomain` bold (like
Safari/Chrome's address bar emphasis). See §2.5 for how to compute it.

**Excessive subdomains / long host.** caution if labels before the registrable
domain ≥ 4, or host length > 80, or any label > 40 chars; caution if the
*subdomain* contains a registrable-domain-looking string of a known brand
(`paypal.com.account-verify.example`).

**Port.** `url.port` is `''` when it equals the scheme default (WHATWG drops `:443`
for https). Non-empty → caution "Non-standard port 8443".

**Userinfo.** `url.username` or `url.password` non-empty → **danger** "Text before
`@` is not the website. This link goes to `evil.example`". Password → also mask
it in the display. (Example: `https://www.paypal.com@evil.example/`.)

### 2.4 Path, query, fragment

- **Length**: info if `href.length > 200`, caution if > 2000 ("Very long link;
  could hide the real destination"); always show the full URL wrapped, never
  truncated in the middle of the host.
- **Downloads**: path ends with (case-insens.) `.apk .aab .ipa .exe .msi .scr .bat
  .cmd .ps1 .vbs .js .jar .dmg .pkg .app .command .iso .img .zip .rar .7z .xpi .crx`
  → caution "Link downloads a file"; `.mobileconfig` / `.mobileprovision` →
  **danger** "Installs a configuration profile".
- **Percent-encoding**: decode each component for display with
  `decodeURIComponent` inside try/catch (malformed → show raw, info). Double
  encoding (`%25xx`) → info. Encoded characters in the *host* are rejected by WHATWG.
- **Query parsing**: split `url.search.slice(1)` on `&`, each at first `=`.
  Keep original order and raw text. Decode with `decodeURIComponent(v.replace(/\+/g,' '))`
  for http(s) query display only (form encoding). Do **not** use this `+`→space rule
  for `mailto:`/`sms:` (RFC 6068 / 5724 treat `+` literally).

**Tracking parameters** — mark `tracking: true`, offer **"Copy without tracking"**
(`cleanHref`: remove those pairs, keep the rest byte-for-byte, drop `?` if empty,
keep fragment). Names compared case-insensitively:

```
prefix: utm_  mtm_  pk_  piwik_  matomo_  hsa_  _hs  __hs  mc_  oly_  vero_  ga_
exact:  fbclid gclid gclsrc dclid gbraid wbraid gad_source gad_campaignid msclkid yclid
        ysclid twclid ttclid li_fat_id igshid igsh mkt_tok _openstat srsltid
        wickedid rb_clickid s_cid ef_id epik sc_cid _branch_match_id _branch_referrer
        _kx trk trkCampaign ncid cmpid spm scm
host-scoped (only remove on these hosts):
        si          on open.spotify.com, youtube.com, youtu.be, music.youtube.com
        feature     on youtube.com, youtu.be
        ref_src ref_url  on twitter.com, x.com
        smid        on nytimes.com
        _ga _gl     (Google cross-domain linker) everywhere
        tag ascsubtag ref ref_ pd_rd_* pf_rd_* psc  on amazon.* (note: `tag` is an affiliate id)
```

Show info (not caution) for tracking params: "Contains tracking parameters
(utm_source, fbclid)".

**Nested / redirect URLs.** For each query value (and for path segments of known
redirectors), try: raw, `decodeURIComponent` once, twice (max 3 rounds). If a
result matches `^(https?:)?//` or `^[a-z][a-z0-9+.-]*://`i, or is base64/base64url
whose decoding matches that → `nestedUrl`. Run the URL analysis recursively (max
depth 2) and add caution "Redirects to `evil.example`" when the nested registrable
domain differs from the outer one. Parameter names that make this more likely:
`url u q to dest destination redirect redirect_uri redirect_url redirectTo return
returnTo return_url returnUrl next continue goto target link out r rurl service
callback forward fwd page view`. Known redirectors (label `special.kind='redirector'`):
`google.*/url?q=|url=`, `l.facebook.com/l.php?u=`, `lm.facebook.com`,
`l.instagram.com/?u=`, `www.youtube.com/redirect?q=`, `www.linkedin.com/redir/redirect?url=`,
`t.umblr.com/redirect?z=`, `slack-redir.net/link?url=`, `*.safelinks.protection.outlook.com/?url=`,
`urldefense.com/v3/__<url>__` (Proofpoint, URL between `__` and `__`), `href.li/?<url>`,
`away.vk.com/away.php?to=`, `steamcommunity.com/linkfilter/?url=`, `exit.sc/?url=`.

### 2.5 Registrable domain: bundle the Public Suffix List — recommended

Measured today (2026-11-18): `public_suffix_list.dat` = **342 KB**, 10,463 rules;
the ICANN section alone is 6,951 rules / ~76 KB without comments; gzip of the full
file ≈ 92 KB. License MPL-2.0 [S8]: bundling the data file unmodified (or a
mechanically derived form) in an app is fine; keep the license header/notice in
the bundled file and mention it in the about/licenses text; MPL is file-level
copyleft, so it does not affect the app's other code.

Recommendation:

- **Bundle a snapshot** of the *full* list (ICANN + PRIVATE; the private section
  is what makes `evil.github.io`, `x.blogspot.com`, `*.vercel.app`,
  `*.pages.dev`, `*.ngrok-free.app` etc. separate sites — exactly the hosts used for
  phishing). Strip comments/blank lines at build time (≈ 160 KB), keep the license
  header. Pin by SHA-256 in `scripts/setup.mjs`; update manually. Staleness is
  harmless for display purposes. Zero runtime deps: it is data, not a package.
- Algorithm (PSL "Formal algorithm" [S8]): lowercase ACE host; labels reversed;
  match rules (exact, `*` wildcard for one label, `!` exception rule wins); if no
  rule matches the default rule is `*`; public suffix = longest matching rule
  (exceptions: drop the leftmost label); registrable domain = public suffix + one
  more label; if host *is* a public suffix → no registrable domain (caution "Host is
  a public suffix"). Store rules in a `Set` keyed by rule string with separate sets
  for wildcards and exceptions; lookup is O(labels).
- Rules in the file are Unicode; convert to ACE at build time (use Node's
  `url.domainToASCII` in the build script) so lookups use `url.hostname` directly.
- Fallback if the list ever fails to load: heuristic "last two labels, or last
  three if the second-level label is in {co, com, net, org, gov, edu, ac, ne, or, go}
  and the TLD is a 2-letter ccTLD" and add info "approximate".

Vectors (with full PSL): `a.b.example.co.uk` → `example.co.uk`;
`evil.github.io` → `evil.github.io`; `www.city.kawasaki.jp` → `city.kawasaki.jp`
(exception rule `!city.kawasaki.jp`); `foo.bar.ck` → `foo.bar.ck` (rule `*.ck`);
`www.ck` → `www.ck` (rule `!www.ck`); `co.uk` → none.

### 2.6 Lookalike-of-popular-brands heuristic (keep simple)

Brand list (~50, editable constant): `apple icloud google gmail youtube microsoft
outlook office live windows amazon aws paypal ebay facebook instagram whatsapp
meta messenger netflix spotify linkedin twitter x tiktok telegram signal dropbox
github gitlab adobe docusign zoom slack binance coinbase kraken metamask ledger
revolut wise n26 ing chase wellsfargo bankofamerica citi hsbc barclays santander
deutschebank sparkasse dhl fedex ups usps royalmail post booking airbnb uber`
plus their canonical registrable domains (`apple.com`, `paypal.com`, …).

Let `L` = the registrable-domain label (without public suffix), `S` = skeleton(L)
from §1.3 (with digit/ASCII map). For each brand `b` with canonical domains `D_b`:

- registrable domain ∈ `D_b` → no warning (optionally info "Official domain").
- `S === b` (homograph / digit swap: `paypa1`, `аpple`) → **danger** "Imitates b".
- Levenshtein(`S`, `b`) = 1 and `b.length ≥ 5` → caution "Similar to b".
- `L` contains `b` with separators (`paypal-login`, `secure-paypal`, `appleid-verify`)
  → caution "Uses the brand name b but is not b's domain".
- `b` appears as a whole label in the subdomain (`paypal.com.example.net`,
  `apple.id.example`) → danger.

### 2.7 URL shorteners and dynamic-QR redirectors

Destination is hidden; the app cannot (and must not) resolve it. caution
"Shortened link — the real destination is unknown until opened". Match on
registrable domain:

```
bit.ly bitly.com j.mp bit.do tinyurl.com tiny.cc t.co goo.gl g.co ow.ly buff.ly is.gd v.gd
rebrand.ly rb.gy cutt.ly shorturl.at t.ly s.id tr.ee linktr.ee lnkd.in fb.me m.me
amzn.to amzn.eu a.co youtu.be wp.me ift.tt dlvr.it trib.al soo.gd x.co clck.ru
shorte.st adf.ly ouo.io bl.ink short.io sl.ink hyperurl.co aka.ms apple.co spoti.fi
msft.it flic.kr db.tt 1drv.ms forms.gle maps.app.goo.gl page.link app.link onelink.me
qrco.de q-r.to l.ead.me qr.codes qrfy.io me-qr.com scnv.io bitly.page
```

(`page.link` = Firebase Dynamic Links, `app.link` = Branch, `onelink.me` =
AppsFlyer: deep-link redirectors; `qrco.de`, `q-r.to`, `l.ead.me`, `qr.codes`,
`qrfy.io`, `me-qr.com`, `scnv.io` = "dynamic QR" generator redirectors — these are
the most common in printed QR codes **(list partly unverified; treat as heuristic)**.)
`youtu.be`, `forms.gle`, `maps.app.goo.gl` are first-party and lower risk: label them
"Short link to YouTube/Google Forms/Google Maps" with info instead of caution.

### 2.8 Special URL families (detect on host/path, add a summary line)

| Family | Detection | Summary / fields |
|---|---|---|
| Apple App Store | `apps.apple.com/<cc>/app/<slug>/id<digits>`, `itunes.apple.com/…/id<digits>`, `itms-apps://…` | "App Store: <slug> (id 123)" |
| Google Play | `play.google.com/store/apps/details?id=<pkg>`, `market://details?id=<pkg>` | "Google Play: com.example.app" |
| WhatsApp | `wa.me/<digits>[?text=…]`, `api.whatsapp.com/send?phone=…&text=…`, `chat.whatsapp.com/<invite>`, `whatsapp://send?phone=` | "WhatsApp chat with +<digits>" / "WhatsApp group invite"; show prefilled text |
| Telegram | `t.me/<user>`, `t.me/+<invite>`, `t.me/joinchat/<x>`, `t.me/<bot>?start=<p>`, `tg://resolve?domain=<user>`, `tg://join?invite=` | "Telegram: @user / group invite / bot with start parameter"; caution for `t.me/proxy?server=…` and `tg://proxy` / `tg://socks` ("Configures a proxy") |
| Signal | `signal.me/#p/<phone>`, `signal.me/#eu/<username-link>`, `signal.group/#<…>`, `sgnl://signal.group/…`, `sgnl://linkdevice?uuid=…&pub_key=…` | **danger** for `linkdevice`: "Links a new device to YOUR Signal account — attackers use this to read your messages" (real-world attack, 2025 [S33]) |
| WhatsApp/Telegram desktop linking | (they show QR on desktop, phone scans) | n/a, but text "link device" phishing applies |
| Zoom | `*.zoom.us/j/<id>[?pwd=…]`, `zoommtg://` | "Zoom meeting 123 456 7890"; `pwd` = sensitive |
| Google Meet | `meet.google.com/<abc-defg-hij>` | "Google Meet abc-defg-hij" |
| MS Teams | `teams.microsoft.com/l/meetup-join/…`, `teams.live.com/meet/<id>` | "Microsoft Teams meeting" |
| Webex | `*.webex.com/meet/…` / `/j.php?MTID=` | "Webex meeting" |
| Maps | §7.2 | geo summary |
| GS1 Digital Link (product packaging, GS1 "Sunrise 2027") | path contains `/01/<14 digits>` (`/gtin/` alias), optional `/10/<batch>`, `/21/<serial>`, query `17=<YYMMDD>` | "Product GTIN 09506000134352, batch ABC, expiry 2027-05-31"; verify GTIN mod-10 (§11.10) |
| EU DCC verifier / health | n/a | |

Vectors (URL):

| Input | Expected |
|---|---|
| `"https://example.com/"` | url; registrableDomain `example.com`; no warnings; actions copy + open |
| `"HTTPS://EXAMPLE.COM/A?b=C"` | href `https://example.com/A?b=C` (path/query case kept) |
| `"https://pаypal.com/login"` (Cyrillic а U+0430) | host `xn--pypal-4ve.com`, hostUnicode `pаypal.com`; danger mixed script (Latin+Cyrillic); danger imitates paypal |
| `"https://аррӏе.com/"` (all Cyrillic) | host `xn--80ak6aa92e.com`; danger whole-script confusable "apple" |
| `"https://www.paypal.com@evil.example/"` | host `evil.example`, username `www.paypal.com`; danger userinfo |
| `"https://xxx\\@facebook.com:443@infosec.rm-it.com/"` | WHATWG host `xxx`; danger parser differential (backslash); Open disabled |
| `"http://3232235777/"` | host `192.168.1.1`; danger obfuscated IP; caution IP; info local; caution http |
| `"http://0x7f.1/"` | host `127.0.0.1`; danger obfuscated IP |
| `"https://example.com:8443/x"` | port `8443`; caution |
| `"https://example.com/p?utm_source=qr&id=7&fbclid=abc&UTM_Medium=x#top"` | cleanHref `https://example.com/p?id=7#top`; info tracking |
| `"https://www.google.com/url?q=https://evil.example/&sa=D"` | nested `https://evil.example/`; caution redirects to evil.example |
| `"https://bit.ly/3xYz"` | special shortener; caution |
| `"https://a.b.c.d.e.f.example.co.uk/"` | registrableDomain `example.co.uk`; caution excessive subdomains |
| `"javascript:alert(document.cookie)"` | url scheme javascript; danger; no open action |
| `"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="` | danger; data `{mediaType:'text/html', base64:true}`; decoded preview shown as text |
| `"https://exa\nmple.com/"` | danger control/newline in URL; Open disabled |
| `"www.example.com/menu"` | url (assumed https); info no scheme |
| `"https://example.com/app.mobileconfig"` | danger configuration profile |
| `"sgnl://linkdevice?uuid=abc&pub_key=xyz"` | danger link-device |

---

## 3. Wi-Fi

### 3.1 `WIFI:` — two dialects

1. **ZXing / de-facto** [S1]: `WIFI:T:WPA;S:mynetwork;P:mypass;;` — fields in any
   order, values **backslash-escaped** (`\\ \; \, \" \:`).
2. **WPA3 Specification §7 (Wi-Fi Alliance, IANA-registered `WIFI` scheme)** [S2][S3]:

```
WIFI-qr    = "WIFI:" [type ";"] [trdisable ";"] ssid ";" [hidden ";"] [id ";"]
             [password ";"] [public-key ";"] ";"
type       = "T:" *(unreserved)        ; e.g. "WPA" (= password-based: WPA2/WPA3-Personal)
trdisable  = "R:" *(HEXDIG)            ; Transition Disable bitmap, hex
ssid       = "S:" *(printable / pct-encoded)
hidden     = "H:true"
id         = "I:" *(printable / pct-encoded)    ; SAE password identifier
password   = "P:" *(printable / pct-encoded)
public-key = "K:" *PKCHAR              ; SAE-PK: base64 of the public key
printable  = %x20-3a / %x3c-7e         ; i.e. any printable ASCII except ';'
PKCHAR     = ALPHA / DIGIT / %x2b / %x2f / %x3d
```

In WPA3 the escaping is **percent-encoding** (`;` → `%3B`, non-ASCII UTF-8 → `%XX`),
not backslashes. In practice many generators (Android, GNOME, KDE) emit `T:SAE`
and backslash escapes [S3]. The parser must accept both.

Fields (union):

| Key | Meaning | Values |
|---|---|---|
| `T` | auth type | `WPA` (WPA/WPA2/WPA3-Personal), `WPA2`, `WPA3`, `SAE` (non-standard but common = WPA3-Personal), `WEP`, `nopass` (open/OWE), `WPA2-EAP` / `WPA-EAP` / `WPA3-EAP` (Enterprise), empty/missing = treat as `nopass` *only if* `P` empty, else `WPA` |
| `S` | SSID (required) | string; ≤ 32 **bytes** UTF-8 |
| `P` | password / PSK | 8–63 ASCII chars, or exactly 64 hex = raw PSK; WEP: 5/13 chars or 10/26 hex |
| `H` | hidden SSID | `true` (also accept `True`, `1`); anything else = false |
| `R` | WPA3 Transition Disable bitmap (hex) | bit0 WPA3-Personal, bit1 SAE-PK, bit2 WPA3-Enterprise, bit3 Enhanced Open → show "Device should disable older WPA2 fallback" |
| `K` | SAE-PK public key (base64) | show fingerprint (SHA-256, first 16 hex) |
| `I` | WPA3: SAE password identifier. **ZXing: EAP identity** | ambiguous — see below |
| `E` | EAP method (ZXing) | `PEAP`, `TTLS`, `TLS`, `PWD`, `SIM`, `AKA`, `AKA'` |
| `A` | EAP anonymous identity (ZXing) | |
| `PH2` | EAP phase 2 (ZXing) | `MSCHAPV2`, `GTC`, `PAP`, `MSCHAP` |

`I:` meaning: if `T` is an EAP type (or `E` present) → EAP identity; else → SAE
password identifier.

### 3.2 Tokenising algorithm

```
body = text.slice(5)                    // after "WIFI:" (case-insensitive)
tokens = split body on ';' not preceded by an odd number of backslashes
for each token (skip empty):
  key = up to first ':' (uppercase it); value = rest (raw)
  duplicate keys: keep the first, caution "Duplicate field K"
unknown keys: keep in data.extra, info
must end with ";;" — missing → info "Not properly terminated" (still parse)
```

Value decoding, per field (S, P, I, A):

- `zx` = backslash-unescape (`\X` → `X` for any X; a lone trailing `\` stays).
- `pct` = percent-decode as UTF-8 (only if every `%` is followed by 2 hex digits and the
  result is valid UTF-8; else `null`).
- If the payload looks WPA3-style (`R:` or `K:` present, or no backslash anywhere and
  at least one `%XX`), the primary value is `pct`; otherwise `zx`.
- If the other interpretation exists and differs → caution on that field:
  "Ambiguous encoding: could also be `<other>`". (`Caf%C3%A9` vs `Café`.)
- Quoted SSID/password `"…"`: strip the quotes (ZXing: quotes mark a value that would
  otherwise look like hex). Unquoted SSID that is even-length hex (`^[0-9A-Fa-f]{2,64}$`)
  → info "May be a hex-encoded SSID; as text it is `4142`, as bytes `AB`" (show both).
  Unquoted 64-hex password = raw PSK (info).

### 3.3 Display, warnings, actions

- Fields: Network (SSID, mono, with escaped view if invisible chars), Security
  (humanised: "WPA3-Personal (SAE)" / "WPA2/WPA3-Personal" / "WEP" / "Open"),
  Password (masked `••••••••`, `sensitive: true`, reveal toggle), Hidden, EAP fields.
- Warnings: `WEP` → danger "WEP is broken; traffic can be decrypted"; `nopass` →
  caution "Open network — traffic not encrypted (unless Enhanced Open/OWE)";
  password < 8 chars for WPA → caution "Invalid WPA password length"; SSID > 32
  bytes → caution invalid; SSID with invisible/bidi/mixed-script chars → caution
  "Network name contains hidden characters — could imitate another network";
  generic info "Only join networks from codes you trust (fake hotspot risk)" only
  when `T` is open.
- Actions: "Copy password" (`sensitive`), "Copy network name". No "join" (the app
  has no network capability; macOS has no URL scheme for joining a Wi-Fi network).

### 3.4 Vectors

| Input | Expected `data` |
|---|---|
| `"WIFI:T:WPA;S:mynetwork;P:mypass;;"` | `{ssid:'mynetwork', auth:'WPA', password:'mypass', hidden:false}` |
| `"WIFI:S:My\\;Net\\\\;T:WPA;P:pa\\:ss\\,\\\"word;H:true;;"` | ssid `My;Net\`, password `pa:ss,"word`, hidden true |
| `"WIFI:T:SAE;S:Home;P:correct horse;;"` | auth `SAE` → label "WPA3-Personal"; no warning |
| `"WIFI:T:WPA;R:1;S:Caf%C3%A9;P:p%3Bss;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAD;;"` | WPA3 style: ssid `Café`, password `p;ss`, transitionDisable `0x1`, saePk present; caution ambiguous (zx would be `Caf%C3%A9`) |
| `"WIFI:S:\"4142\";T:WPA;P:12345678;;"` | ssid `4142` (quoted → text), no hex note |
| `"WIFI:S:4142;T:nopass;;"` | ssid `4142`; info maybe-hex (`AB`); caution open network |
| `"WIFI:T:WEP;S:old;P:abcde;;"` | danger WEP |
| `"WIFI:T:WPA2-EAP;S:corp;E:PEAP;PH2:MSCHAPV2;A:anon;I:alice;P:pw;;"` | eap `{method:'PEAP', phase2:'MSCHAPV2', anonymousIdentity:'anon', identity:'alice'}` |
| `"WIFI:T:WPA;S:Free\u200BWiFi;P:12345678"` | ssid has ZWSP → caution; info not terminated |

### 3.5 `DPP:` — Wi-Fi Easy Connect bootstrapping URI

Used to onboard a *device* (printer, IoT): a configurator (phone) scans the
device's QR. A Mac cannot act on it; show it as information.

```
dpp-qr = "DPP:" *(token ";") ";"     ; tokens in any order, K is mandatory
C:<opclass>/<channel>[,<opclass>/<channel>…]   e.g. C:81/1,115/36  (channel list)
M:<12 hex>        MAC address (show as aa:bb:cc:dd:ee:ff)
I:<text>          information (model/serial), printable
V:<digits>        DPP version (1, 2, 3)
H:<host>          supported host name (DPP over TCP)
B:<bands>         supported bands (v3) (unverified)
K:<base64>        bootstrapping public key: base64 of DER SubjectPublicKeyInfo (mandatory)
```

Example (from a kernel/hostapd thread) [S4]:
`DPP:C:81/1;M:44d43771bb2e;V:2;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAD5ANLCEXDDO7vnLVgSDoiJJ5H2Mo7aPXVriSVZ0ygP7M=;;`
→ `{format:'dpp', channels:['81/1'], mac:'44:d4:37:71:bb:2e', version:2, publicKeyB64:'MDkw…'}`;
summary "Wi-Fi Easy Connect device (DPP v2)"; info "This code is for setting up a
device with a phone or router; nothing to join here". Optional: decode the DER to
show the curve (OID `1.2.840.10045.3.1.7` = P-256) and SHA-256 fingerprint.
Missing `K` → caution invalid.

---

## 4. Contacts

### 4.1 vCard (2.1, 3.0, 4.0)

Detection `^BEGIN:VCARD` (case-insens.); ends at `END:VCARD`. Specs: 2.1 (IMC
1996), 3.0 RFC 2426, 4.0 RFC 6350 [S10][S11].

Line handling:

1. Split on CRLF, LF or CR (QR generators often use bare LF).
2. **Unfold**: a line starting with SPACE or TAB continues the previous line (remove
   the line break + that one whitespace char). 2.1 additionally: when
   `ENCODING=QUOTED-PRINTABLE`, a line ending with `=` continues on the next line
   (soft break) — join before QP-decoding.
3. Content line: `[group "."] name *(";" param) ":" value`. The first unquoted `:`
   ends the params (param values may be quoted `"…"` containing `:`/`;`).
   Name/param names case-insensitive. Groups (`item1.EMAIL`, `item1.X-ABLabel` —
   Apple) bind a label to a value.
4. Params: 3.0/4.0 `TYPE=work,voice` or repeated `TYPE=`; 2.1 bare values
   (`TEL;CELL;PREF:`). 2.1 `ENCODING=QUOTED-PRINTABLE` / `BASE64`, `CHARSET=UTF-8|ISO-8859-1|…`
   (decode QP bytes with `TextDecoder(charset)`); 3.0 `ENCODING=b` (base64).
   4.0 `VALUE=uri` (e.g. `TEL;VALUE=uri:tel:+1-555-0100`).
5. Value unescaping (3.0/4.0): `\\`→`\`, `\,`→`,`, `\;`→`;`, `\n`/`\N`→LF. Split
   structured values on **unescaped** `;` first, then lists on unescaped `,`.
   2.1: only `\;` in structured values.

Fields to extract:

| Property | Meaning / structure |
|---|---|
| `VERSION` | 2.1/3.0/4.0 (missing → info) |
| `FN` | formatted name (display title); else compose from N |
| `N` | `family;given;additional;prefixes;suffixes` |
| `ORG` | `org;unit;subunit…`, `TITLE`, `ROLE` |
| `TEL` | number + TYPE (cell, work, home, fax, voice, pager, text) — run §6.1 checks |
| `EMAIL` | address + TYPE — run §5 domain checks |
| `ADR` | `pobox;ext;street;locality;region;postal;country` |
| `URL` | run §2 analysis, show warnings inline |
| `BDAY`, `ANNIVERSARY` | `YYYYMMDD` / `YYYY-MM-DD` / `--MMDD` (4.0 no year) |
| `NOTE`, `NICKNAME`, `X-SOCIALPROFILE`, `IMPP`, `GEO`, `TZ`, `CATEGORIES`, `UID`, `REV` | show as text |
| `PHOTO`, `LOGO`, `SOUND`, `KEY` | inline data (base64/data: URI) or a remote URI |

Warnings: `PHOTO/LOGO/SOUND/KEY` with `http(s)` URI → caution "Contains a remote
image link; Contacts may fetch it (tracking)"; inline photo > 32 KB → info; `URL`
property warnings are propagated (prefix "Website: …"); `TEL` with `*`/`#` → danger
(§6.1); several `BEGIN:VCARD` blocks → info "N contacts" (show each); missing
`END:VCARD` → info truncated; unknown version → info; invisible chars in FN/ORG →
caution.

Actions: "Save as contact (.vcf)" — `saveAs:{suggestedName: sanitize(FN)||'contact' + '.vcf', kind:'vcf'}`,
value = original text with line endings normalised to CRLF (vCard requires CRLF);
copy name/phone/email individually.

Vectors:

```
"BEGIN:VCARD\nVERSION:3.0\nN:Doe;John;Q.;Dr.;Jr.\nFN:Dr. John Q. Doe Jr.\nORG:Example\\, Inc.;R&D\nTEL;TYPE=CELL:+1 555 0100\nEMAIL;TYPE=WORK:john@example.com\nADR;TYPE=WORK:;;1 Main St\\nSuite 2;Springfield;IL;62701;USA\nURL:https://example.com\nEND:VCARD"
→ contact, version '3.0', fn 'Dr. John Q. Doe Jr.', n {family:'Doe', given:'John', additional:'Q.', prefix:'Dr.', suffix:'Jr.'},
  org ['Example, Inc.','R&D'], tel [{value:'+1 555 0100', types:['cell']}], adr street '1 Main St\nSuite 2'
```

```
"BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:M=C3=BCller;J=C3=BCrgen\r\nTEL;CELL;PREF:+49301234567\r\nNOTE;ENCODING=QUOTED-PRINTABLE:Line one=0D=0ALine=\r\n two\r\nEND:VCARD"
→ version '2.1', n family 'Müller', given 'Jürgen'; tel types ['cell','pref']; note 'Line one\r\nLine two'
```

```
"BEGIN:VCARD\nVERSION:4.0\nFN:Jane\n  Roe\nTEL;VALUE=uri;TYPE=\"voice,home\":tel:+1-555-555-5555;ext=5555\nPHOTO:https://tracker.example/p.png\nEND:VCARD"
→ fn 'Jane Roe' (folded: LF + one space removed, second space kept), tel value 'tel:+1-555-555-5555;ext=5555' types ['voice','home'];
  caution remote PHOTO
```

```
"BEGIN:VCARD\nVERSION:3.0\nFN:Bank Support\nTEL:*21*+15550100#\nEND:VCARD"
→ danger "phone number is a USSD/MMI code (call forwarding)"
```

### 4.2 Converting to .vcf for MECARD/BIZCARD

Emit vCard 3.0 with CRLF: `BEGIN:VCARD`, `VERSION:3.0`, `N:`, `FN:`, then one line per
field, escaping `\ , ;` and newlines (`\n`); fold lines > 75 octets. Map: MECARD
`N:Last,First` → `N:Last;First;;;` + `FN:First Last`; `SOUND` → `X-PHONETIC-LAST-NAME`
(Apple) or `SORT-STRING`; `TEL` → `TEL`; `TEL-AV` → `TEL;TYPE=video`; `EMAIL`; `ADR` →
`ADR:;;<value>;;;;`; `BDAY` → `BDAY:YYYY-MM-DD`; `NOTE`; `URL`; `NICKNAME`; `ORG`.
BIZCARD `N`+`X` → given/family; `T` → TITLE; `C` → ORG; `A` → ADR street; `B` → TEL work;
`M` → TEL cell; `F` → TEL fax; `E` → EMAIL.

### 4.3 MECARD (NTT DoCoMo)

`MECARD:` then `KEY:value;` pairs, terminated `;;` [S1]. Escape with backslash:
`\\ \; \: \,` (DoCoMo spec mandates escaping `\ ; : ,` in values). Tokenise exactly like
§3.2 (split on unescaped `;`, key = up to first `:`, unescape `\X`→`X`).
Keys: `N` (name, `Last,First` — comma splits reading order; unescaped comma only),
`SOUND` (phonetic/kana reading), `TEL` (repeatable), `TEL-AV`, `EMAIL` (repeatable),
`NOTE`, `BDAY` (8 digits `YYYYMMDD`), `ADR` (single string; DoCoMo: comma-separated
parts PO box, room, street, city, state, zip, country — show as one line with commas),
`URL`, `NICKNAME`, `ORG` (ZXing extension).

Vectors:

```
"MECARD:N:Owen,Sean;ADR:76 9th Avenue\\, 4th Floor\\, New York\\, NY 10011;TEL:12125551212;EMAIL:srowen@example.com;;"
→ name {last:'Owen', first:'Sean'}, adr '76 9th Avenue, 4th Floor, New York, NY 10011', tel ['12125551212']
"MECARD:N:Doe,John;TEL:+15550100;TEL:+15550101;NOTE:a\\;b\\:c;BDAY:19900131;URL:http://example.com;;"
→ tel 2 entries; note 'a;b:c'; bday '1990-01-31'; url warnings propagated (caution http)
"MECARD:N:山田,太郎;SOUND:ヤマダ,タロウ;TEL:0312345678;;"
→ name {last:'山田', first:'太郎'}, sound 'ヤマダ,タロウ'
```

(Unescaped comma in `ADR` from real generators is common — ZXing's own example in
[S1] has `ADR:76 9th Avenue, 4th Floor, …` unescaped; accept it.)

### 4.4 BIZCARD

`BIZCARD:N:Sean;X:Owen;T:Software Engineer;C:Google;A:76 9th Avenue, New York, NY 10011;B:+12125551212;E:srowen@google.com;;`
[S1]. Keys: `N` first name, `X` last name, `T` title, `C` company, `A` address,
`B` phone (business), `M` mobile, `F` fax, `E` email. Same tokenising/escaping.
Vector: the example above → `{first:'Sean', last:'Owen', title:'Software Engineer', company:'Google', phones:[{value:'+12125551212', kind:'work'}], emails:['srowen@google.com']}`.

### 4.5 Other Japanese formats (identify only)

au/KDDI address book `MEMORY:…\r\nNAME1:…\r\nNAME2:…\r\nTEL1:…\r\nMAIL1:…\r\nADD:…`
**(unverified)**: if text starts with `MEMORY:` and contains `NAME1:` → `contact`,
map NAME1 (name), NAME2 (kana), TEL1-3, MAIL1-3, ADD (address), MEMORY (note).

---

## 5. Email

### 5.1 `mailto:` (RFC 6068 [S12])

```
mailtoURI = "mailto:" [ to ] [ hfields ]
to        = addr-spec *("," addr-spec)          ; percent-encoded
hfields   = "?" hfield *( "&" hfield )
hfield    = hfname "=" hfvalue                   ; hfname case-insensitive
```

- Decode `to` and each `hfvalue` with `decodeURIComponent` (try/catch); **`+` is a
  literal plus** (don't use `URLSearchParams`). `to` may also appear as an `hfield`
  (`?to=`) — merge. Known hfnames: `to cc bcc subject body in-reply-to`; others shown as extra.
- `body` line breaks are `%0D%0A`. Body/subject are text: run §1 checks; extract
  URLs from body (regex `https?://\S+`) and run §2 analysis on each (show
  warnings "Body contains link to …").
- Address syntax check: `local@domain` with a domain that passes WHATWG host
  parsing; IDN domain → apply §1.3/§2.3 host checks (homograph emails).

Warnings: `attach`, `attachment`, `attachments` (non-standard, some clients attached
local files: "Mailto: Me Your Secrets", Müller et al. 2020 [S13]) → **danger**
"Tries to attach a local file `…`"; `bcc` present → caution "Hidden recipients";
> 5 recipients → caution; long body (> 1000) → info; no recipient → info.

Actions: Open (confirm; main shows recipients + subject), copy address(es), copy body.

Vectors:

| Input | Expected |
|---|---|
| `"mailto:alice@example.com"` | to `['alice@example.com']` |
| `"mailto:a@example.com,b@example.com?subject=Hi%20there&body=Line1%0D%0ALine2&cc=c@example.com"` | to 2, cc `['c@example.com']`, subject `Hi there`, body `Line1\r\nLine2` |
| `"MAILTO:x+tag@example.com?subject=1+1"` | to `x+tag@example.com`, subject `1+1` (plus kept) |
| `"mailto:?to=a@example.com&bcc=spy@example.net&attach=/etc/passwd"` | to a@…; caution bcc; danger attach |
| `"mailto:support@pаypal.com"` | danger homograph in domain |

### 5.2 `MATMSG:` (DoCoMo)

`MATMSG:TO:<addr>;SUB:<subject>;BODY:<body>;;` — MECARD-style tokenising/escaping.
Vector: `"MATMSG:TO:a@example.com;SUB:Hello\\; world;BODY:See https://example.com;;"`
→ `{to:['a@example.com'], subject:'Hello; world', body:'See https://example.com'}`, body link analysed.

### 5.3 `SMTP:` (ZXing)

`SMTP:<addr>[:<subject>[:<body>]]` — split on the first two `:` only (the body may
contain `:`; the subject can't). Vectors: `"SMTP:a@example.com:Hello:See you at 10:30"`
→ `{to:['a@example.com'], subject:'Hello', body:'See you at 10:30'}`;
`"SMTP:a@example.com:Re: hi:x"` → subject `Re`, body ` hi:x` (format is ambiguous; follow
ZXing and show as-is).

---

## 6. Phone, SMS, FaceTime

### 6.1 `tel:` (RFC 3966 [S14])

```
telephone-uri = "tel:" ( global-number / local-number )
global-number = "+" digits-with-visual-separators *par        ; separators: - . ( )
local-number  = digits/*/#/A-D with separators *par ";phone-context=" descriptor *par
par           = ";ext=" … / ";isub=" … / ";phone-context=" … / ";" pname ["=" pvalue]
```

Display: E.164 digits grouped as given; params (`ext`) as fields; country from
the calling code prefix (small table of 1–3 digit codes, optional).

Warnings:
- contains `*` or `#` (also `%23`, `%2A`) → **danger** "This is a USSD/MMI service
  code, not a phone number; it can change phone settings (e.g. `*21*` call forwarding,
  `**21*`, `*#06#`)". Historic: Samsung `tel:*2767*3855#` factory-reset attack (2012).
- local number without `phone-context` → info "No country code".
- letters (vanity) → info; > 15 digits → caution invalid E.164.
- short numbers (3–6 digits, no `+`) → info "Short code".

Actions: Open (confirm — on macOS hands off to FaceTime/iPhone), copy number.

Vectors: `"tel:+1-201-555-0123"` → number `+12015550123`, display `+1-201-555-0123`;
`"tel:7042;phone-context=example.com"` → local; `"TEL:+44 20 7946 0958;ext=12"` →
caution whitespace (spaces are not allowed by RFC; accept with caution), ext `12`;
`"tel:*21*+15550100%23"` → danger USSD.

### 6.2 `sms:` / `mms:` (RFC 5724 [S15]) and `SMSTO:` / `MMSTO:`

- `sms:<recipient>[,<recipient>…][?body=<pct-encoded>]` — `+` literal; hfnames
  case-insensitive; only `body` defined. iOS-style `sms:+15550100&body=hi` (no `?`)
  → accept: if no `?` and `&body=` present, split there (info "non-standard").
  `mms:` same plus ZXing `subject`.
- `SMSTO:<number>:<message>` / `MMSTO:` (DoCoMo, ZXing) — split at the **first** `:`
  after the prefix; message may contain `:`; message is raw (not percent-encoded).

Warnings: short codes (≤ 6 digits, no `+`) → caution "Short code — could be a
premium-rate service"; multiple recipients → info; body with links → §2 analysis;
body with invisible chars → caution; recipient with `*`/`#` → danger.
Actions: Open `sms:` (confirm; Messages app), copy number, copy message. For `SMSTO:`
build `sms:<number>?body=<encodeURIComponent(msg)>` for Open.

Vectors: `"sms:+15105550101?body=hello%20there"`; `"sms:+15105550101,+15105550102?body=a+b"`
→ body `a+b`; `"SMSTO:+15105550101:Code: 1234"` → body `Code: 1234`;
`"smsto:12345:STOP"` → caution short code; `"sms:+15105550101&body=hi"` → body `hi`, info non-standard.

### 6.3 FaceTime

`facetime:<phone-or-email>`, `facetime://<…>`, `facetime-audio:<…>`,
`facetime-audio://<…>` (Apple URL Scheme Reference). Target is percent-decoded;
validate as phone (§6.1) or email (§5). Type `phone`, `data.service:'facetime'|'facetime-audio'`.
Vector: `"facetime:user@example.com"`, `"facetime-audio://+14085551234"`.

---

## 7. Geo

### 7.1 `geo:` (RFC 5870 [S16])

```
geo-URI     = "geo:" coord-a "," coord-b [ "," coord-c ] *( ";" param ) [ "?" query ]
coord       = [ "-" ] 1*DIGIT [ "." 1*DIGIT ]
; order per RFC: [";crs=" label] [";u=" uval] *(";" pname ["=" pvalue]); names case-insensitive
```

- Default CRS WGS-84: lat ∈ [-90, 90], lon ∈ [-180, 180], `coord-c` altitude in
  metres. `u=` uncertainty metres. `crs` ≠ `wgs84` → caution "Unknown coordinate system".
- At poles (`±90`) longitude is irrelevant; `-0` equals `0`.
- Android/Google extension: `geo:0,0?q=<address or lat,lon(label)>&z=<zoom>`
  (`q` percent-encoded, `+` = space here per Android usage).
- Display: decimal (6 dp) and DMS `40°43′07.4″N 73°59′20.6″W`; label from `q`.
- Out of range / unparsable → caution "Invalid coordinates".
- Actions: copy coordinates (`lat,lon`), "Copy as Apple Maps link"
  `https://maps.apple.com/?ll=<lat>,<lon>&q=<label>` and Google
  `https://www.google.com/maps/search/?api=1&query=<lat>,<lon>`; Open of those uses
  the normal URL confirm (note in UI: opening reveals the place to that service).

Vectors: `"geo:40.71872,-73.98905,100"` → `{lat:40.71872, lon:-73.98905, alt:100}`;
`"GEO:37.786971,-122.399677;crs=wgs84;u=35"` → u 35; `"geo:37.786971,-122.399677;u=35;crs=wgs84"` → accept, info "parameter order (RFC requires crs before u)"; `"geo:0,0?q=1600+Amphitheatre+Pkwy"` →
query label; `"geo:91,0"` → caution invalid; `"geo:48.2010,16.3695;crs=Moon-2011"` → caution crs.

### 7.2 Map URLs (type `url`, `special.kind:'map'`, `data.geo`)

| Pattern | Coordinates |
|---|---|
| `google.<tld>/maps/@<lat>,<lon>,<zoom>z` | `@lat,lon` |
| `google.<tld>/maps?q=<lat>,<lon>` / `?ll=` | q / ll |
| `google.com/maps/search/?api=1&query=<lat>,<lon>` / `/maps/dir/?api=1&destination=` | query / destination |
| `…/maps/place/<name>/@<lat>,<lon>,…/data=…!3d<lat>!4d<lon>` | prefer `!3d`/`!4d` (the pin) over `@` (the viewport) |
| `maps.app.goo.gl/<id>`, `goo.gl/maps/<id>` | none (shortener; say so) |
| `maps.apple.com/?ll=<lat>,<lon>&q=<label>`; `?q=`, `?address=`, `?daddr=`, `?sll=`; `maps.apple.com/place?coordinate=<lat>,<lon>&name=` (newer form) | ll / coordinate |
| `openstreetmap.org/?mlat=<lat>&mlon=<lon>` / `#map=<z>/<lat>/<lon>` | mlat/mlon or hash |
| `waze.com/ul?ll=<lat>,<lon>` | ll |

Summary: "Map: 48.858370, 2.294481 (Google Maps)".

---

## 8. Calendar (iCalendar subset, RFC 5545 [S17])

Detection: `BEGIN:VCALENDAR` or bare `BEGIN:VEVENT` (ZXing style). Support
`VEVENT` (and show `VTODO` summary-only). Multiple VEVENTs → list.

Line handling: as vCard (CRLF/LF; unfold CRLF+SPACE/TAB; quoted params).
TEXT value unescape: `\\ \; \, \n \N`. Lines are ≤ 75 octets in spec — don't
enforce.

Properties: `SUMMARY`, `DTSTART`, `DTEND`, `DURATION` (e.g. `PT1H30M`, `P1D`,
`-PT15M`), `LOCATION`, `DESCRIPTION`, `URL`, `ORGANIZER` (`mailto:`), `ATTENDEE`
(repeatable), `RRULE`, `GEO` (`lat;lon`), `UID`, `STATUS`, `CATEGORIES`, `VALARM`
(sub-component), `ATTACH`.

Date/time forms (`DTSTART`/`DTEND`):

| Form | Example | Meaning |
|---|---|---|
| `DATE` (`;VALUE=DATE`) | `20180601` | all-day; DTEND is **exclusive** (one-day event: 20180601→20180602) |
| UTC | `20180601T070000Z` | absolute; show in local tz and UTC |
| floating | `20180601T070000` | "local time wherever you are" (info) |
| with zone | `DTSTART;TZID=Europe/Berlin:20180601T090000` | convert via `Intl.DateTimeFormat({timeZone})` if the TZID is a valid IANA name (try/catch); otherwise show the TZID raw (Outlook names like `W. Europe Standard Time` → info) |

Lenient extras: some generators emit `DTSTART:2018-06-01T07:00:00Z` or `SUMMARY:Summer+Vacation!`
(ZXing's own example uses `+` for space [S1]) — accept ISO separators; keep `+` literal.

Display: title (SUMMARY), "Sat 1 Jun 2018, 09:00–10:30 (Europe/Berlin)", location,
description, organizer, attendee count, recurrence humanised (FREQ, INTERVAL, COUNT,
UNTIL, BYDAY), alarms.

Warnings: `URL`/`ATTACH`/links in DESCRIPTION → §2 analysis; `VALARM` with
`ACTION:EMAIL` or `ACTION:PROCEDURE` (deprecated) → caution; `RRULE` with
`FREQ=SECONDLY|MINUTELY|HOURLY` and no COUNT/UNTIL → caution "Repeats very
frequently, forever"; DTEND before DTSTART → caution invalid; > 20 attendees → info;
start more than 5 years away → info.

Actions: "Add to Calendar (.ics)": if the payload is only a VEVENT, wrap as
`BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//QR Reader//EN\r\n…\r\nEND:VCALENDAR`,
normalise to CRLF; `saveAs:{suggestedName: sanitize(SUMMARY)+'.ics', kind:'ics'}`.
Opening the .ics afterwards is the user's choice.

Vectors:

```
"BEGIN:VEVENT\nSUMMARY:Summer+Vacation!\nDTSTART:20180601T070000Z\nDTEND:20180831T070000Z\nEND:VEVENT"
→ event, summary 'Summer+Vacation!', start 2018-06-01T07:00:00Z, end 2018-08-31T07:00:00Z, allDay false
"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:Team sync\\, weekly\r\nDTSTART;TZID=Europe/Berlin:20261201T090000\r\nDURATION:PT30M\r\nRRULE:FREQ=WEEKLY;BYDAY=TU;COUNT=10\r\nLOCATION:Room 4\\; 2nd floor\r\nEND:VEVENT\r\nEND:VCALENDAR"
→ summary 'Team sync, weekly', start 2026-12-01 09:00 Europe/Berlin (= 08:00Z), end +30 min, rrule weekly Tue ×10, location 'Room 4; 2nd floor'
"BEGIN:VEVENT\nSUMMARY:Holiday\nDTSTART;VALUE=DATE:20261224\nDTEND;VALUE=DATE:20261227\nDESCRIPTION:Info: https://bit.ly/x\nEND:VEVENT"
→ allDay, 24–26 Dec (3 days), caution shortened link in description
"BEGIN:VEVENT\nSUMMARY:Spam\nDTSTART:20261201T090000Z\nRRULE:FREQ=MINUTELY\nEND:VEVENT"
→ caution frequent forever
```

---

## 9. Two-factor authentication

### 9.1 `otpauth://` Key URI (Google Authenticator format [S18])

```
otpauth://TYPE/LABEL?PARAMETERS
TYPE   = totp | hotp              (case-insensitive; others e.g. "steam" → caution unknown)
LABEL  = accountname | issuer (":" | "%3A") *("%20") accountname
```

Parse with WHATWG URL: `url.hostname` = TYPE (lowercase), `url.pathname.slice(1)` =
label (percent-decode with `decodeURIComponent`; `+` literal). Split label at the
first `:` (after decoding — both literal and `%3A` count); trim leading spaces of
the account name. Neither part may contain a colon (more colons → caution, keep
the rest in account).

Parameters (names case-sensitive in the spec; accept case-insensitively):

| Param | Rules | Default |
|---|---|---|
| `secret` | **required**; RFC 4648 base32 (`A–Z2–7`), case-insensitive; ignore spaces and `=` padding (spec says omit padding) | — |
| `issuer` | strongly recommended; should equal the label prefix | — |
| `algorithm` | `SHA1` / `SHA256` / `SHA512` | SHA1 |
| `digits` | `6` / `8` (7 occasionally) | 6 |
| `period` | seconds, TOTP only | 30 |
| `counter` | HOTP only, **required** for hotp | — |
| `image` | non-standard (FreeOTP): icon URL → caution "remote image link" | |

Base32 decoding: map chars to 5-bit values; reject `0 1 8 9` and other chars
(caution "Invalid secret"); leftover bits < 8 are dropped (non-zero leftovers → info).

Warnings: always **caution** "Contains a 2FA secret — anyone who sees this code can
generate your login codes. Don't share or screenshot it." Mark secret, live code
and full URI `sensitive`. Plus: issuer param ≠ label prefix → caution "Issuer
mismatch (label says X, issuer says Y)"; secret < 80 bits (16 base32 chars) →
caution weak (RFC 4226 requires ≥ 128, recommends 160 bits); missing counter for
hotp → caution invalid; digits not in 6..8 → caution; period not 30 → info
"Non-standard period 60 s (some apps ignore it)"; algorithm ≠ SHA1 → info "Some apps
(Google Authenticator historically) ignore algorithm/digits/period" [S18].

Display: issuer, account, type, algorithm, digits, period/counter, secret (masked,
mono, grouped in 4s), **live code** with seconds remaining (TOTP) or "code for
counter N" (HOTP; do not auto-increment). Actions: copy code (sensitive), copy secret
(sensitive), copy URI (sensitive).

### 9.2 Code computation (RFC 4226 HOTP, RFC 6238 TOTP [S19][S20])

```
HOTP(K, C) = Truncate(HMAC-H(K, C_8byte_bigendian)) mod 10^digits   (left-pad with '0')
Truncate: o = hmac[last] & 0x0f;
          bin = ((hmac[o] & 0x7f) << 24) | (hmac[o+1] << 16) | (hmac[o+2] << 8) | hmac[o+3]
TOTP(K, t) = HOTP(K, floor((t - T0) / period)), T0 = 0
```

WebCrypto: `crypto.subtle.importKey('raw', key, {name:'HMAC', hash:'SHA-1'|'SHA-256'|'SHA-512'}, false, ['sign'])`
then `sign('HMAC', key, counterBytes)`. Counter as 8-byte big-endian (use `DataView.setBigUint64`).

RFC 4226 Appendix D (key ASCII `12345678901234567890`, base32
`GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`, SHA-1, 6 digits), counter 0–9:
`755224 287082 359152 969429 338314 254676 287922 162583 399871 520489`.

RFC 6238 Appendix B (8 digits, period 30). Keys: SHA-1 `12345678901234567890` (20 B),
SHA-256 `12345678901234567890123456789012` (32 B), SHA-512
`1234567890123456789012345678901234567890123456789012345678901234` (64 B):

| Unix time | SHA-1 | SHA-256 | SHA-512 |
|---|---|---|---|
| 59 | 94287082 | 46119246 | 90693936 |
| 1111111109 | 07081804 | 68084774 | 25091201 |
| 1111111111 | 14050471 | 67062674 | 99943326 |
| 1234567890 | 89005924 | 91819424 | 93441116 |
| 2000000000 | 69279037 | 90698825 | 38618901 |
| 20000000000 | 65353130 | 77737706 | 47863826 |

(Recomputed with Node `crypto` in the scratchpad; matches the RFC.)
Extra vectors for secret `JBSWY3DPEHPK3PXP` (bytes `48656c6c6f21deadbeef`, SHA-1):
t=0 → `282760`, t=59 → `996554`, t=1700000000 → `324550` (6 digits) /
`02324550` (8 digits), period 60 at t=1700000000 → `508648`.

### 9.3 Vectors

| Input | Expected |
|---|---|
| `"otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"` | `{type:'totp', issuer:'Example', account:'alice@google.com', secretB32:'JBSWY3DPEHPK3PXP', algorithm:'SHA1', digits:6, period:30}`; caution secret |
| `"otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"` | issuer `ACME Co`, account `john.doe@email.com` |
| `"otpauth://totp/Big%20Corporation%3A%20alice%40bigco.com?secret=jbsw y3dp ehpk 3pxp====&issuer=Big%20Corporation"` | account `alice@bigco.com` (leading space trimmed), secret normalised `JBSWY3DPEHPK3PXP` (lowercase/spaces/padding accepted, info) |
| `"otpauth://hotp/Svc:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=5"` | hotp counter 5; code `254676` |
| `"otpauth://hotp/Svc:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"` | caution missing counter |
| `"otpauth://totp/PayPal:me?secret=JBSWY3DPEHPK3PXP&issuer=Evil"` | caution issuer mismatch |
| `"otpauth://totp/X?secret=ABC1"` | caution invalid base32 (`1`) |

### 9.4 `otpauth-migration://offline?data=…` (Google Authenticator export)

`data` = **standard base64** (`+ /`, `=` padding) of a protobuf `MigrationPayload`,
URL-encoded. Extract `data` by locating `data=` in the raw query and
`decodeURIComponent` it (not `URLSearchParams`: an unencoded `+` would become a
space). Also map spaces back to `+` and accept base64url (`- _`), missing padding.

Schema (proto3; community reverse-engineered, used by many importers [S21]):

```proto
message MigrationPayload {
  enum Algorithm  { ALGORITHM_UNSPECIFIED = 0; ALGORITHM_SHA1 = 1; ALGORITHM_SHA256 = 2;
                    ALGORITHM_SHA512 = 3; ALGORITHM_MD5 = 4; }
  enum DigitCount { DIGIT_COUNT_UNSPECIFIED = 0; DIGIT_COUNT_SIX = 1; DIGIT_COUNT_EIGHT = 2; }
  enum OtpType    { OTP_TYPE_UNSPECIFIED = 0; OTP_TYPE_HOTP = 1; OTP_TYPE_TOTP = 2; }
  message OtpParameters {
    bytes      secret    = 1;   // raw key bytes (NOT base32)
    string     name      = 2;   // account label; may itself be "Issuer:account"
    string     issuer    = 3;
    Algorithm  algorithm = 4;
    DigitCount digits    = 5;
    OtpType    type      = 6;
    int64      counter   = 7;   // HOTP
  }
  repeated OtpParameters otp_parameters = 1;
  int32 version     = 2;
  int32 batch_size  = 3;   // number of QR codes in this export
  int32 batch_index = 4;   // 0-based index of this QR
  int32 batch_id    = 5;   // random; same for all QRs of one export (may be negative)
}
```

Minimal protobuf decoder (wire format):

- A message is a sequence of `key, value`. `key` = varint; `field = key >>> 3`,
  `wire = key & 7`.
- **varint**: little-endian base-128; each byte contributes `b & 0x7f`, continue while
  `b & 0x80`. Max 10 bytes; accumulate in `BigInt` (or two 32-bit halves). For
  `int32` fields take `BigInt.asIntN(32, v)` (negative int32 is sign-extended to
  64 bits and always occupies 10 bytes); `int64` → `BigInt.asIntN(64, v)`; enums: Number.
- wire 0 varint; wire 2 length-delimited (`len` varint, then `len` bytes — bounds-check);
  wire 1 = 8 bytes, wire 5 = 4 bytes (skip); wire 3/4 (groups) or 6/7 → error.
- Unknown fields: skip. Repeated field 1 may occur many times. Proto3 missing
  scalar = 0 (so `UNSPECIFIED`): treat algorithm 0 → SHA1, digits 0 → 6, type 0 →
  TOTP, but show info "unspecified".
- Limits: input ≤ 8 KB, nesting depth 2, ≤ 100 entries, string fields UTF-8 decoded
  with `TextDecoder('utf-8', {fatal:false})`.

Per entry → convert to an `otpauth://` view: secret → base32 (no padding), digits
1→6, 2→8, algorithm 1..3 → SHA1/256/512, 4 → MD5 (caution "MD5 not supported by
most apps; code can't be computed with WebCrypto"), period always 30.

`Analysis` (`type:'otp-migration'`): title "Authenticator export (N accounts)";
**danger** "This QR contains N two-factor secrets. Anyone who sees it can take over
those accounts' 2FA."; `batch_size > 1` → info "Part i+1 of n — scan every part".
Each entry: issuer, name, type, algorithm, digits, counter, live code (sensitive),
actions "Copy as otpauth:// URI" (sensitive; build
`otpauth://totp/<encodeURIComponent(issuer)>:<encodeURIComponent(name)>?secret=…&issuer=…&algorithm=…&digits=…[&counter=…]`).

**Constructed & verified vector** (encoded and independently decoded by
`scratchpad/mig.mjs`):

```
otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUuY29tGgdFeGFtcGxlIAEoATACCjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgtBQ01FIENvOmJvYhoHQUNNRSBDbyACKAIwATisAhABGAEgACj50rT%2F%2F%2F%2F%2F%2F%2F8B
```

Payload hex (130 bytes):
```
0a2e 0a0a48656c6c6f21deadbeef 1211616c696365406578616d706c652e636f6d 1a074578616d706c65 2001 2801 3002
0a35 0a143132333435363738393031323334353637383930 120b41434d4520436f3a626f62 1a0741434d4520436f 2002 2802 3001 38ac02
1001 1801 2000 28f9d2b4ffffffffffff01
```

Decoded:
```json
{ "otp": [
   { "secret": "JBSWY3DPEHPK3PXP", "name": "alice@example.com", "issuer": "Example",
     "algorithm": 1, "digits": 1, "type": 2 },
   { "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "name": "ACME Co:bob", "issuer": "ACME Co",
     "algorithm": 2, "digits": 2, "type": 1, "counter": 300 } ],
  "version": 1, "batch_size": 1, "batch_index": 0, "batch_id": -1234567 }
```
Expected view: entry 1 = TOTP SHA1 6 digits (at t=59 → `996554`); entry 2 = HOTP
SHA256 8 digits counter 300, name `ACME Co:bob` → account `bob` (strip the
`issuer:` prefix when it equals `issuer`). Tricky bits exercised: non-ASCII secret
bytes (`de ad be ef`), `%2F` in data, 2-byte varint (`ac 02` = 300), 10-byte negative
int32 (`f9 d2 b4 ff ff ff ff ff ff 01` = −1234567), `batch_index` 0 encoded explicitly.
Negative tests: truncate the data by 3 bytes → error "truncated"; wire type 3 →
error; `data=` missing → caution invalid.

---

## 10. Payments

General display rule for every payment type: a "What you'd pay" header —
**amount + currency**, **beneficiary name**, **account (IBAN/address) grouped**,
reference — followed by validation badges (✓ IBAN checksum, ✓ CRC, ✓ reference
check digit). Always add info "Paying happens in your banking app; compare these
details with the invoice." Actions: copy IBAN (without spaces), copy amount,
copy reference, copy beneficiary, copy all as text. No Open.

Common validators:

- **IBAN (ISO 13616) mod-97**: remove spaces, uppercase; check `^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$`;
  move first 4 chars to the end; replace letters A=10 … Z=35; compute mod 97
  incrementally digit by digit; valid iff result = 1. Optional per-country length
  table (DE 22, AT 20, CH 21, LI 21, FR 27, IT 27, ES 24, NL 18, BE 16, GB 22, IE 22,
  PL 28, CZ 24, SK 24, …). Verified: `DE71110220330123456789` ✓,
  `FR1420041010050500013M02606` ✓, `DE89370400440532013000` ✓,
  `DE89370400440532013001` ✗, `CH9300762011623852957` ✓, `CH4431999123000889012` ✓.
  Display in groups of 4.
- **ISO 11649 RF creditor reference**: `RF` + 2 check digits + 1–21 alnum; same
  mod-97 rule as IBAN (move first 4 to end) ⇒ 1. `RF18539007547034` ✓.
- **BIC**: `^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$`.

### 10.1 EPC069-12 SEPA Credit Transfer ("GiroCode", "EPC QR") [S5]

Defined by EPC069-12 v3.0 (2022). QR EC level M, max version 13, **max 331 bytes**.
Elements separated by **LF or CRLF**; "the last populated element is not followed by
any character or element separator" (be lenient: accept a trailing newline, info).
Empty optional elements are empty lines; trailing empty elements may be omitted.

| Line | O/M | Max | Content |
|---|---|---|---|
| 1 | M | 3 | Service tag `BCD` |
| 2 | M | 3 | Version `001` or `002` |
| 3 | M | 1 | Character set `1`–`8` (table below) |
| 4 | M | 3 | Identification `SCT` |
| 5 | V1: M; V2: O within EEA | 8/11 | BIC of beneficiary PSP |
| 6 | M | 70 | Beneficiary name |
| 7 | M | 34 | Beneficiary IBAN (only IBAN) |
| 8 | O | 12 | Amount `EUR` + `#.##`; 0.01 ≤ amount ≤ 999999999.99 (e.g. `EUR12.3`) |
| 9 | O | 4 | Purpose code (ISO 20022 ExternalPurpose, e.g. `GDDS`, `CHAR`, `SALA`) |
| 10 | O {or} | 35 | Structured remittance: creditor reference (ISO 11649 RF may be used) |
| 11 | O {or} | 140 | Unstructured remittance text |
| 12 | O | 70 | Beneficiary to originator information (shown to payer, not transmitted) |

Lines 10 and 11 are mutually exclusive ("only one of the elements may be populated").
"Fixed" (payer should not change): BIC, name, IBAN, structured reference.

Character sets: `1` UTF-8, `2` ISO 8859-1, `3` ISO 8859-2, `4` ISO 8859-4,
`5` ISO 8859-5, `6` ISO 8859-7, `7` ISO 8859-10, `8` ISO 8859-15.
**Decode from `bytesBase64`** with `new TextDecoder(label)` using that table when the
charset isn't 1 (Vision's `text` may have guessed wrongly). If bytes are unavailable,
use `text` and info "charset N declared; text decoding not verified".

Detection: line 1 === `BCD` exactly (uppercase) and line 4 === `SCT`; otherwise not EPC
(fall through). Validation → warnings: version not 001/002 → caution; charset
outside 1–8 → caution; V1 without BIC → caution; IBAN checksum fails → **danger**
"IBAN checksum invalid — likely tampered or mistyped"; amount bad format/range or
non-EUR → caution; both 10 and 11 → caution; RF reference invalid → caution;
lengths exceeded → caution; total > 331 bytes → info; > 12 lines → caution.
Beneficiary name with invisible chars / mixed scripts → caution. Info: "Your bank
will check the name against the IBAN (EU Verification of Payee, Reg. 2024/886)".

Vectors (from the spec, §2.3, reconstructed; 95 chars / 96 bytes UTF-8 for V1,
103 bytes ISO-8859-1 for V2):

```
"BCD\n001\n1\nSCT\nBHBLDEHHXXX\nFranz Mustermänn\nDE71110220330123456789\nEUR12.3\nGDDS\nRF18539007547034"
→ epc-payment {version:'001', charset:1, bic:'BHBLDEHHXXX', name:'Franz Mustermänn',
   iban:'DE71110220330123456789', ibanValid:true, amount:'12.30', currency:'EUR', purpose:'GDDS',
   reference:'RF18539007547034', referenceValid:true}; no warnings
bytes(latin1) "BCD\n002\n2\nSCT\n\nFrançois D'Alsace S.A.\nFR1420041010050500013M02606\nEUR12.3\n\n\nClient:Marie Louise La Lune"
→ version '002', charset 2 (decode bytes as ISO-8859-1 → 'François'), bic '', amount 12.30, text 'Client:Marie Louise La Lune'
"BCD\r\n002\r\n1\r\nSCT\r\n\r\nShop\r\nDE89370400440532013001\r\nEUR5\r\n\r\nRF18539007547034\r\nalso text"
→ CRLF ok; danger IBAN invalid; caution both structured and unstructured remittance
"BCD\n001\n1\nSCT\n\nX\nDE89370400440532013000\nUSD10"
→ caution V1 missing BIC; caution non-EUR amount
```

### 10.2 Swiss QR-bill (`SPC`) — Implementation Guidelines v2.3 (valid from 21 Nov 2025) [S6][S7]

UTF-8 only; separators CRLF or LF (consistent within a payload); each element on
its own line, empty elements still present as empty lines; QR EC level M; max 997
characters. v2.3 changes: address type `K` (combined) **removed** — only `S`;
ultimate creditor must be empty; extended character set = Basic Latin U+0020–007E,
Latin-1 Supplement U+00A0–00FF, Latin Extended-A U+0100–017F, plus Ș ș Ț ț €
(U+0218, U+0219, U+021A, U+021B, U+20AC); QR reference must not be all zeros;
SCOR reference 5–25 chars. (v2.4, valid from 14 Nov 2026, exists; no payload
changes found in summaries — verify against the PDF before relying on this.)

| # | Element | Rules |
|---|---|---|
| 1 | QRType | `SPC` |
| 2 | Version | `0200` (accept `02xx`) |
| 3 | Coding | `1` (UTF-8) |
| 4 | IBAN | 21 chars, `CH`/`LI`, no spaces; **QR-IBAN** iff IID (chars 5–9) ∈ 30000–31999 |
| 5–11 | Creditor: AdrTp, Name (70), Street (70), Building no. (16), Postal code (16), Town (35), Country (2) | AdrTp `S` (or legacy `K`: line 7 = address line 1, line 8 = address line 2 (70), 9/10 empty) |
| 12–18 | Ultimate creditor (7 lines) | must be empty |
| 19 | Amount | `^\d{1,9}\.\d{2}$`-ish, 0.01–999999999.99, or empty (payer enters) |
| 20 | Currency | `CHF` or `EUR` |
| 21–27 | Ultimate debtor: AdrTp, Name, Street, Bldg, PostCode, Town, Country | optional group (all empty or complete) |
| 28 | Reference type | `QRR` / `SCOR` / `NON` |
| 29 | Reference | QRR: 27 digits, mod-10 recursive; SCOR: ISO 11649 RF; NON: empty |
| 30 | Unstructured message | ≤ 140 |
| 31 | Trailer | `EPD` |
| 32 | Bill information | optional, ≤ 140 (e.g. Swico `//S1/10/…/11/…`) — show raw |
| 33–34 | Alternative procedures | optional, ≤ 100 each, max 2 (e.g. `eBill/B/…`) |

Consistency rules: QR-IBAN ⇔ `QRR` (QR-IBAN with SCOR/NON, or normal IBAN with
QRR → **danger** "Reference type doesn't match the account type"). Messages +
bill info combined ≤ 140 chars.

**Mod-10 recursive** (QR reference / ESR): table `[0,9,4,6,8,2,7,1,3,5]`; `c=0`; for
each digit d of the first 26: `c = table[(c + d) % 10]`; check digit = `(10 - c) % 10`.
Verified: `21000000000313947143000901` → check `7`. Display QRR grouped
`21 00000 00003 13947 14300 09017`.

Warnings: version/coding mismatch → caution; IBAN checksum (mod-97) → danger;
QRR check digit wrong → danger; trailer missing → caution "Not a complete QR-bill";
address type K → info "Outdated address format (not allowed since 21 Nov 2025)";
non-allowed characters → caution; ultimate creditor filled → caution.

Vector (structure of the SIX examples, values verified by script):

```
SPC
0200
1
CH4431999123000889012
S
Robert Schneider AG
Rue du Lac
1268
2501
Biel
CH
(7 empty lines: 12–18)
1949.75
CHF
S
Pia-Maria Rutschmann-Schnyder
Grosse Marktgasse
28
9400
Rorschach
CH
QRR
210000000003139471430009017
Order of 15 June 2020
EPD
//S1/10/10201409/11/200701/20/140.000-53/30/102673831/31/200615/32/7.7/33/7.7:5.09/40/0:30
eBill/B/john.doe@example.com
```

→ `{iban:'CH4431999123000889012', qrIban:true, ibanValid:true, creditor:{name:'Robert Schneider AG', street:'Rue du Lac', building:'1268', postcode:'2501', town:'Biel', country:'CH'}, amount:'1949.75', currency:'CHF', debtor:{name:'Pia-Maria Rutschmann-Schnyder', …}, refType:'QRR', reference:'210000000003139471430009017', referenceValid:true, message:'Order of 15 June 2020', billInfo:'//S1/…', altProcedures:['eBill/B/john.doe@example.com']}`.
Tricky variants: same with `CH9300762011623852957` (normal IBAN) + `QRR` → danger
mismatch; `SCOR` + `RF18539007547034` with the normal IBAN → valid; amount line empty
→ info "amount to be entered by payer"; creditor AdrTp `K` → info outdated.

### 10.3 Czech "QR Platba" — `SPD*1.0*` [S22]

```
SPD*<version>*KEY:value*KEY:value*…     (trailing '*' optional)
```

Header `SPD`, version `1.0`. Values may contain any chars except `*`; `*` must be
`%2A` (values may be percent-encoded generally — decode `%XX`). Recommended charset
is uppercase alnum + ` $%*+-./:`; keys uppercase. Keys:

| Key | Max | Meaning |
|---|---|---|
| `ACC` | 46 | **required**: `IBAN[+BIC]` |
| `ALT-ACC` | 93 | alternative accounts, comma-separated `IBAN[+BIC]` |
| `AM` | 10 | amount, `.` decimal, ≤ 2 dp |
| `CC` | 3 | currency ISO 4217 (default CZK) |
| `RF` | 16 | payment identifier (digits) |
| `RN` | 35 | recipient name |
| `DT` | 8 | due date `YYYYMMDD` |
| `PT` | 3 | payment type (`IP` = instant) |
| `MSG` | 60 | message |
| `CRC32` | 8 | CRC32 hex of the canonical payload (optional) |
| `NT` / `NTA` | 1 / 320 | notification channel `P`/`E` + address |
| `X-VS` / `X-SS` / `X-KS` | 10 | variable / specific / constant symbol (digits) |
| `X-PER` | 2 | retry days 0–30 |
| `X-ID` | 20 | payer's id |
| `X-URL` | 140 | URL → §2 analysis |

Vectors: `"SPD*1.0*ACC:CZ9106000000000000000123*AM:450.00*CC:CZK*MSG:PLATBA ZA ZBOZI*X-VS:1234567890"`
→ payment spd `{iban:'CZ9106000000000000000123', amount:'450.00', currency:'CZK', message:'PLATBA ZA ZBOZI', vs:'1234567890'}`;
`"SPD*1.0*ACC:CZ5855000000001265098001+RZBCCZPP*AM:480.50*CC:CZK*RN:FIRMA%2A S.R.O.*DT:20261231"` → bic `RZBCCZPP`, name `FIRMA* S.R.O.`, due 2026-12-31.
IBAN check as §10; missing ACC → caution invalid. (The SK "PAY by square" format is
LZMA-compressed base32 — not identifiable reliably; leave as text.)

### 10.4 Bezahlcode (Germany, legacy) **(unverified details)**

`bank://singlepayment?…`, `bank://singlepaymentsepa?…`, `bank://singledirectdebit…`,
`bank://periodicsinglepayment…`. Params: `name`, `account`+`BNC` (old) or `iban`+`bic`,
`amount` (**comma** decimal, e.g. `9,90`), `currency`, `reason` (purpose text),
`executiondate` (`DDMMYYYY`), `period`, `periodlastexecutiondate`. Percent-encoded.
Mostly superseded by EPC QR (GiroCode). Display like EPC; IBAN check.
Vector: `"bank://singlepaymentsepa?name=Max%20Muster&reason=Rechnung%2012&iban=DE89370400440532013000&bic=COBADEFFXXX&amount=9,90"`
→ `{name:'Max Muster', iban:'DE89370400440532013000', bic:'COBADEFFXXX', amount:'9.90', currency:'EUR', reason:'Rechnung 12'}`.

### 10.5 EMVCo Merchant-Presented QR (Pix, PromptPay, PayNow, QRIS, VietQR, FPS, UPI-EMV, …) [S23][S24]

**TLV grammar**: sequence of `ID(2 digits) LEN(2 digits, decimal) VALUE(LEN chars)`.
Template values (IDs 26–51, 62, 64, 80–99) contain nested TLVs with the same grammar.
Payload must start with `000201` (ID 00 Payload Format Indicator = `01`) and end
with ID `63` length `04` + CRC.

**CRC**: CRC-16/CCITT-FALSE — poly `0x1021`, init `0xFFFF`, no reflection, xorout 0
— over all bytes from the start **through the `6304`** (ID + length of the CRC field),
UTF-8. Result as 4 uppercase hex chars (accept lowercase, info). Check value
`crc("123456789") = 29B1`.

```js
let c = 0xFFFF; for (const b of bytes) { c ^= b << 8; for (let i = 0; i < 8; i++) c = (c & 0x8000) ? ((c << 1) ^ 0x1021) & 0xFFFF : (c << 1) & 0xFFFF; }
```

Parsing algorithm: `i=0; while i < s.length: id=s.substr(i,2), len=+s.substr(i+2,2)`
(both must be digits), `v = s.substr(i+4, len)`; error if out of bounds; push; `i += 4+len`.
LEN counts characters (code points); payloads should be ASCII — if non-ASCII is
present and code-point counting fails, retry with UTF-8 byte counting (info).
Detection succeeds only if the whole string parses, first TLV is `00`=`01` and
the last is `63` with 4 chars; else fall through to text.

Top-level IDs:

| ID | Name |
|---|---|
| 00 | Payload Format Indicator (`01`) |
| 01 | Point of Initiation: `11` static (reusable), `12` dynamic (one-time) |
| 02–25 | Card-network merchant account info (02–03 Visa, 04–05 Mastercard, 06–08 EMVCo, 09–10 Discover, 11–12 Amex, 13–14 JCB, 15–16 UnionPay, 17–25 EMVCo) |
| 26–51 | Merchant Account Information templates: sub-ID `00` = Globally Unique Identifier (reverse domain or AID) identifying the scheme |
| 52 | Merchant Category Code (4 digits; `0000` = not used) |
| 53 | Transaction currency, ISO 4217 **numeric** (986 BRL, 356 INR, 764 THB, 702 SGD, 360 IDR, 704 VND, 344 HKD, 458 MYR, 840 USD, 978 EUR, 156 CNY) |
| 54 | Transaction amount (decimal, `.`) — absent = payer enters |
| 55 | Tip/convenience indicator: `01` prompt, `02` fixed (56), `03` percentage (57) |
| 56 / 57 | Convenience fee fixed / percentage |
| 58 | Country code (ISO 3166 alpha-2) |
| 59 | Merchant name (≤ 25) |
| 60 | Merchant city (≤ 15) |
| 61 | Postal code |
| 62 | Additional Data template: 01 bill number, 02 mobile, 03 store label, 04 loyalty, 05 reference label (Pix: txid, `***` = none), 06 customer label, 07 terminal label, 08 purpose, 09 additional consumer data request, 10 merchant tax id, 11 merchant channel |
| 63 | CRC |
| 64 | Merchant Info Language template: 00 language, 01 alt name, 02 alt city |
| 80–99 | Unreserved templates |

Scheme identification via sub-`00` (GUI) of 26–51:

| GUI | Scheme |
|---|---|
| `br.gov.bcb.pix` (case-insens.) | **Pix** (Brazil): sub 01 = Pix key (email, phone `+55…`, CPF/CNPJ, or random UUID), 02 = description, 25 = URL of dynamic payload (no scheme, e.g. `qrpix.example.com/qr/v2/…`) |
| `A000000677010111` / `A000000677010112` | PromptPay (Thailand) credit transfer / bill payment **(unverified)** |
| `SG.PAYNOW` | PayNow (Singapore) **(unverified)** |
| `ID.CO.QRIS.WWW` | QRIS (Indonesia) **(unverified)** |
| `A000000727` | NAPAS / VietQR (Vietnam) **(unverified)** |
| `hk.com.hkicl` | FPS (Hong Kong) **(unverified)** |

Display: scheme, merchant name + city + country, amount + currency (map numeric
code), static/dynamic, Pix key (with key kind), txid, description. Warnings: CRC
mismatch → **danger** "Checksum wrong — code damaged or altered"; dynamic
(01=12 or Pix sub-25 URL) → info "Final amount/recipient are fetched by your bank
app from <host>"; Pix key is a phone/email → info; merchant name with invisible chars →
caution; amount absent → info.

Vectors:

```
"00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-4266554400005204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***63041D3D"
→ payment emv/pix, static (no 01), key '123e4567-e12b-12d1-a456-426655440000' (random key), currency BRL,
  merchant 'Fulano de Tal', city 'BRASILIA', txid '***', crc OK (1D3D)   [BCB manual example]
"00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-426655440000520400005303986540510.005802BR5913Fulano de Tal6008BRASILIA62070503***6304288F"
→ amount 10.00 BRL; crc OK (288F)   [constructed]
"00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-426655440000520400005303986540599.005802BR5913Fulano de Tal6008BRASILIA62070503***6304288F"
→ amount 99.00 but CRC mismatch → danger (amount tampered)
"00020101021226830014br.gov.bcb.pix2561qrpix.example.com/qr/v2/cobv/9d36b84fc70b478fb95c12729b90ca25520400005303986540525.505802BR5912EXEMPLO LTDA6009SAO PAULO62070503***63048E28"
→ dynamic (01=12), url 'qrpix.example.com/qr/v2/cobv/…', amount 25.50; crc OK (8E28)   [constructed]
```

### 10.6 UPI (India) `upi://pay?…` [S25]

Params (all percent-encoded): `pa` payee VPA (`name@handle`, **required**), `pn`
payee name, `am` amount, `mam` minimum amount, `cu` currency (`INR`), `tn`
transaction note, `tr` transaction ref, `tid` txn id, `mc` MCC, `url` info URL,
`mode`, `purpose`, `orgid`, `sign` (signed merchant QR). Also `upi://mandate?…`
(autopay mandate → caution "Sets up recurring debits"). Display payee VPA + name,
amount. Warnings: info "Name `pn` is set by whoever made this code; your UPI app shows
the registered name — compare it"; danger-ish text for the "scan to receive money"
scam: info "Scanning a payment QR only ever SENDS money"; `am` present + `cu`≠INR →
caution; `url` → §2.

Vectors: `"upi://pay?pa=merchant@okaxis&pn=Example%20Store&am=150.00&cu=INR&tn=Order%2042&tr=ORD42"`
→ `{vpa:'merchant@okaxis', name:'Example Store', amount:'150.00', currency:'INR', note:'Order 42', ref:'ORD42'}`;
`"UPI://PAY?pa=a.b-c@ybl"` → amount absent info; `"upi://pay?pn=X"` → caution missing pa.

### 10.7 Cryptocurrency URIs (`type:'crypto'`)

Common display: network, address (mono, grouped in 4s, **first 6 and last 6
highlighted** — address-poisoning attacks reuse look-alike prefixes/suffixes),
amount (both coin and smallest unit), label/message. Always info "Crypto payments
are irreversible; verify the whole address." Actions: copy address, copy amount, copy
URI.

**BIP21 `bitcoin:`** [S26]:
```
bitcoinurn = "bitcoin:" [ address ] [ "?" params ]
params: amount=<decimal BTC, '.' only>  label=  message=  req-<x>=  (unknown req-* → URI invalid)
        common extensions: lightning=<BOLT11> (unified QR), pj= (payjoin endpoint URL), sp= (silent payment)
```
Scheme case-insensitive; uppercase bech32 (`BC1Q…`) is common in QR. Address kinds:
`1…` P2PKH, `3…` P2SH (base58check, 25–34 chars), `bc1q…` (bech32, 42 or 62),
`bc1p…` (bech32m taproot, 62); testnet `tb1`, `m`, `n`, `2`. Validation optional but
cheap: bech32/bech32m polymod (sync, ~30 lines) and base58check (double SHA-256 →
async WebCrypto). Warnings: invalid checksum → danger; unknown `req-` → caution
"Wallet must refuse this"; `pj=` → info (wallet contacts a server); testnet → info.
Vectors:
`"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"`
→ amount 50 BTC, label `Luke-Jr`, message `Donation for project xyz`;
`"BITCOIN:BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ?amount=0.00001&lightning=LNBC10U1P…"`
→ bech32 (uppercase accepted), amount 0.00001 BTC (1000 sat), lightning invoice present;
`"bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?req-somethingyoudontunderstand=50"` → caution unknown req.

**Lightning** (`lightning:<bolt11>` or bare): BOLT11 invoice = bech32 string,
case-insensitive, human-readable part `ln` + currency (`bc` mainnet, `tb` testnet,
`tbs` signet, `bcrt` regtest) + optional amount = digits + optional multiplier
`m` (10⁻³), `u` (10⁻⁶), `n` (10⁻⁹), `p` (10⁻¹²) BTC; separator = **last** `1` [S27].
Show "Lightning invoice, 2500 µBTC = 0.0025 BTC = 250,000 sat". No amount → "any amount".
Expiry/description need bech32 data decoding (5-bit → tagged fields: `d` description,
`x` expiry, `n` payee pubkey) — optional. `LNURL1…` (bech32 of an https URL) /
`lnurlp://`, `lnurlw://` → decode and show the URL (§2). Vectors: `"lightning:lnbc2500u1pvjluez…"`
→ amount 0.0025 BTC mainnet; `"LNTB1U1…"` → testnet 1 µBTC; `"lnbc1pvjluez…"` → no amount.

**EIP-681 `ethereum:`** [S28]:
```
request = "ethereum:" ["pay-"] target_address ["@" chain_id] ["/" function_name] ["?" parameters]
target_address = "0x" 40 hex  |  ENS name
parameters: value=<number in wei>  gasLimit=  gasPrice=  gas=  and for functions: <abi type>=<value>, e.g. address=0x…&uint256=…
number = digits ["." digits] ["e" digits]   (scientific notation allowed: value=2.014e18)
```
Chain ids to label: 1 Ethereum, 10 OP, 56 BNB, 100 Gnosis, 137 Polygon, 8453 Base,
42161 Arbitrum, 11155111 Sepolia (testnet). Warnings: `function_name=transfer` →
the **recipient is the `address` parameter, the target is the token contract** —
display "Token transfer: send <uint256> units of token 0x89…e7 to 0x8e…52"; `approve`
/ `setApprovalForAll` / `increaseAllowance` → **danger** "Grants someone permission to
spend your tokens"; other function → caution "Calls contract function X"; ENS name →
info "Name resolved by wallet"; checksum (EIP-55 mixed case) needs Keccak-256 (not
in WebCrypto) — either bundle a ~100-line Keccak or show info "Checksum not verified".
Vectors: `"ethereum:0xfb6916095ca1df60bb79Ce92cE3Ea74c37c5d359?value=2.014e18"` →
2.014 ETH, chain 1; `"ethereum:0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7/transfer?address=0x8e23ee67d1332ad560396262c48ffbb01f93d052&uint256=1"`
→ token transfer, recipient 0x8e23…; `"ethereum:pay-0xfb6916095ca1df60bb79Ce92cE3Ea74c37c5d359@137?value=1e18"`
→ Polygon 1 (MATIC/POL); `"ethereum:0x…/approve?address=0xdead…&uint256=1e77"` → danger.
Bare `0x` + 40 hex text → `crypto` with info "EVM address (network unknown)".

**Other schemes** (BIP21-like unless noted):

| Scheme | Notes |
|---|---|
| `litecoin:`, `dogecoin:`, `dash:`, `zcash:`, `bitcoincash:` | `amount`, `label`, `message`; bitcoincash uses cashaddr (`bitcoincash:q…`, the prefix is part of the address) |
| `monero:<addr>?tx_amount=&recipient_name=&tx_description=&tx_payment_id=` | addresses start `4` (standard, 95 chars) or `8` (subaddress) |
| `solana:<base58 recipient>?amount=&spl-token=<mint>&reference=&label=&message=&memo=` (Solana Pay transfer) | `solana:<percent-encoded https URL>` = **transaction request**: wallet fetches a transaction from that server → caution "Wallet will load a transaction from <host>"; analyse the URL |
| `ton://transfer/<addr>?amount=<nanoton>&text=` | amount in nanoton (10⁻⁹) |
| `tron:`, `xrpl:`/`ripple:`, `stellar` (`web+stellar:pay?destination=&amount=&asset_code=`), `web+cardano:`, `algorand://`, `cosmos:` | identify + show address/amount params generically |

---

## 11. Misc payloads

### 11.1 App store / messenger / meeting links

Covered in §2.8 (they are URLs). Non-http forms (`market://details?id=`,
`itms-apps://`, `tg://resolve?domain=`, `whatsapp://send?phone=`, `zoommtg://…`)
are copy-only with the same summary line.

### 11.2 `magnet:` (BitTorrent)

`magnet:?xt=urn:btih:<40 hex | 32 base32>&dn=<name>&tr=<tracker url>&xl=<bytes>&ws=<web seed>`
(also `urn:btmh:1220<sha256 hex>` for v2). Params repeat (`tr`, `xt.1`). Show name,
info-hash (mono), size, tracker hosts (each → registrable domain). Copy-only, info
"Opening starts a peer-to-peer download; your IP is visible to peers".
Vector: `"magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=Example%20File&tr=udp%3A%2F%2Ftracker.example.org%3A1337"`
→ `{infoHash:'c12fe1c06bba254a9dc9f519b335aa7c1367a88a', name:'Example File', trackers:['udp://tracker.example.org:1337']}`.

### 11.3 `ssh://`, `sftp://`, `ftp://`, `smb://`, `vnc://`, `rdp://`

Parse as URL (`ssh://user@host:2222`, OpenSSH also accepts `ssh://host;fingerprint=SHA256-…`
**(draft syntax)**). Show user/host/port; copy-only (suggest command
`ssh -p 2222 user@host` as a copy action). caution for `smb:`/`afp:` (Finder mounts
the share, may send credentials).

### 11.4 Health certificates (identify; decoding optional)

| Prefix | Format | Decode feasibility (no deps) |
|---|---|---|
| `HC1:` | EU Digital COVID Certificate: `HC1:` + Base45(zlib(COSE_Sign1(CBOR CWT))) [S29] | **Feasible**: Base45 ~20 lines; zlib via `new DecompressionStream('deflate')` (Chromium/Electron & Node 18+; async); COSE_Sign1 = CBOR tag 18 array `[protected bstr, unprotected map, payload bstr, signature bstr]`; payload CWT map keys 1 iss, 4 exp, 6 iat, −260 → {1: DCC JSON-like map (nam, dob, v/t/r)}. Needs a minimal CBOR decoder (~150 lines). **Signature cannot be verified offline** (trust lists are online). The EU DCC regulation expired 30 Jun 2023; framework continued as WHO GDHCN. Recommend: identify + optionally show name/DOB/dates with info "Signature not verified; contains personal health data" (sensitive) |
| `shc:/` | SMART Health Card (US/CA): digits; each pair `nn` → `String.fromCharCode(nn+45)` gives a compact JWS; payload is raw DEFLATE (`zip:"DEF"`) → `DecompressionStream('deflate-raw')` | Feasible, same caveats. Chunked form `shc:/1/3/…` (part 1 of 3) |
| `NZCP:/1/` | NZ COVID Pass: base32 CBOR/COSE | identify only |

Base45 (RFC 9285): alphabet `0-9A-Z $%*+-./:`; each 3 chars `c0 c1 c2` → `n = c0 + c1·45 + c2·45²` → 2 bytes (n ≤ 65535); trailing 2 chars → 1 byte. Vectors (RFC 9285): `"AB"` ↔ `BB8`, `"Hello!!"` ↔ `%69 VD92EX0`, `"ietf!"` ↔ `QED8WEX0`.
SHC vector: `"shc:/56762909524320603460292437404460"` → `eyJ6aXAiOiJERUYi` (base64url of `{"zip":"DEF"`) → identified as SHC, truncated JWS → info.

### 11.5 JWT / tokens

`^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$` (also `…` with 4 dots = JWE).
Decode header + payload (base64url → UTF-8 → JSON). Show `alg`, `typ`, `iss`, `sub`,
`aud`, `exp`/`iat`/`nbf` as dates (expired → info). **caution** "Looks like an access
token — treat it like a password" → value `sensitive`. `alg:none` → info.
Vector: `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
→ header `{alg:'HS256', typ:'JWT'}`, payload `{sub:'1234567890', name:'John Doe', iat:1516239022}` (2018-01-18T01:30:22Z).

### 11.6 Keys and certificates

- `-----BEGIN (PGP PUBLIC KEY BLOCK|PGP MESSAGE|CERTIFICATE|PUBLIC KEY)-----` → info, show type.
- `-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----` or `PGP PRIVATE KEY BLOCK` →
  **danger** "Contains a private key" (sensitive).
- `^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh.com) AAAA[0-9A-Za-z+/=]+( .*)?$`
  → SSH public key; show type + comment; optional SHA-256 fingerprint
  (`SHA256:` + base64(sha256(blob)) without padding, async).
- `age1[0-9a-z]{58}` → age public key; `AGE-SECRET-KEY-1…` → danger.
- WIF private keys (`^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$`), 64-hex strings with
  `0x` → caution "May be a crypto private key".

### 11.7 Wallet recovery phrases

12/15/18/21/24 lowercase words `^[a-z]{3,8}( [a-z]{3,8}){11,23}$` → caution "May be a
wallet recovery phrase — anyone who sees it controls the funds" (sensitive, masked).
To make it precise, bundle the BIP39 English list (2048 words, ~13 KB, MIT) and check
all words + checksum (SHA-256, async). Without the list keep it caution/"may be".

### 11.8 JSON and base64 blobs

- **JSON**: first non-space char `{` or `[` and `JSON.parse` succeeds → `json`.
  Show pretty-printed (2-space) with a collapsible tree; depth/size guard (depth > 64 →
  show raw). Scan string values for URLs (§2) and secrets (keys named
  `password|secret|token|key|apikey|private`) → mark sensitive. Duplicate keys can't be
  detected with `JSON.parse` (info only if implementing a custom scanner).
- **base64**: `^[A-Za-z0-9+/]{20,}={0,2}$` with length % 4 = 0, or base64url
  `^[A-Za-z0-9_-]{22,}$`, and at least 2 of {upper, lower, digit} present (avoid words).
  Decode → classify: valid UTF-8 printable text → show it ("decoded text"); JSON;
  magic bytes: `1F 8B` gzip, `78 01|5E|9C|DA` zlib, `89 50 4E 47` PNG, `FF D8 FF` JPEG,
  `25 50 44 46` PDF, `50 4B 03 04` ZIP, `D2 84` / `84` COSE/CBOR, `0A` + plausible
  protobuf; else hex dump. Offer "Copy decoded" only for text.

### 11.9 Binary payloads, byte mode, ECI

Facts: QR byte mode carries arbitrary 8-bit data. ISO/IEC 18004:2015 says the default
interpretation (no ECI) is ISO-8859-1; the 2000 edition said JIS8; in practice most
generators write UTF-8 without ECI, Japanese ones Shift_JIS. An ECI segment
(`0111` + designator) switches charset: 3 = ISO-8859-1, 4 = 8859-2, 5 = 8859-3,
6 = 8859-4, 7 = 8859-5, 8 = 8859-6, 9 = 8859-7, 10 = 8859-8, 11 = 8859-9, 12 = 8859-10,
13 = 8859-11, 15 = 8859-13, 16 = 8859-14, 17 = 8859-15, 18 = 8859-16, 20 = Shift_JIS,
21 = windows-1250, 22 = windows-1251, 23 = windows-1252, 24 = windows-1256,
25 = UTF-16BE, 26 = UTF-8, 27 = US-ASCII, 28 = Big5, 29 = GB2312/GB18030, 30 = EUC-KR.
ECI designator: `0xxxxxxx` (1 byte, 0–127), `10xxxxxx`+1 byte (≤ 16383),
`110xxxxx`+2 bytes (≤ 999999).

What `bytesBase64` contains must be checked empirically against the helper: Vision's
`VNBarcodeObservation.payloadData` vs `CIQRCodeDescriptor.errorCorrectedPayload` (the
latter is the raw **bit stream with mode indicators**). Test: generate a QR of
`"A"` in byte mode; if bytes start `0x40 0x14 0x10 …` (mode `0100`, count `00000001`,
data `01000001`) it's the bit stream. If it is the bit stream, parse segments:

| Mode bits | Mode | Count bits (v1–9 / 10–26 / 27–40) | Data |
|---|---|---|---|
| `0001` | numeric | 10 / 12 / 14 | 3 digits per 10 bits (2 → 7, 1 → 4) |
| `0010` | alphanumeric | 9 / 11 / 13 | 2 chars per 11 bits (`0-9A-Z $%*+-./:`) |
| `0100` | byte | 8 / 16 / 16 | 8 bits each |
| `1000` | kanji | 8 / 10 / 12 | 13 bits each → Shift_JIS |
| `0111` | ECI | — | designator as above |
| `0011` | structured append | — | 4-bit index, 4-bit total, 8-bit parity → info "Part i of n" |
| `0101` / `1001` | FNC1 (GS1) first / second position | — | GS1 element strings |
| `0000` | terminator | | |

(QR version comes from `qr.version` in the helper output.)

Text decision for bytes (`raw.bytesHex` always kept):

1. If ECI present → decode with it (`TextDecoder` supports all labels above).
2. Else valid UTF-8 (`TextDecoder('utf-8', {fatal:true})` succeeds) → UTF-8.
3. Else if plausible Shift_JIS (decodes with `fatal:true` and contains kana/kanji) → Shift_JIS.
4. Else ISO-8859-1 (always succeeds) — but if > 10% of bytes are C0 controls
   (excluding TAB/LF/CR) or there are NUL bytes → `binary`.
5. Compare with Vision's `text`; if different, info "Decoded as X; the system decoder
   read it as Y" and offer the alternative view. Mojibake hint: text matching
   `/Ã[\x80-\xBF]|Â[\x80-\xBF]/` → info "Looks like UTF-8 shown as Latin-1".

`binary` display: size, magic-type guess (§11.8), hex dump
(`00000000  48 65 6c 6c 6f …  |Hello…|`, 16 bytes/row, max 4 KB shown). Actions:
copy hex, copy base64, (optional) save `.bin`.

Vectors: bytes `48 65 6C 6C 6F` → text `Hello`; bytes `43 61 66 C3 A9` → UTF-8 `Café`;
bytes `43 61 66 E9` → not UTF-8 → Latin-1 `Café` + info; bytes `00 01 02 FF FE` →
binary; bytes `82 B1 82 F1 82 C9 82 BF 82 CD` → Shift_JIS `こんにちは`.

### 11.10 Product codes (1D symbologies, DataMatrix)

When `symbology` is EAN13/EAN8/UPCE/UPCA/ITF14/GS1DataBar or the payload is
13 digits: GTIN mod-10 check (weights 3,1 from the right, excluding the check digit);
`978`/`979` prefix → ISBN-13 (show ISBN-10 for 978: drop prefix, mod-11 check digit,
`X` for 10); `977` → ISSN; `20–29` → in-store/variable-measure. GS1 DataMatrix /
GS1-128 element strings (`]d2`, FNC1 = GS `\x1D`): parse AIs `01` GTIN(14), `10`
batch (var, ends at GS), `17` expiry YYMMDD, `21` serial (var), `11` production date,
`3103` net weight kg (3 decimals). Vector: `"9780306406157"` → ISBN `978-0-306-40615-7`,
ISBN-10 `0306406152`, check OK; GS1 DataMatrix `"\u001D01095060001343521727053110ABC123"`
(leading FNC1 as GS) → GTIN 09506000134352 (check OK), expiry 2027-05-31, batch ABC123
(last variable-length AI runs to the end; earlier ones end at GS).

### 11.11 Plain text

Fallback. Show text with §1 checks; linkify nothing automatically, but list
detected URLs/emails/phones inside the text as secondary chips (each analysed).
Actions: copy text.

---

## 12. Scanner app survey & presentation recommendations

### 12.1 What popular scanners do

| App | Presentation | Security features |
|---|---|---|
| iOS Camera / Code Scanner (Apple) | Yellow chip "Open *example.com* in Safari" / "Join network X" / "Add contact"; tap to act; long-press preview | Shows only the **host** in the chip (registrable part + subdomain). CVE-2018-4187 (iOS 11): chip host ≠ opened host via `\@` parser differential — fixed in 11.3.1 [S31]. Safari's Fraudulent Website Warning (network) after opening. |
| Android Camera / Google Lens | Chip with URL/host; Wi-Fi join, contact, copy text; Lens adds "search" | Opening goes through Chrome Safe Browsing (network reputation). Lens offers copy before open. |
| ZXing Barcode Scanner (archived) | Type-specific result screen: formatted fields, raw text, metadata (format, EC level, time), contextual buttons (add contact, dial, open, add event, Wi-Fi connect, product search) | Settings: "Ask before opening", optional history; no reputation checks. The type parsers here largely follow ZXing's `ResultParser`s [S1]. |
| QR & Barcode Scanner (Gamma Play) | Type icons + parsed result; actions; history, CSV export, batch scan; product lookups (network) | Optional auto-open (bad); no meaningful link analysis. Ads. |
| "Scan" (QR Code City) | Minimal: content + one main action | Basic. |
| Kaspersky QR Scanner / Norton Snap / Trend Micro | Shows the URL, then a verdict | Cloud reputation lookup (KSN); malicious links highlighted red and blocked from opening or saving to contacts [S32]. Some vendors also "unshorten" links or render a server-side sandbox preview (network). |

Takeaways: mainstream scanners optimise for one-tap action and rely on **online**
reputation. Security-focused ones add verdicts that need a server. None of them
show a structured, offline breakdown (punycode, userinfo, IP obfuscation, nested
redirects, tracking params) — that is this app's niche. Real-world threat model
("quishing"): fraudulent stickers over parking-meter / restaurant / EV-charger codes,
fake parcel notices, MFA/device-link phishing, payment QR with swapped IBAN
(FBI IC3 PSA 2022, FTC 2023 [S34][S35]).

### 12.2 Recommended presentation (offline, no network, not distracting)

1. **One card per code**, header = type icon + `title` + one-line `summary` written
   for a human ("Website: **paypal.com** — login page", "Wi-Fi: CoffeeShop (WPA2)",
   "Pay €12.30 to Franz Mustermänn").
2. **Verdict strip** directly under the header: highest-severity warning only,
   colour-coded (danger red / caution amber / info neutral) with "N more" disclosure.
   No warning → no strip (don't train users to ignore green badges; at most a
   subtle "No issues found by offline checks").
3. **Smart view (default) / Raw / Escaped / Hex** segmented control. Smart = parsed
   fields; Raw = exact text (selectable, mono); Escaped = §1.2 with chips; Hex = bytes
   (if available). Auto-switch the default to *Escaped* when bidi/tag/control chars exist.
4. **URL breakdown** (Smart view): big host line with the registrable domain bold,
   subdomain dimmed, Unicode + ACE when IDN, then a compact table: scheme, user info
   (red), port, path, each query parameter (tracking ones struck-through/greyed,
   nested URLs expandable with their own mini verdict), fragment. Actions: **Open…**
   (main-process confirm showing the same host emphasis), **Copy**, **Copy without
   tracking** (only when it differs), **Copy domain**.
5. **Sensitive values** (Wi-Fi password, OTP secret/code, tokens, keys, seed phrases):
   masked by default, reveal on click, copy uses `sensitive:true` (60 s clipboard
   clear) and the button says so ("Copy — clears in 60 s").
6. **OTP**: live code with a small countdown ring; migration exports as a list with
   per-entry "Copy otpauth URI".
7. **Payments**: "What you'd pay" box with amount/beneficiary/IBAN grouped and
   validation ticks (checksum, CRC, reference). These checks are fully offline and
   catch damaged/edited codes.
8. **Contacts / events**: a preview that looks like the Contacts/Calendar card,
   with "Save .vcf" / "Save .ics".
9. **Image-level signals** (cheap, offline, useful against sticker overlays): if one
   image yields several different codes → info "This image contains N different codes
   — a sticker may cover the original"; show code bounds on the preview with numbers;
   show `qr.version`/EC level/symbology in a muted "Details" row.
10. **Do not**: auto-open anything, fetch favicons/previews/unshorten, look up
    reputation, show history, add confetti/animations on warnings. Keep warnings to
    short factual sentences ("This link goes to evil.example, not paypal.com").

---

## 13. Sources

- [S1] ZXing wiki, *Barcode Contents* — https://github.com/zxing/zxing/wiki/Barcode-Contents
- [S2] Wi-Fi Alliance, *WPA3 Specification* v3.x §7 (Wi-Fi URI / QR) — https://www.wi-fi.org/system/files/WPA3%20Specification%20v3.4.pdf ; IANA provisional `wifi` scheme — https://www.iana.org/assignments/uri-schemes/prov/wifi
- [S3] "Most WPA3 WiFi QR Codes are broken" (quotes the WPA3 ABNF; T:SAE / backslash issues) — https://stevetech-me.pages.dev/posts/wifi-qr-codes-are-broken ; KDE bug 514026 — https://bugs.kde.org/show_bug.cgi?id=514026
- [S4] Wi-Fi Easy Connect / DPP URI: IANA `dpp` — https://www.iana.org/assignments/uri-schemes/prov/dpp ; Espressif docs — https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32/api-reference/network/esp_dpp.html ; linux-wireless thread with example — https://lore.kernel.org/all/8da7587a-d25d-5f11-5c4d-76cd54987637@gmail.com/T/
- [S5] EPC069-12 v3.0, *Quick Response Code – Guidelines to Enable the Data Capture for the Initiation of a SEPA Credit Transfer* (read in full) — https://europeanpaymentscouncil.eu/sites/default/files/kb/file/2022-09/EPC069-12%20v3.0%20Quick%20Response%20Code%20-%20Guidelines%20to%20Enable%20the%20Data%20Capture%20for%20the%20Initiation%20of%20an%20SCT_0.pdf
- [S6] SIX, *Swiss Implementation Guidelines for the QR-bill* v2.3 — https://www.six-group.com/dam/download/banking-services/standardization/qr-bill/ig-qr-bill-v2.3-en.pdf ; v2.4 — https://www.six-group.com/dam/download/banking-services/standardization/qr-bill/ig-qr-bill-v2.4-en.pdf
- [S7] SIX, *Delta guide v2.2 → v2.3* (read in full) — https://www.six-group.com/dam/download/banking-services/standardization/qr-bill/ig-qr-bill-delta-guide-v2.3-en.pdf
- [S8] Public Suffix List (MPL-2.0) and formal algorithm — https://publicsuffix.org/list/ , https://publicsuffix.org/list/public_suffix_list.dat
- [S9] UTS #39 Unicode Security Mechanisms — https://www.unicode.org/reports/tr39/ ; UTS #24 Script property
- [S10] RFC 2426 (vCard 3.0), RFC 6350 (vCard 4.0); vCard 2.1 (IMC)
- [S11] RFC 6868 (parameter value encoding in vCard/iCalendar)
- [S12] RFC 6068 — The `mailto` URI Scheme
- [S13] J. Müller et al., "Mailto: Me Your Secrets. On Bugs and Features in Email End-to-End Encryption" (2020) — https://www.nds.ruhr-uni-bochum.de/research/publications/mailto-me-your-secrets/
- [S14] RFC 3966 — The `tel` URI
- [S15] RFC 5724 — The `sms` URI
- [S16] RFC 5870 — The `geo` URI
- [S17] RFC 5545 — iCalendar
- [S18] Google Authenticator *Key Uri Format* — https://github.com/google/google-authenticator/wiki/Key-Uri-Format
- [S19] RFC 4226 — HOTP (Appendix D test values)
- [S20] RFC 6238 — TOTP (Appendix B test vectors)
- [S21] otpauth-migration protobuf schema (as published in `otpauth-migration-parser`) — https://cdn.jsdelivr.net/npm/otpauth-migration-parser@0.1.1/otpauth-migration.proto ; GNOME Authenticator's importer — https://world.pages.gitlab.gnome.org/Authenticator/src/authenticator/backup/google.rs.html
- [S22] Czech Banking Association, *QR Platba (SPD) format* — https://qr-platba.cz/pro-vyvojare/specifikace-formatu/
- [S23] EMVCo, *QR Code Specification for Payment Systems: Merchant-Presented Mode* v1.1+ — https://www.emvco.com/emv-technologies/qr-codes/
- [S24] Banco Central do Brasil, *Manual de Padrões para Iniciação do Pix* (BR Code, GUI `br.gov.bcb.pix`, example with CRC `1D3D`) — https://www.bcb.gov.br/estabilidadefinanceira/pix
- [S25] NPCI, *UPI Linking Specs* (upi://pay parameters) — https://www.npci.org.in/
- [S26] BIP-21 — https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki ; BIP-173/350 (bech32/bech32m)
- [S27] BOLT #11 — https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
- [S28] EIP-681 — https://eips.ethereum.org/EIPS/eip-681 ; EIP-55 checksum
- [S29] eHealth Network, *EU DCC technical specifications* (HC1, Base45, COSE) — https://ec.europa.eu/health/ehealth/covid-19_en ; RFC 9285 Base45 ; SMART Health Cards spec — https://spec.smarthealth.cards/
- [S30] Chromium *IDN in Google Chrome* display policy — https://chromium.googlesource.com/chromium/src/+/main/docs/idn.md
- [S31] CVE-2018-4187 iOS Camera QR URL spoofing — https://thehackernews.com/2018/03/ios-qr-code-camera.html
- [S32] Kaspersky QR Scanner help — https://support.kaspersky.com/QRSAndroid/1.7/en-US/94042.htm
- [S33] Google Threat Intelligence, "Signals of Trouble: Multiple Russia-Aligned Threat Actors Actively Targeting Signal Messenger" (Feb 2025; malicious `linkdevice` QR codes) — https://cloud.google.com/blog/topics/threat-intelligence/russia-targeting-signal-messenger
- [S34] FBI IC3 PSA I-011822-PSA "Cybercriminals Tampering with QR Codes" (2022) — https://www.ic3.gov/Media/Y2022/PSA220118
- [S35] FTC consumer alert "Scammers hide harmful links in QR codes" (Dec 2023) — https://consumer.ftc.gov/consumer-alerts/2023/12/scammers-hide-harmful-links-qr-codes-steal-your-information
- [S36] Trojan Source (CVE-2021-42574) — https://trojansource.codes/
- RFC 3492 Punycode; RFC 4648 Base32/64; ISO 13616 IBAN; ISO 11649 RF reference; ISO/IEC 18004 QR.

`scratchpad/{vectors,mig,more}.mjs` (temporary, not kept in the repo).
`/private/tmp/claude-501/-Users-stepans-Documents-testbed-mac-qr-reader/d7b03f13-21ab-4688-827f-c95e3a15848e/scratchpad/{vectors,mig,more}.mjs`.

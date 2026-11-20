# Public Suffix List snapshot

| | |
|---|---|
| File | `public_suffix_list.dat` (unmodified) |
| Source URL | https://publicsuffix.org/list/public_suffix_list.dat |
| Retrieved | 2026-11-18 (via `curl`; the official URL worked) |
| List version | `2026-11-17_16-14-34_UTC`, commit `09c1b150f33c6145a73afcf7db0fb872fc54b4d1` |
| Size | 342,473 bytes, 10,463 rules (ICANN + PRIVATE) |
| SHA-256 | `809adae1a2cb1621b70165c11e0d14412d3f104f40a4ebed9a99e23c54f78d71` |

`psl-rules.js` is generated from this file by `scripts/gen-psl.mjs` (comments
stripped, rules converted to ASCII/punycode). The script refuses to run if the
SHA-256 of the `.dat` differs from the value pinned in the script.
`node scripts/gen-psl.mjs --check` verifies that the generated module is current.

To update: download the file from the URL above, replace the `.dat`, update the
pinned hash in `scripts/gen-psl.mjs` and this table, then run the script.

The copy on GitHub (`raw.githubusercontent.com/publicsuffix/list/main/…`) lacks
the `VERSION`/`COMMIT` header lines; the official URL is preferred.

The official test vectors (`tests/test_psl.txt`, public domain / CC0) are stored
in `test/unit/data/test_psl.txt` (from
https://raw.githubusercontent.com/publicsuffix/list/main/tests/test_psl.txt,
SHA-256 `8f50ad958916d6a8f79fba2363501475571acce752757f9126fe9d2f17dd920d`).

## License

The Public Suffix List is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, you can obtain
one at https://mozilla.org/MPL/2.0/. The `.dat` file is bundled unmodified with
its license header; `psl-rules.js` is a mechanically derived form and carries the
same notice. MPL-2.0 is file-level copyleft and does not affect the app's other code.

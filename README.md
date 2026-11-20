# QR Reader

A personal, security-focused QR/barcode reader for macOS (Apple silicon, macOS 14+, built
and tested on macOS 26). Drop, paste or open an image or PDF; codes are decoded by a tiny
Apple Vision helper running under a `(deny default)` sandbox, and every payload gets a
safety breakdown. No network, no telemetry, no history.

## Run

```sh
./start.sh          # or: npm start
```

The first run takes about 20 s. After that a run takes about 1 s when nothing has changed.
`./start.sh` uses your `node` if it is ≥ 22.12, otherwise it uses `fnm` with `.node-version`
(24.18.0). It runs `scripts/setup.mjs` and then opens `build/QR Reader.app`. If the app is
already running, it brings that window to the front. If setup rebuilt the bundle, it restarts
the app. Use `./start.sh --no-open` to run setup only.

## What setup does (and verifies)

Every stage is skipped when its hash stamp in `build/.stamps/` still matches its inputs.

1. **env**: checks that this is macOS on arm64 with node ≥ 22.12 and `swiftc` available. It
   refuses to run if `ELECTRON_MIRROR`, `ELECTRON_CUSTOM_*`, `npm_config_electron_*`,
   `NODE_OPTIONS`, `DYLD_*` or similar variables are set.
2. **npm**: checks that `package.json` has exact pins and no runtime dependencies. Every
   `package-lock.json` entry must match `scripts/lockfile-allowlist.json` (version, sha512,
   resolved from the pinned registry, no install scripts). It runs `npm ci` only when the
   lockfile changes. `.npmrc` sets `ignore-scripts`, `min-release-age=7`, `allow-git=none`
   and `engine-strict`.
3. **electron**: does **not** run Electron's `install.js`. Setup takes
   `electron-v45.2.3-darwin-arm64.zip` from the Electron cache, or downloads it from the
   GitHub release over HTTPS with curl. The zip's SHA-256 must equal the value pinned in
   `scripts/setup.mjs` and in `electron/checksums.json`. When online, it is also checked
   against the release `SHASUMS256.txt`, plus `gh attestation verify` if `gh` is installed.
   The zip is then extracted with `/usr/bin/ditto`.
4. **helper**: builds `native/qr-decode.swift` and runs a self-test. The self-test decodes a
   generated QR image through `sandbox-exec` and must find the exact payload, otherwise
   setup fails.
5. **icon**: renders `native/make-icon.swift` and converts it with `iconutil` into
   `build/icon.icns`.
6. **app**: runs `scripts/build-app.mjs`, which:
   - copies `Electron.app` and renames it to "QR Reader" (`local.qr-reader`);
   - cleans up `Info.plist`: removes the camera, microphone and Bluetooth usage strings and
     the ATS exception, and registers image and PDF types as "Open With" (rank Alternate);
   - packs `app.asar` from `src/**` with per-file integrity, and adds the helper and its
     sandbox profile;
   - flips the fuses and signs the bundle ad-hoc with hardened runtime.
7. **verify**: runs on every launch. It checks:
   - `codesign --verify --deep --strict` passes;
   - hardened runtime is on, and the entitlements are exactly `allow-jit` +
     `disable-library-validation`;
   - fuse wire `010011001`;
   - the `ElectronAsarIntegrity` hash equals the ASAR header hash, and every file matches
     its embedded hash;
   - the packaged helper passes the sandboxed self-test.

   If any check fails, setup rebuilds the bundle once.

## Security properties of the built app

- **Fuses:**
  - Off: RunAsNode, `NODE_OPTIONS`, `--inspect` and file:// extra privileges.
  - On: cookie encryption, embedded ASAR integrity and only-load-from-ASAR.
  - Editing one byte of `app.asar` makes the app abort at launch ("Integrity check failed").
- **Debug switches:** the main process exits when it sees `--remote-debugging-port`,
  `--inspect` and similar switches.
- **Signing:** hardened runtime blocks `DYLD_INSERT_LIBRARIES` and debugger attach. There is
  no `get-task-allow` entitlement. The signature is ad-hoc: it seals the bundle's integrity
  but carries no identity.
- **Bundle contents:** the bundle has no npm code, only the Electron binary and our own JS.
- The renderer is sandboxed, with context isolation and strict CSP plus Trusted Types. It
  makes no network requests and does not use `file://`.

Details and evidence are in [docs/SECURITY.md](docs/SECURITY.md). Module contracts are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development and tests

```sh
npm run dev           # = ./start.sh --dev: dev setup, then the unfused dev Electron on the project dir
npm test              # unit + native helper tests
npm run test:e2e      # Playwright against the real app (dev binary; the fused app refuses --inspect)
npm run test:packaged # Playwright against the PACKAGED app: build/QR Reader (Test).app (built if stale)
npm run verify        # launches the real app, real interactions, screenshots → verify-output/
npm run gen-fixtures  # rebuild helpers + regenerate test/fixtures
npm run build         # force-rebuild helper + app bundle (then verifies)
node scripts/build-app.mjs --smoke   # quit QR Reader first: launch the fused app, assert debug switches are refused
node scripts/build-app.mjs --test-variant  # build build/QR Reader (Test).app (docs/SECURITY.md §6.6)
```

When the active node is too old, prefix commands with `fnm exec --using=24.18.0`.

## Updating Electron safely

1. Wait until the new version is on the mirror and at least 7 days old
   (`npm view electron time --json`). Check
   https://github.com/electron/electron/security/advisories.
2. In a scratch copy, set the exact version in `package.json`, then run
   `npm install --package-lock-only`. Repeat the checks in docs/SECURITY.md §3.3/§11 for
   every package in the lockfile: deps.dev, jsDelivr, OSV, npm signatures and IOC lists.
3. Download `electron-v<ver>-darwin-arm64.zip` from
   `https://github.com/electron/electron/releases/download/v<ver>/`. Confirm that three
   values agree:
   - `shasum -a 256` of the zip;
   - the zip's entry in that release's `SHASUMS256.txt`;
   - the zip's entry in the new package's `checksums.json`.

   Also run `gh attestation verify <zip> --repo electron/electron`.
4. Update `ELECTRON` (version, zip name, sha256, base URL) and `PINS` in
   `scripts/setup.mjs`. Update `scripts/lockfile-allowlist.json` (regenerate it from the
   vetted lockfile), and update the tables in docs/SECURITY.md.
5. Run `./start.sh`. Setup checks the new fuse wire layout (it refuses removed or unknown
   fuses), rebuilds the bundle and verifies it. Then run `npm run verify` and
   `node scripts/build-app.mjs --smoke`.

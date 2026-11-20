# QR Reader — guide for agents

Security-focused personal macOS QR/barcode reader (Electron 45.2.3, zero runtime npm deps).
Read first: `docs/ARCHITECTURE.md` (contracts: IPC, ScanResult, helper, parsers, runtime
paths), `docs/SECURITY.md` (hardening decisions, all tested), `docs/PAYLOADS.md` (payload formats).

Node: the default node is too old — use `fnm exec --using=24.18.0 <cmd>` (`.node-version`).

## Build & run

| What | Command |
|---|---|
| Everything (deps, helper, fused .app) + launch | `./start.sh` (= `npm start`) |
| Native helper only / + fixtures | `native/build.sh` / `native/build.sh --fixtures` |
| Packaged app only | `npm run build` → `build/QR Reader.app` (fused: Playwright cannot drive it) |
| Packaged test variant | `node scripts/build-app.mjs --test-variant` → `build/QR Reader (Test).app` (inspect fuse on + asar marker; for `test:packaged` only) |
| Unfused dev run | `npm run dev` (= `node_modules/electron/dist/Electron.app/Contents/MacOS/Electron .`) |
| Ad-hoc QR image | `build/bin/gen-fixtures one "<text>" out.png` |

## Verify the REAL app (do this after every change)

`scripts/verify.mjs` launches the dev Electron binary with the project dir via Playwright
`_electron`, drives real input paths, and writes PNGs + `summary.json` to `verify-output/`.
Look at the screenshots with the Read tool (e.g. `verify-output/03-drop-multi-3.png-dark.png`).

```sh
N="fnm exec --using=24.18.0 node"
$N scripts/verify.mjs shots                       # empty state + fixtures via every input path, light + dark
$N scripts/verify.mjs scan <file...>              # Finder "Open With" (open-file event); prints ScanResult + analysis
$N scripts/verify.mjs open <file...>              # File ▸ Open… (dialog.showOpenDialog stubbed at the boundary only)
$N scripts/verify.mjs drop <file...>              # real renderer drop event with Files built from the bytes
$N scripts/verify.mjs paste-image <file>          # image → REAL system clipboard, then Meta+V
$N scripts/verify.mjs paste-files <file...>       # Finder-style file URLs → clipboard, then Meta+V
$N scripts/verify.mjs paste-text <text>           # text → clipboard, then Meta+V
$N scripts/verify.mjs eval 'document.title'       # renderer JS;  'main:app.getPath("userData")' for main
$N scripts/verify.mjs canary                      # scan a unique canary, quit, grep disk → must find nothing
# options: --theme light|dark, --out <dir>, --keep-open <ms>
```

Clipboard commands save the whole pasteboard in memory first and restore it afterwards.
Launches use a temp userData dir with `autoScanClipboard: false`. Exit code 0 = OK.

## Tests

- `npm test` — unit (parsers) + native helper tests (`test/unit`, `test/native`).
- `npm run test:e2e` — `test/e2e/*.test.mjs` against the real app (~70 s). Files are
  serialised by a lock in `test/e2e/harness.mjs` (`serialize()`); all clipboard-touching
  tests live in `clipboard.test.mjs`. Shared launch/input helpers: `test/e2e/harness.mjs`
  (`launch`, `openWith`, `openViaDialog`, `dropFiles`, `pasteKeys`, `clipboardSet*`,
  `setTheme`, `screenshot`, `nextResults`, `clickMenu`).
- `npm run test:packaged` — `test/e2e-packaged/*.test.mjs` against the PACKAGED app (~60 s):
  builds `build/QR Reader (Test).app` if stale and drives it with Playwright
  (`executablePath`); also checks tampered copies and that the production bundle refuses
  `--inspect`/`--remote-debugging-port`. Needs `build/QR Reader.app` (`./start.sh --no-open`).
  Helpers: `test/e2e-packaged/harness.mjs` (`launchPackaged`, `openWithLS` = real `open -a`,
  `watchChildren` + `sandboxCheck`, `copyBundle`, `runExe`, `killBundle`). No test hooks there:
  `installRecorder` wraps the IPC handlers via the inspector to fill the same `__qrTestLog`.
  Details: docs/SECURITY.md §6.6.
- Results are observed through a dev-only hook: with `QR_TEST_HOOKS=1` on the unpackaged
  app, main records each returned/pushed `ScanResult[]` in `globalThis.__qrTestLog`
  (`{seq, via, results}`), read via `electronApp.evaluate`. Never active when packaged.
- Kill stray Electron processes you start (`pkill -f "Electron.app/Contents/MacOS/Electron /Users/.../mac-qr-reader"`).

## Where things live

`src/main/` main process (CommonJS): `main.js` entry/lifecycle/window/open-file/single
instance · `security.js` session, `app://qr` protocol + CSP, permissions, network block,
navigation lockdown, debug-switch refusal · `ipc.js` validated handlers + openExternal confirm (`linkinfo.js`: PSL site, truncation, local-address warning)
· `decoder.js` sandbox-exec'd helper, limits, self-test, ScanResult mapping · `files.js` file
reads · `clipboard.js` paste/copy/auto-scan · `menu.js` · `settings.js` · `paths.js` ·
`testhooks.js`. `src/preload/preload.js` exposes `window.qr` only. `src/renderer/` UI +
`parsers/` (pure ES modules). `native/` helper + sandbox profile. `scripts/` setup, build,
verify.

## Rules for contributors

- No new dependencies (runtime: none; dev: electron + playwright-core only) without a
  written justification in `docs/SECURITY.md`.
- Renderer: no `innerHTML`/`insertAdjacentHTML`/`eval`/inline scripts or styles (CSP +
  Trusted Types make them throw). Build DOM with `createElement`/`textContent`.
- Never add network access, telemetry, history, or disk writes of decoded content
  (Save… is the only exception). Run `verify.mjs canary` after touching storage/caching.
- Images are decoded only by the helper under `sandbox-exec`; never add an unsandboxed
  fallback. Links open only via `window.qr.openExternal` (main validates + native confirm).
- Every new IPC channel: `ipc.js` `handle()` (sender check) + argument validation + preload
  wrapper + ARCHITECTURE.md table. Never expose `ipcRenderer` or filesystem paths.
- Test-only behaviour must be gated on `!app.isPackaged` (see `QR_TEST_*` env vars).
- After changes: `npm test`, `npm run test:e2e`, `npm run test:packaged`, `verify.mjs shots`, and look at the PNGs.

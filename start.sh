#!/bin/sh
# QR Reader — the one command: install/verify everything that is needed, then launch.
#   ./start.sh            setup (fast when nothing changed) + open the app
#   ./start.sh --no-open  setup only
#   ./start.sh --dev      dev setup, then run the unfused dev Electron on the project dir (npm run dev)
# Setup details: scripts/setup.mjs, docs/SECURITY.md.
set -eu
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"
APP="$ROOT/build/QR Reader.app"
MODE=${1:-open}
case "$MODE" in open|--no-open|--dev) ;; *) echo "usage: ./start.sh [--no-open|--dev]" >&2; exit 2 ;; esac
WANT=$(cat .node-version 2>/dev/null || echo 24.18.0)

node_ok() { # $@ = command prefix that runs node
  "$@" -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(process.arch==="arm64"&&(a>22||(a===22&&b>=12))?0:1)' 2>/dev/null
}

if command -v node >/dev/null 2>&1 && node_ok node; then
  set -- node
elif command -v fnm >/dev/null 2>&1; then
  if ! node_ok fnm exec --using="$WANT" node; then
    echo "✗ Node $WANT is not installed in fnm. Fix: fnm install $WANT" >&2
    exit 1
  fi
  set -- fnm exec --using="$WANT" node
else
  echo "✗ Node >= 22.12 (arm64) is required; found: $(node -v 2>/dev/null || echo none)." >&2
  echo "  Fix: install fnm (brew install fnm) and run: fnm install $WANT" >&2
  exit 1
fi

if [ "$MODE" = --dev ]; then
  "$@" scripts/setup.mjs --dev-only
  exec node_modules/electron/dist/Electron.app/Contents/MacOS/Electron "$ROOT"
fi

before=$(cat build/.stamps/app.json 2>/dev/null || true)
"$@" scripts/setup.mjs
after=$(cat build/.stamps/app.json 2>/dev/null || true)

[ "$MODE" = open ] || exit 0

# A rebuilt bundle replaces the one a running instance was started from: quit it first so
# `open` doesn't just focus the old build.
EXE="$APP/Contents/MacOS/QR Reader"
# PIDs whose executable path is exactly $EXE (string comparison, no regex: the path may contain
# characters that are special in patterns, and argv can be spoofed by other processes).
app_pids() {
  /bin/ps -axo pid=,comm= | /usr/bin/awk -v exe="$EXE" '{ pid = $1; sub(/^[ ]*[0-9]+ /, ""); if ($0 == exe) print pid }'
}
if [ "$before" != "$after" ] && [ -n "$(app_pids)" ]; then
  echo "Restarting QR Reader (new build)…"
  i=0
  while [ -n "$(app_pids)" ] && [ $i -lt 8 ]; do # graceful quit (SIGTERM → app.quit), repeated, then SIGKILL
    for p in $(app_pids); do kill -TERM "$p" 2>/dev/null || true; done
    sleep 0.5; i=$((i + 1))
  done
  for p in $(app_pids); do kill -KILL "$p" 2>/dev/null || true; done
fi

# `open` launches the app, or focuses the running instance (single-instance app).
/usr/bin/open "$APP"
echo "✓ QR Reader launched"

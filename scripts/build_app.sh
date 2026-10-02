#!/bin/bash
# Builds a self-contained BugBane.app: an embedded Python (requirements/runtime.txt, checksum-verified),
# the pymobiledevice3 and MVT packages, the app code, a launcher and the icon. Running it needs no
# Homebrew, no setup.sh and no Terminal. Data goes to ~/Library/Application Support/Bugbane
# (app/scan/paths.py); the bundle itself is never written to. Ad-hoc signed for local use; Developer ID
# signing and notarization are a separate step.
#
# Usage: scripts/build_app.sh [--out DIR]          -> DIR/BugBane.app   (default DIR: build/)
# Builds for this Mac's architecture (arm64 or x86_64); the other one needs its own machine.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# --- 1. embedded Python, verified ------------------------------------------------------------------
case "$(uname -m)" in
  arm64) TRIPLE=aarch64-apple-darwin ;;
  x86_64) TRIPLE=x86_64-apple-darwin ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
PIN="$ROOT/requirements/runtime.txt"
RELEASE=$(awk '$1=="release"{print $2}' "$PIN")
PYVER=$(awk '$1=="python"{print $2}' "$PIN")
SHA=$(awk -v t="$TRIPLE" '$1==t{print $2}' "$PIN")
FILE="cpython-${PYVER}+${RELEASE}-${TRIPLE}-install_only.tar.gz"
CACHE="$HOME/Library/Caches/bugbane-build"
mkdir -p "$CACHE"
if ! echo "$SHA  $CACHE/$FILE" | shasum -a 256 -c --status 2>/dev/null; then
  echo "Downloading $FILE…"
  curl -fsSL -o "$CACHE/$FILE.part" \
    "https://github.com/astral-sh/python-build-standalone/releases/download/$RELEASE/$FILE"
  if ! echo "$SHA  $CACHE/$FILE.part" | shasum -a 256 -c --status; then
    rm -f "$CACHE/$FILE.part"
    echo "Checksum mismatch for $FILE: refusing to build." >&2
    exit 1
  fi
  mv "$CACHE/$FILE.part" "$CACHE/$FILE"
fi

APP="$OUT/BugBane.app"
RES="$APP/Contents/Resources"
RT="$RES/runtime"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$RT"
tar xzf "$CACHE/$FILE" -C "$RT"            # -> $RT/python
PY="$RT/python/bin/python3"
export PYTHONNOUSERSITE=1

# --- 2. the two tool environments (kept apart, as in the checkout: their pins move independently) ------
for env in pmd3 mvt; do
  echo "Installing $env…"
  "$PY" -m pip install -q --disable-pip-version-check --no-compile --target "$RT/$env/site" \
    -r "$ROOT/requirements/$env.txt"
  rm -rf "$RT/$env/site/bin"               # pip's scripts point at this build folder; we write our own
done
# pip isn't needed at runtime; tkinter/IDLE aren't used
rm -rf "$RT"/python/lib/python3.*/site-packages/pip "$RT"/python/lib/python3.*/site-packages/pip-*.dist-info \
       "$RT"/python/lib/python3.*/{tkinter,idlelib,turtledemo} "$RT"/python/lib/python3.*/lib-dynload/_tkinter* \
       "$RT"/python/lib/{tcl,tk,libtcl,libtk,itcl,thread}*

# --- 3. launchers with the same shape as .tools/<env>/bin/ ----------------------------------------------
for env in pmd3 mvt; do
  mkdir -p "$RT/$env/bin"
  cat > "$RT/$env/bin/python" <<'SH'
#!/bin/sh
# BugBane's embedded interpreter with this environment's packages. Never writes bytecode (the signed
# bundle must not change) and ignores the user's own Python settings.
ENV_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
unset PYTHONHOME PYTHONSTARTUP
PYTHONPATH="$ENV_DIR/site" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  exec "$ENV_DIR/../python/bin/python3" "$@"
SH
  chmod +x "$RT/$env/bin/python"
done
"$PY" - "$RT" <<'PYGEN'
import importlib.metadata as md, pathlib, sys
rt = pathlib.Path(sys.argv[1])
wanted = {"pmd3": {"pymobiledevice3"}, "mvt": {"mvt", "mvt-ios"}}
for env, names in wanted.items():
    found = {ep.name: ep for d in md.distributions(path=[str(rt / env / "site")])
             for ep in d.entry_points if ep.group == "console_scripts" and ep.name in names}
    missing = names - set(found)
    if missing:
        sys.exit(f"console scripts not found in {env}: {sorted(missing)}")
    for name, ep in found.items():
        path = rt / env / "bin" / name
        code = f"import sys; sys.argv[0] = {name!r}; import {ep.module} as m; sys.exit(m.{ep.attr}())"
        path.write_text(f'#!/bin/sh\nexec "$(dirname "$0")/python" -c "{code}" "$@"\n')
        path.chmod(0o755)
PYGEN

# --- 4. app code, licences, precompiled bytecode -------------------------------------------------------
rsync -a --exclude '__pycache__' --exclude '*.pyc' "$ROOT/app/" "$RES/app/"
cp "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_NOTICES.md" "$RES/"
echo "Precompiling…"
# relative source paths in bytecode (-s): tracebacks never show the build machine's folders
"$PY" -m compileall -q -j0 -s "$RES/" "$RT/python/lib" "$RT/pmd3/site" "$RT/mvt/site" "$RES/app" >/dev/null || true

# --- 5. bundle metadata, launcher, icon ----------------------------------------------------------------
VERSION=$(sed -n 's/^APP_VERSION = "\(.*\)"/\1/p' "$ROOT/app/scan/pipeline.py")
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>BugBane</string>
  <key>CFBundleDisplayName</key><string>BugBane</string>
  <key>CFBundleIdentifier</key><string>app.bugbane.mac</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleExecutable</key><string>launcher</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHumanReadableCopyright</key><string>GPL-3.0-or-later. Source: github.com/heresherbert/BugBane</string>
</dict></plist>
PLIST

cat > "$APP/Contents/MacOS/launcher" <<'LAUNCHER'
#!/bin/bash
# Starts BugBane's local server from the embedded runtime, or reopens the running one.
RES="$(cd "$(dirname "$0")/../Resources" && pwd -P)"
DATA="${BUGBANE_DATA:-$HOME/Library/Application Support/Bugbane}"
LOGDIR="$HOME/Library/Logs/Bugbane"
mkdir -p "$LOGDIR" "$DATA/run"
chmod 700 "$DATA"
exec >>"$LOGDIR/launcher.log" 2>&1
echo "$(date '+%F %T') launch"
if [ -f "$DATA/run/server.pid" ] && kill -0 "$(cat "$DATA/run/server.pid")" 2>/dev/null && [ -f "$DATA/run/url.txt" ]; then
  open "$(cat "$DATA/run/url.txt")"
  exit 0
fi
rm -f "$DATA/run/url.txt"
nohup "$RES/runtime/pmd3/bin/python" "$RES/app/server.py" >> "$DATA/run/server.log" 2>&1 &
for _ in $(seq 1 80); do
  [ -f "$DATA/run/url.txt" ] && exit 0
  sleep 0.25
done
osascript -e 'display alert "BugBane didn’t start" message "Details are in ~/Library/Logs/Bugbane/launcher.log and Application Support/Bugbane/run/server.log."'
LAUNCHER
chmod +x "$APP/Contents/MacOS/launcher"
"$ROOT/scripts/app_icon.sh" "$RES/AppIcon.icns" || echo "(icon skipped)"

# --- 6. sign (ad-hoc), smoke-test without changing anything, verify ----------------------------------
codesign --force --deep --sign - "$APP" 2>/dev/null
echo "Smoke test…"
"$RT/pmd3/bin/python" -c "import pymobiledevice3, cryptography; print('  pymobiledevice3 ok')"
"$RT/pmd3/bin/pymobiledevice3" --help >/dev/null && echo "  pymobiledevice3 CLI ok"
"$RT/mvt/bin/mvt-ios" --help >/dev/null && echo "  mvt-ios CLI ok"
"$RT/pmd3/bin/python" "$RES/app/helpers/device_helper.py" usb | sed 's/^/  device helper: /'
codesign --verify --deep --strict "$APP"   # fails if the smoke test wrote anything into the bundle
echo "Built: $APP ($(du -sh "$APP" | cut -f1), $(uname -m), signature intact)"

#!/bin/bash
# Installs (or updates) BugBane for everyday use, cleanly: builds the self-contained app (scripts/build_app.sh)
# in a temporary folder, finds every older copy on this Mac, and leaves exactly one: ~/Applications/BugBane.app.
# Data stays in ~/Library/Application Support/Bugbane, so History is kept.
#
# Older copies are found by bundle ID (app.bugbane.mac) through Spotlight and LaunchServices, and by name in
# /Applications and ~/Applications. Each one's bundle ID is checked before anything happens to it. Strays go to
# the Trash, never deleted outright; the copy being replaced in ~/Applications and leftover build output in this
# checkout are simply replaced or removed. Earlier versions kept code and virtualenvs next to the data; those go
# to the Trash too. The data folders (history/, run/, evidence/) are never touched.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
DATA="$HOME/Library/Application Support/Bugbane"
APPS="$HOME/Applications"
DEST="$APPS/BugBane.app"
IDS=("app.bugbane.mac")
NAMES=("BugBane.app" "Bugbane.app")
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

bundle_id() { /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$1/Contents/Info.plist" 2>/dev/null || true; }
version() { /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$1/Contents/Info.plist" 2>/dev/null || echo "?"; }
ours() { local id; id="$(bundle_id "$1")"; for known in "${IDS[@]}"; do [ "$id" = "$known" ] && return 0; done; return 1; }

# Moves items to the Trash with the system's own API (no Full Disk Access needed, nothing is deleted).
to_trash() {
  /usr/bin/swift - "$@" <<'SWIFT'
import Foundation
for path in CommandLine.arguments.dropFirst() {
    do {
        try FileManager.default.trashItem(at: URL(fileURLWithPath: path), resultingItemURL: nil)
        print("  to the Trash: \(path)")
    } catch {
        FileHandle.standardError.write("  couldn't move \(path) to the Trash: \(error.localizedDescription)\n".data(using: .utf8)!)
        exit(1)
    }
}
SWIFT
}

# Every copy of the app on this Mac, one path per line (outside the Trash).
find_copies() {
  {
    for id in "${IDS[@]}"; do mdfind "kMDItemCFBundleIdentifier == '$id'" 2>/dev/null || true; done
    "$LSREGISTER" -dump 2>/dev/null | awk '/^path:/{sub(/^path: +/, ""); sub(/ \(0x[0-9a-f]+\)$/, ""); p=$0}
      /^identifier:/{for (i = 2; i <= NF; i++) if ($i == "app.bugbane.mac") print p}' || true
    for dir in "$APPS" /Applications; do for name in "${NAMES[@]}"; do [ -d "$dir/$name" ] && echo "$dir/$name"; done; done
  } | grep -v "/\.Trash/" | grep -vF "${BUILD:-//none}" | sort -u  # never the build being installed
}

# 1. Stop a running copy. SIGTERM makes it restore backup encryption and erase unkept data first.
if [ -f "$DATA/run/server.pid" ]; then
  PID="$(cat "$DATA/run/server.pid")"
  if kill "$PID" 2>/dev/null; then
    for _ in $(seq 1 40); do kill -0 "$PID" 2>/dev/null || break; sleep 0.25; done
  fi
  rm -f "$DATA/run/server.pid" "$DATA/run/url.txt"
fi

# 2. Build in a temporary folder, so no second copy is left behind for Spotlight and Launchpad.
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
"$SRC/scripts/build_app.sh" --out "$BUILD"
NEW="$(version "$BUILD/BugBane.app")"

# 3. Clear out every older copy.
echo "Looking for older copies of BugBane…"
STRAYS=()
while IFS= read -r app; do
  [ -n "$app" ] && [ -d "$app" ] || continue
  ours "$app" || { echo "  skipped (not BugBane): $app"; continue; }
  "$LSREGISTER" -u "$app" 2>/dev/null || true
  case "$app" in
    "$DEST"|"$APPS/Bugbane.app") echo "  replacing $(version "$app") with $NEW: $app"; rm -rf "$app" ;;
    "$SRC/build/"*) echo "  removing leftover build output: $app"; rm -rf "$app" ;;
    *) echo "  older copy ($(version "$app")): $app"; STRAYS+=("$app") ;;
  esac
done < <(find_copies)
[ ${#STRAYS[@]} -gt 0 ] && to_trash "${STRAYS[@]}"

# 4. The earlier layout's code and virtualenvs, next to the data.
OLD=()
for old in app .tools requirements setup.sh make_app.sh Bugbane.app; do [ -e "$DATA/$old" ] && OLD+=("$DATA/$old"); done
[ ${#OLD[@]} -gt 0 ] && to_trash "${OLD[@]}"

# 5. Install the new build.
mkdir -p "$APPS" "$DATA"
chmod 700 "$DATA"
ditto "$BUILD/BugBane.app" "$DEST"
codesign --verify --deep --strict "$DEST"
"$LSREGISTER" -f "$DEST" 2>/dev/null || true
echo "Installed BugBane $NEW: $DEST"
echo "Data (History etc.): $DATA"

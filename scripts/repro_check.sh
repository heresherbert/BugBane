#!/bin/bash
# Reproducible-build check: builds BugBane.app twice from this checkout, in two different folders, and compares
# the SHA-256 of every file. Any difference means something outside the commit and the hashed locks went into
# the build. Writes the file manifest of the first build to --manifest (default: build/BugBane.app.sha256).
#
# Usage: scripts/repro_check.sh [--manifest FILE]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/build/BugBane.app.sha256"
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for n in one two; do
  echo "Build $n…"
  "$ROOT/scripts/build_app.sh" --out "$WORK/$n" > "$WORK/$n.log" 2>&1 || { tail -20 "$WORK/$n.log"; exit 1; }
  (cd "$WORK/$n" && find BugBane.app -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256) > "$WORK/$n.sha256"
done

mkdir -p "$(dirname "$MANIFEST")"
cp "$WORK/one.sha256" "$MANIFEST"
if cmp -s "$WORK/one.sha256" "$WORK/two.sha256"; then
  echo "Reproducible: $(wc -l < "$MANIFEST" | tr -d ' ') files identical in both builds. Manifest: $MANIFEST"
else
  echo "NOT reproducible. Files that differ:" >&2
  diff "$WORK/one.sha256" "$WORK/two.sha256" | awk '/^[<>]/{print $3}' | sort -u | head -40 >&2
  exit 1
fi

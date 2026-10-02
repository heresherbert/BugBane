#!/bin/bash
# Developer setup (idempotent): Python 3.12 venvs for MVT and pymobiledevice3 in .tools/, pinned to the
# versions the app was tested with, plus the latest spyware indicators. Users don't need this: the app
# bundle (scripts/build_app.sh, ./install.sh) carries its own Python.
set -euo pipefail
cd "$(dirname "$0")"

find_python() {
  for p in /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12 "$(command -v python3.12 || true)"; do
    if [ -n "$p" ] && [ -x "$p" ] && "$p" -c 'import sys; assert sys.version_info[:2] == (3, 12)' 2>/dev/null; then
      echo "$p"; return 0
    fi
  done
  return 1
}

PY=$(find_python || true)
if [ -z "$PY" ]; then
  if ! command -v brew >/dev/null; then
    echo "Python 3.12 is required. Install Homebrew (https://brew.sh) and run this again." >&2
    exit 1
  fi
  echo "Installing Python 3.12 with Homebrew…"
  brew install python@3.12
  PY=$(find_python)
fi

mkdir -p .tools run evidence
for env in mvt pmd3; do
  if [ ! -x ".tools/$env/bin/python" ]; then
    echo "Creating .tools/$env…"
    "$PY" -m venv ".tools/$env"
  fi
  ".tools/$env/bin/pip" install -q --upgrade pip
  ".tools/$env/bin/pip" install -q -r "requirements/$env.txt"
done

echo "Downloading the latest spyware indicators…"
.tools/mvt/bin/mvt download-iocs >/dev/null 2>&1 || echo "(offline? indicators will be fetched on the next scan)"

echo "Setup complete. Run from the checkout: .tools/pmd3/bin/python app/server.py"
echo "Build the app: scripts/build_app.sh   (or ./install.sh to build and install it)"

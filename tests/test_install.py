"""install.sh must recognise the bundle ID that build_app.sh gives the app, or it would trash the new install."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_installer_knows_the_current_bundle_id():
    built = re.search(r"<key>CFBundleIdentifier</key><string>([^<]+)</string>", (ROOT / "scripts/build_app.sh").read_text()).group(1)
    ids = re.search(r"^IDS=\(([^)]*)\)", (ROOT / "install.sh").read_text(), re.M).group(1)
    assert f'"{built}"' in ids
    assert 'DEST="$APPS/BugBane.app"' in (ROOT / "install.sh").read_text()
    assert 'APP="$OUT/BugBane.app"' in (ROOT / "scripts/build_app.sh").read_text()

"""Where BugBane's code, tools and data live.

One codebase runs in three setups:

- dev checkout: code, the setup.sh virtualenvs (.tools/) and data (run/, history/, evidence/) all in the
  repository folder.
- legacy install (install.sh before the app bundle): the same layout under
  ~/Library/Application Support/Bugbane.
- app bundle: code and the embedded runtime inside BugBane.app/Contents/Resources, which must stay
  read-only once the app is signed; data in ~/Library/Application Support/Bugbane (so History carries
  over from the legacy install).

BUGBANE_DATA overrides the data folder (tests, CI, a second profile).
"""
import os
from pathlib import Path

APP_SUPPORT = Path.home() / "Library/Application Support/Bugbane"


def in_bundle(root):
    """True when `root` (the folder holding app/) is BugBane.app/Contents/Resources."""
    root = Path(root)
    return root.name == "Resources" and root.parent.name == "Contents" and root.parent.parent.suffix == ".app"


def tools_folder(root):
    """The embedded runtime in a bundle (runtime/), else the setup.sh virtualenvs (.tools/).
    Both have the same shape: <env>/bin/python, <env>/bin/<console script>."""
    root = Path(root)
    return root / "runtime" if (root / "runtime").is_dir() else root / ".tools"


def data_folder(root, environ=os.environ):
    if environ.get("BUGBANE_DATA"):
        return Path(environ["BUGBANE_DATA"])
    return APP_SUPPORT if in_bundle(root) else Path(root)


ROOT = Path(__file__).resolve().parents[2]
TOOLS = tools_folder(ROOT)
DATA = data_folder(ROOT)
EVIDENCE = DATA / "evidence"
HISTORY = DATA / "history"
RUN = DATA / "run"

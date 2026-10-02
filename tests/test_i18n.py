"""Both languages must stay complete and consistent; every key the code uses must exist."""
import json
import re
from pathlib import Path

from scan import i18n
from scan.pipeline import STEPS

ROOT = Path(__file__).resolve().parents[1]
EN = json.loads((ROOT / "app/i18n/en.json").read_text(encoding="utf-8"))
HU = json.loads((ROOT / "app/i18n/hu.json").read_text(encoding="utf-8"))
CHECK_IDS = ("apps", "profiles", "network", "processes", "jetsam", "shutdown", "crashes", "logs", "mvt",
             "browsers", "ios")


def placeholders(s):
    return sorted(set(re.findall(r"\{(\w+)\}", s)))


def test_same_keys():
    assert set(EN) == set(HU)


def test_same_placeholders():
    assert {k: placeholders(v) for k, v in EN.items()} == {k: placeholders(v) for k, v in HU.items()}


def test_keys_used_in_python_exist():
    pattern = re.compile(r"""["']((?:chk|i|hit|d|p|v|level|res|next|net|err|step|explain|rep)\.[\w.]+)["']""")
    used = set()
    for f in (ROOT / "app/scan").glob("*.py"):
        used |= set(pattern.findall(f.read_text()))
    missing = sorted(k for k in used if k not in EN)
    assert not missing, missing


def test_keys_used_in_ui_exist():
    js = (ROOT / "app/ui/app.js").read_text()
    used = set(re.findall(r"""\bT\(\s*["']([\w.]+)["']""", js))
    missing = sorted(k for k in used if k not in EN)
    assert not missing, missing


def test_dynamic_keys_exist():
    needed = [f"chk.{c}.{part}" for c in CHECK_IDS for part in ("title", "what")]
    needed += [f"level.{lvl}" for lvl in ("ok", "info", "warn", "alert", "skipped")]
    needed += [f"step.{s}" for s in STEPS] + [f"explain.{s}" for s in STEPS]
    needed += [f"v.{v}.{p}" for v in ("ok", "warn", "alert", "partial") for p in ("t", "b")]
    needed += [f"learn.{n}.{p}" for n in range(1, 6) for p in ("t", "b")]
    assert not [k for k in needed if k not in EN]


def test_hungarian_formats():
    assert i18n.fmt_num(2269, "hu") == "2269"
    assert i18n.fmt_num(73650, "hu") == "73 650"
    assert i18n.fmt_num(73650, "en") == "73,650"
    ts = 1790000000  # 2026-09-21
    assert re.fullmatch(r"2026\. szept\. \d{1,2}\.", i18n.fmt_date(ts, "hu"))


def test_escaping_and_nesting():
    out = i18n.t("i.apps.vpn", "en", {"name": "<b>x</b>"}, escape=True)
    assert "&lt;b&gt;x&lt;/b&gt;" in out and "<b>x</b>" not in out
    nested = i18n.t("chk.apps.sum", "hu", {"n": 3, "tail": {"t": "chk.apps.tail.ok"}})
    assert nested.startswith("3 alkalmazás ellenőrizve") and "App Store" in nested

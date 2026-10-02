"""Brand: the tokens keep their contrast, the report is self-contained, and the app's
logo symbols are the generated ones."""
import json
import re
from pathlib import Path

from scan.report import render_report

ROOT = Path(__file__).resolve().parents[1]
TOKENS = dict(re.findall(r"--(c-[\w-]+):\s*(#[0-9a-f]{6})", (ROOT / "app/ui/tokens.css").read_text()))


def contrast(a, b):
    def lum(h):
        r, g, b_ = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
        f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
        return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b_)
    hi, lo = sorted((lum(TOKENS[a]), lum(TOKENS[b])), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_text_tokens_meet_wcag_aa():
    text = [("c-ink-light", "c-graphite"), ("c-ink-light", "c-sheet"), ("c-mist", "c-sheet"), ("c-mist-2", "c-sheet"),
            ("c-actaea", "c-sheet"), ("c-alert", "c-sheet"), ("c-warn", "c-sheet"), ("c-info", "c-sheet"),
            ("c-ink", "c-paper"), ("c-stone", "c-paper"), ("c-actaea-deep", "c-paper"), ("c-alert-deep", "c-white"),
            ("c-warn-deep", "c-white"), ("c-info-deep", "c-white"), ("c-graphite", "c-ink-light")]
    for fg, bg in text:
        assert contrast(fg, bg) >= 4.5, (fg, bg, round(contrast(fg, bg), 2))
    for fg, bg in [("c-control", "c-sheet"), ("c-control-light", "c-paper")]:  # field borders: 3:1
        assert contrast(fg, bg) >= 3, (fg, bg, round(contrast(fg, bg), 2))


def test_report_is_self_contained():
    r = {"verdict": "ok", "mode": "quick", "finished": 1790000000, "partial": [], "device": {"name": "X", "model": "iPhone11,2", "ios": "18.7"},
         "indicators": {"total": 7362, "feeds": 19, "families": ["Pegasus"]},
         "checks": [{"id": "apps", "status": "ok", "summary": {"key": "chk.apps.none", "params": {}}, "items": []}]}
    html = render_report(r, "hu")
    assert html.count("url(data:font/woff2;base64,") == 3
    assert "<link" not in html and "@import" not in html and "googleapis" not in html
    assert 'href="#lockup-small"' in html and 'id="lockup-small"' in html
    assert "--c-graphite:" in html  # the brand tokens are inlined


def test_app_symbols_are_the_generated_ones():
    """Run scripts/brand_assets.py after changing the mark; it refreshes both files."""
    generated = re.search(r"<defs>(.*)</defs>", (ROOT / "app/ui/brand.svg").read_text(), re.S).group(1)
    index = (ROOT / "app/ui/index.html").read_text()
    block = re.search(r"<!-- brand:begin \(scripts/brand_assets.py\) -->(.*?)<!-- brand:end -->", index, re.S).group(1)
    assert block == generated
    for f in ("app-icon.svg", "app-icon-small.svg", "lockup.svg", "mark.svg"):  # app_icon.sh renders the icon masters
        assert (ROOT / "assets/brand" / f).is_file(), f


def test_the_name_is_spelled_BugBane():
    for lang in ("en", "hu"):
        strings = json.loads((ROOT / f"app/i18n/{lang}.json").read_text())
        old = [k for k, v in strings.items() if "Bugbane" in v]
        assert not old, old

"""Reports must escape anything that came from a phone."""
from scan.report import render_report

EVIL = "<script>alert(1)</script>"


def results(verdict="warn", partial=()):
    return {
        "verdict": verdict, "mode": "full", "finished": 1790000000, "last_restart": 1789843019,
        "partial": list(partial),
        "device": {"name": "<img src=x onerror=alert(1)>", "model": "iPhone14,5", "ios": "27.0"},
        "indicators": {"total": 7362, "feeds": 19, "families": ["Pegasus", "Predator"]},
        "checks": [{"id": "apps", "status": "warn", "summary": {"key": "chk.apps.sum", "params": {"n": 1, "tail": {"t": "chk.apps.tail.warn"}}},
                    "items": [{"level": "warn", "key": "i.apps.sideload", "params": {"name": EVIL}, "detail": EVIL}]}],
    }


def test_escapes_phone_data_in_both_languages():
    for lang in ("en", "hu"):
        html = render_report(results(), lang)
        assert EVIL not in html and "<img src=x" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_verdicts_are_localized():
    assert "Ismert kémprogram nem található" in render_report(results("ok"), "hu")
    partial = render_report(results("ok", ["processes"]), "en")
    assert "No known spyware in what BugBane could check" in partial and "Programs running right now" in partial

"""Translations shared by the server, the checks and the HTML report.

Strings live in app/i18n/<lang>.json (the UI loads the same files). Checks
store *keys and parameters*, not sentences, so a saved result can be shown in
either language later.

A parameter value can be:
  plain str/int      → inserted (ints get locale digit grouping)
  {"t": key, "p": {}} → a nested translated string
  {"d": ts} / {"dt": ts} → a localized date / date+time
  [ ... ]            → each element rendered, joined with ", "
"""
import datetime as dt
import html
import json
import re
from functools import lru_cache
from pathlib import Path

I18N_DIR = Path(__file__).resolve().parents[1] / "i18n"
LANGS = ("en", "hu")
DEFAULT = "en"
EN_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
HU_MONTHS = ("jan.", "febr.", "márc.", "ápr.", "máj.", "jún.", "júl.", "aug.", "szept.", "okt.", "nov.", "dec.")


@lru_cache(maxsize=None)
def strings(lang):
    lang = lang if lang in LANGS else DEFAULT
    return json.loads((I18N_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def fmt_num(n, lang):
    if lang == "hu":
        # Hungarian typography groups numbers of five or more digits with a (non-breaking) space
        return f"{n:,}".replace(",", " ") if abs(n) >= 10000 else str(n)
    return f"{n:,}"


def fmt_date(ts, lang, with_time=False):
    d = dt.datetime.fromtimestamp(ts)
    if lang == "hu":
        s = f"{d.year}. {HU_MONTHS[d.month - 1]} {d.day}."
    else:
        s = f"{d.day} {EN_MONTHS[d.month - 1]} {d.year}"  # same as the UI (app.js fmtDate)
    return f"{s} {d:%H:%M}" if with_time else s


def t(key, lang, params=None, escape=False):
    """Render `key` in `lang`. With escape=True, plain parameters are HTML-escaped
    (the templates themselves are trusted and may contain markup)."""
    template = strings(lang).get(key) or strings(DEFAULT).get(key) or key
    params = params or {}

    def value(v):
        if isinstance(v, dict):
            if "t" in v:
                return t(v["t"], lang, v.get("p"), escape)
            if "d" in v:
                return fmt_date(v["d"], lang)
            if "dt" in v:
                return fmt_date(v["dt"], lang, with_time=True)
        if isinstance(v, list):
            return ", ".join(value(x) for x in v)
        if isinstance(v, int) and not isinstance(v, bool):
            return fmt_num(v, lang)
        s = str(v)
        return html.escape(s) if escape else s

    out = re.sub(r"\{(\w+)\}", lambda m: value(params[m.group(1)]) if m.group(1) in params else m.group(0),
                 template)
    # Hungarian suffixes hang off a hyphen ("iPhone-on"); a non-breaking hyphen keeps them on the same line
    return re.sub(r"(iPhone|Mac)-", "\\1\u2011", out) if lang == "hu" else out

"""Standalone HTML report, rendered on demand from a result (works offline, no scripts).

Nothing is written to disk here: the server streams it to the browser, where the
user saves or prints it wherever they choose. It is the same examination record as
the results screen: dark on screen, ink on white paper when printed.
"""
import base64
import html
import json
import re
from pathlib import Path

from .i18n import fmt_date, t

APP = Path(__file__).resolve().parents[1]
MODELS = json.loads((APP / "ui" / "models.json").read_text())
LEVELS = ("ok", "info", "warn", "alert", "skipped")
ORDER = ("alert", "warn", "info", "ok", "skipped")

# Brand: the tokens and the logo symbols are the app's own files, and the brand faces are
# embedded, so a saved report looks the same anywhere and loads nothing from the network.
TOKENS = (APP / "ui" / "tokens.css").read_text()
BRAND = (APP / "ui" / "brand.svg").read_text()
# the <use> box starts at 0 0; the symbol's own viewBox does the offset
LOCKUP_VIEW = "0 0 " + " ".join(re.search(r'<symbol id="lockup-small" viewBox="[-\d.]+ [-\d.]+ ([\d.]+ [\d.]+)"', BRAND).group(1).split())


def _face(family, file, weight):
    data = base64.b64encode((APP / "fonts" / file).read_bytes()).decode()
    return (f'@font-face{{font-family:"{family}";src:url(data:font/woff2;base64,{data}) format("woff2");'
            f'font-weight:{weight};font-style:normal;font-display:block}}')


# BugBane Sans and Mono are subsets of IBM Plex Sans and Mono, renamed because "Plex" is a reserved font name
FONTS = (_face("Newsreader", "Newsreader.woff2", "400 500") + _face("BugBane Sans", "BugBaneSans.woff2", "400 600")
         + _face("BugBane Mono", "BugBaneMono-Regular.woff2", "400"))

# Shape-coded level glyphs, the same as app/ui/index.html: diamonds = something found, circles = nothing of concern
GLYPHS = """<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="g-alert" viewBox="0 0 16 16"><path d="M8 1.4 14.6 8 8 14.6 1.4 8z" fill="currentColor"/></symbol>
<symbol id="g-warn" viewBox="0 0 16 16"><path d="M8 2.3 13.7 8 8 13.7 2.3 8z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><circle cx="8" cy="8" r="2" fill="currentColor"/></symbol>
<symbol id="g-info" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.6" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="8" cy="8" r="1.9" fill="currentColor"/></symbol>
<symbol id="g-ok" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.6" fill="none" stroke="currentColor" stroke-width="1.5"/></symbol>
<symbol id="g-skipped" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-dasharray="2.2 2.2"/></symbol>
<symbol id="g-partial" viewBox="0 0 16 16"><path d="M2.4 8a5.6 5.6 0 0 1 11.2 0" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M13.6 8a5.6 5.6 0 0 1-11.2 0" fill="none" stroke="currentColor" stroke-width="1.5" stroke-dasharray="2.2 2.2"/></symbol>
</defs></svg>"""

STYLE = """
:root{color-scheme:dark;--paper:var(--c-graphite);--sheet:var(--c-sheet);--rule:var(--c-rule);--ink:var(--c-ink-light);
--ink-2:var(--c-mist);--ink-3:var(--c-mist-2);
--l-alert:var(--c-alert);--l-warn:var(--c-warn);--l-info:var(--c-info);--l-ok:var(--c-mist);--l-skipped:var(--c-mist-2);--l-partial:var(--c-mist);
--serif:"Newsreader","New York",ui-serif,Georgia,serif;--sans:"BugBane Sans",-apple-system,system-ui,"Helvetica Neue",sans-serif;
--mono:"BugBane Mono",ui-monospace,"SF Mono",Menlo,monospace}
@media print{:root{color-scheme:light;--paper:var(--c-white);--sheet:var(--c-white);--rule:var(--c-rule-light);--ink:var(--c-ink);
--ink-2:var(--c-stone);--ink-3:var(--c-stone);
--l-alert:var(--c-alert-deep);--l-warn:var(--c-warn-deep);--l-info:var(--c-info-deep);--l-ok:var(--c-stone);--l-skipped:var(--c-stone);--l-partial:var(--c-stone)}
main{padding:0}.check,.row{break-inside:avoid}h2{break-after:avoid}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
main{max-width:780px;margin:0 auto;padding:40px 20px 72px}
.mast{display:flex;align-items:center;gap:8px;color:var(--ink-2);font-size:13px;padding-bottom:14px;border-bottom:1px solid var(--rule);margin-bottom:28px}
.mast .lockup{height:18px;width:auto;color:var(--ink);display:block}.mast span{margin-left:auto}
.g{flex:none;vertical-align:-3px}
.l-alert{color:var(--l-alert)}.l-warn{color:var(--l-warn)}.l-info{color:var(--l-info)}.l-ok{color:var(--l-ok)}.l-skipped{color:var(--l-skipped)}.l-partial{color:var(--l-partial)}
.row{display:grid;grid-template-columns:44px 1fr;gap:0 12px}
h1,h2{font-family:var(--serif);font-weight:500;letter-spacing:-.01em}
h1{font-size:30px;line-height:1.2;margin:0 0 10px;font-weight:400}
h2{font-size:21px;margin:36px 0 10px}
h3{font-size:15px;font-weight:600;margin:0}
.lead{font:18px/1.55 var(--serif);margin:0 0 20px;max-width:62ch}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 20px;margin:0 0 18px;padding:14px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);font-size:14px}
dt{color:var(--ink-2)}dd{margin:0}
.legend{display:flex;flex-wrap:wrap;gap:6px 20px;font-size:13.5px;color:var(--ink-2);margin:0}
.legend>span{display:inline-flex;align-items:center;gap:6px}.legend b{color:var(--ink);font-variant-numeric:tabular-nums}
ol{margin:0;padding-left:20px;max-width:64ch}ol li{margin:0 0 8px;padding-left:4px}
.check{padding:14px 0;border-top:1px solid var(--rule)}
.check .flag{padding-top:2px}
.head{display:flex;gap:16px;align-items:baseline}.head .st{margin-left:auto;font-size:13px;white-space:nowrap}
.sum{margin:3px 0 0;color:var(--ink-2);font-size:14px}
.item{display:grid;grid-template-columns:18px 1fr;gap:4px 8px;margin:12px 0 0;font-size:14px}
.item .g{margin-top:3px}
.item .word{font-weight:600}
code{grid-column:2;display:block;font:12px/1.5 var(--mono);color:var(--ink-2);word-break:break-all}
.what{margin:10px 0 0;font-size:13px;color:var(--ink-3);max-width:64ch}
.foot{margin-top:40px;padding-top:16px;border-top:1px solid var(--rule);font-size:13px;color:var(--ink-2)}
.foot p{margin:0 0 10px;max-width:68ch}.foot b{color:var(--ink)}
@media (max-width:560px){.row{grid-template-columns:28px 1fr;gap:0 8px}h1{font-size:25px}.head{flex-direction:column;gap:2px}.head .st{margin-left:0}}
"""


def glyph(level, size=16):
    return (f'<svg class="g l-{level}" width="{size}" height="{size}" aria-hidden="true">'
            f'<use href="#g-{level}"/></svg>')


def verdict_text(results, lang):
    v = results["verdict"]
    if v == "ok" and results.get("partial"):
        names = [t(f"chk.{cid}.title", lang) for cid in results["partial"]]
        return (t("v.partial.t", lang),
                t("v.partial.b", lang, {"list": ", ".join(names),
                                        "fix": {"t": results.get("partial_fix") or "v.partial.fix.other"}},
                  escape=True), "partial")
    return t(f"v.{v}.t", lang), t(f"v.{v}.b", lang, {"total": results["indicators"]["total"]}), v


def next_steps(verdict):
    common = ["next.update", "next.restart", "next.safety", "next.password", "next.lockdown"]
    if verdict == "alert":
        # next.alert2 ("choose below") points at a control that only exists in the app
        return ["next.alert1", "next.alert3", "next.alert4", "next.alert5"]
    return ["next.warn", *common] if verdict == "warn" else common


def check_section(c, lang):
    items = []
    for i in c["items"]:
        word = (f'<span class="word l-{i["level"]}">{t("level." + i["level"], lang)}.</span> '
                if i["level"] != c["status"] else "")
        detail = f'<code>{html.escape(i["detail"])}</code>' if i.get("detail") else ""
        items.append(f'<div class="item">{glyph(i["level"], 14)}<span>{word}'
                     f'{t(i["key"], lang, i.get("params"), escape=True)}</span>{detail}</div>')
    summary = t(c["summary"]["key"], lang, c["summary"].get("params"), escape=True)
    return f'''<section class="row check">
  <div class="flag">{glyph(c["status"])}</div>
  <div>
    <div class="head"><h3>{t(f"chk.{c['id']}.title", lang)}</h3><span class="st l-{c["status"]}">{t("level." + c["status"], lang)}</span></div>
    <p class="sum">{summary}</p>
    {"".join(items)}
    <p class="what">{t(f"chk.{c['id']}.what", lang)}</p>
  </div>
</section>'''


def render_report(results, lang, version=""):
    d = results.get("device") or {}
    ind = results["indicators"]
    name = d.get("name") or "iPhone"
    title, blurb, vclass = verdict_text(results, lang)
    label = [
        (t("res.l.iphone", lang), t("res.v.iphone", lang, {"name": name, "model": MODELS.get(d.get("model"), d.get("model") or "iPhone"),
                                                            "ios": d.get("ios") or "?"}, escape=True)),
        (t("res.l.check", lang), t("res.v.check", lang, {"mode": {"t": f"res.mode.{results['mode']}"},
                                                          "date": {"dt": results["finished"]}})),
        (t("res.l.compared", lang), t("res.v.compared", lang, {"total": ind["total"], "feeds": ind["feeds"]})),
    ]
    if results.get("last_restart"):
        label.append((t("res.l.restart", lang), fmt_date(results["last_restart"], lang, with_time=True)))
    counts = {}
    for c in results["checks"]:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    legend = "".join(f'<span>{glyph(k, 14)}<span>{t("level." + k, lang)}</span><b>{counts[k]}</b></span>'
                     for k in ORDER if counts.get(k))
    families = ", ".join(ind.get("families") or [])
    limits = (t("res.clean_b", lang, {"families": families}, escape=True) if vclass in ("ok", "partial")
              else t("res.provenance", lang, {"families": families}, escape=True))
    method = t("rep.method", lang, {"version": version}).replace("  ", " ")
    return f'''<!doctype html><html lang="{lang}"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{t("rep.title", lang, {"name": name}, escape=True)}</title>
<style>{FONTS}{TOKENS}{STYLE}</style>
{GLYPHS}{BRAND}
<main>
<header class="mast"><svg class="lockup" viewBox="{LOCKUP_VIEW}" role="img" aria-label="BugBane"><use href="#lockup-small"/></svg>
<span>{t("rep.title", lang, {"name": name}, escape=True)}</span></header>
<div class="row">
  <div class="flag">{glyph(vclass, 28)}</div>
  <div>
    <h1>{title}</h1>
    <p class="lead">{blurb}</p>
    <dl>{"".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in label)}</dl>
    <p class="legend" aria-label="{t("res.legend", lang)}">{legend}</p>
  </div>
</div>
<div class="row"><div></div><div>
  <h2>{t("res.next", lang)}</h2>
  <ol>{"".join(f"<li>{t(k, lang)}</li>" for k in next_steps(results["verdict"]))}</ol>
  <h2>{t("res.all", lang)}</h2>
</div></div>
{"".join(check_section(c, lang) for c in results["checks"])}
<div class="foot">
  <p>{limits}</p>
  <p><b>{t("rep.l.method", lang)}.</b> {method}</p>
  <p><b>{t("rep.help_t", lang)}</b> {t("rep.help_b", lang)}</p>
  <p>{t("rep.generated", lang)}</p>
</div>
</main></html>'''

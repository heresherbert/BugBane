#!/usr/bin/env python3
"""Generates BugBane's brand assets from one construction.

Writes:
  assets/brand/*.svg    master files: the mark, lockups and the app icon (Mac and full-bleed), in fixed colours
  app/ui/brand.svg      the symbols the app and the report use (mark, lockups)
  app/ui/index.html     the symbol block between the brand markers, refreshed from app/ui/brand.svg
  app/fonts/            subsets of the brand faces for the report (Latin and Hungarian) and their licences;
                        the IBM Plex subsets are named BugBane Sans and BugBane Mono (Plex is a reserved name)

The fonts come from google/fonts at pinned commits and are checked against SHA-256 before use; they are
cached in .cache/brand-fonts/. Needs the dev requirements (fonttools, uharfbuzz).

Usage: .venv/bin/python scripts/brand_assets.py
"""
import hashlib
import io
import re
import urllib.request
from pathlib import Path

import uharfbuzz as hb
from fontTools import subset
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache/brand-fonts"
GF = "https://raw.githubusercontent.com/google/fonts"
SOURCES = {  # file: (path at a pinned google/fonts commit, sha256)
    "Newsreader[opsz,wght].ttf": ("8b0a1d0f5983c89bc2b93f1b5fb55f9e252744b5/ofl/newsreader/Newsreader%5Bopsz,wght%5D.ttf",
                                  "8a08d13f8a6c0d51be379a60af84f945f65369a67e509ee3c3bdcc421254d7c1"),
    "OFL-Newsreader.txt": ("8b0a1d0f5983c89bc2b93f1b5fb55f9e252744b5/ofl/newsreader/OFL.txt",
                           "fdfad38143ec470553cae82a1e45320bdd1b9ec70415d37bd0171051d8a4ded8"),
    "IBMPlexSans[wdth,wght].ttf": ("0b58fb370093f9a9f4ff785d94405710b79de67c/ofl/ibmplexsans/IBMPlexSans%5Bwdth,wght%5D.ttf",
                                   "3b031aa4216174205bd8471f88a49b91f093169e9e87bd5262242bc5967fe2e3"),
    "OFL-IBMPlexSans.txt": ("0b58fb370093f9a9f4ff785d94405710b79de67c/ofl/ibmplexsans/OFL.txt",
                            "7e6b2818edbd8f6a01ae80641cc8f16a51080d08fb4e532be3a0b6f74adb07da"),
    "IBMPlexMono-Regular.ttf": ("0b58fb370093f9a9f4ff785d94405710b79de67c/ofl/ibmplexmono/IBMPlexMono-Regular.ttf",
                                "6a3412f058c7d8dfd9170c41e85ade48e5156ecb89356110ca57a0a27734af46"),
    "OFL-IBMPlexMono.txt": ("0b58fb370093f9a9f4ff785d94405710b79de67c/ofl/ibmplexmono/OFL.txt",
                            "7e6b2818edbd8f6a01ae80641cc8f16a51080d08fb4e532be3a0b6f74adb07da"),
}
# Basic Latin, Latin-1, Latin Extended-A (Hungarian ő ű), general punctuation, euro, trademark, minus
UNICODES = [*range(0x20, 0x7F), *range(0xA0, 0x180), *range(0x2010, 0x2028), *range(0x2030, 0x203B), 0x20AC, 0x2122, 0x2212]

INK, INK_LIGHT, PAPER, NIGHT = "#1a191d", "#ecebee", "#f6f5f7", "#141317"
NAME = "BugBane"


def font(name):
    path = CACHE / name
    url, sha = SOURCES[name]
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        path.write_bytes(urllib.request.urlopen(f"{GF}/{url}", timeout=60).read())
    if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
        path.unlink()
        raise SystemExit(f"{name}: checksum mismatch, refusing to use it")
    return path


# ---- the mark --------------------------------------------------------------------------------------------
# "Fine-tooth": a boxwood comb. Going over something with a fine-tooth comb is what BugBane does to a phone's
# records, and a nit comb is the oldest household bug bane (in Hungarian, "átfésül"). Drawn on the 1024 icon
# canvas: an arched spine (a half-ellipse sitting on the root line), two square-shouldered guard teeth that
# continue the arch's vertical ends, and tapered inner teeth with round tips. Three cuts:
ICON = dict(x0=152.0, x1=872.0, apex=312.0, root=512.0, tip=748.0, n_inner=15, guard=40.0, tooth_root=21.0,
            tooth_tip=16.0)                                                      # the app icon: 17 teeth
MARK = dict(ICON, n_inner=9, guard=48.0, tooth_root=30.0, tooth_tip=24.0, apex=300.0, root=520.0, tip=744.0)
SMALL = dict(ICON, n_inner=5, guard=64.0, tooth_root=60.0, tooth_tip=52.0, apex=300.0, root=520.0)
# MARK: the UI glyph at 18-24 px, 11 heavier teeth. SMALL: the icon's 16 and 32 px slots, 7 teeth.


def comb(g, ink="currentColor"):
    x0, x1, apex, root, tip = g["x0"], g["x1"], g["apex"], g["root"], g["tip"]
    rx, ry = (x1 - x0) / 2, root - apex
    out = [f'<path d="M{x0:.1f} {root + 1:.1f}V{root:.1f}A{rx:.1f} {ry:.1f} 0 0 1 {x1:.1f} {root:.1f}V{root + 1:.1f}Z" fill="{ink}"/>']
    gw = g["guard"]
    for gx in (x0, x1 - gw):  # guard teeth, squared at the top so they join the spine without a notch
        out.append(f'<rect x="{gx:.1f}" y="{root - 2:.1f}" width="{gw:.1f}" height="{tip - root + 2:.1f}" rx="{gw / 2:.1f}" fill="{ink}"/>'
                   f'<rect x="{gx:.1f}" y="{root - 2:.1f}" width="{gw:.1f}" height="{gw:.1f}" fill="{ink}"/>')
    n, wr, wt = g["n_inner"], g["tooth_root"], g["tooth_tip"]
    span0, span1 = x0 + gw, x1 - gw
    gap = (span1 - span0 - n * wr) / (n + 1)
    for i in range(n):
        cx, y_end = span0 + gap * (i + 1) + wr * i + wr / 2, tip - wt / 2
        out.append(f'<path d="M{cx - wr / 2:.2f} {root - 2:.1f}H{cx + wr / 2:.2f}L{cx + wt / 2:.2f} {y_end:.2f}'
                   f'A{wt / 2:.2f} {wt / 2:.2f} 0 0 1 {cx - wt / 2:.2f} {y_end:.2f}Z" fill="{ink}"/>')
    return "".join(out)


def mark_view(g=MARK):
    return f'{g["x0"]:.0f} {g["apex"]:.0f} {g["x1"] - g["x0"]:.0f} {g["tip"] - g["apex"]:.0f}'


# ---- the wordmark ----------------------------------------------------------------------------------------
def wordmark(opsz, tracking):
    """'BugBane' in Newsreader Medium at an optical size, shaped with HarfBuzz (kerning), as one SVG path.
    Returns (path, advance, ink bounds) in font units with the baseline at y=0, y pointing down."""
    var = TTFont(font("Newsreader[opsz,wght].ttf"))
    inst = instancer.instantiateVariableFont(var, {"opsz": opsz, "wght": 500})
    buf = io.BytesIO()
    inst.save(buf)
    data = buf.getvalue()
    tt = TTFont(io.BytesIO(data))
    glyphs, order, upm = tt.getGlyphSet(), tt.getGlyphOrder(), tt["head"].unitsPerEm
    face = hb.Face(data)
    hbuf = hb.Buffer()
    hbuf.add_str(NAME)
    hbuf.guess_segment_properties()
    hb.shape(hb.Font(face), hbuf, {"kern": True, "liga": True})
    pen, bounds, x = SVGPathPen(glyphs), BoundsPen(glyphs), 0.0
    for info, pos in zip(hbuf.glyph_infos, hbuf.glyph_positions):
        g = glyphs[order[info.codepoint]]
        m = (1, 0, 0, -1, x + pos.x_offset, -pos.y_offset)
        g.draw(TransformPen(pen, m))
        g.draw(TransformPen(bounds, m))
        x += pos.x_advance + tracking * upm
    return pen.getCommands(), x - tracking * upm, bounds.bounds, upm


def lockup(small=False):
    """The comb before the word, its teeth on the baseline, a little taller than the x-height: (inner svg, viewBox)."""
    path, adv, (xmin, ymin, xmax, ymax), upm = wordmark(16 if small else 72, 0 if small else -0.02)
    g = MARK
    s = 0.59 * upm / (g["tip"] - g["apex"])
    mw, gap = (g["x1"] - g["x0"]) * s, 0.19 * upm
    word_x = mw + gap - xmin
    inner = (f'<g transform="translate({-g["x0"] * s:.1f} {-g["tip"] * s:.1f}) scale({s:.5f})">{comb(g)}</g>'
             f'<path transform="translate({word_x:.1f} 0)" d="{path}" fill="currentColor"/>')
    top = min(-(g["tip"] - g["apex"]) * s, ymin)
    return inner, f"0 {top:.0f} {word_x + xmax:.0f} {ymax - top:.0f}"


# ---- outputs ---------------------------------------------------------------------------------------------
def svg(view, body, label=None, extra=""):
    a11y = f' role="img" aria-label="{label}"' if label else ""
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}"{a11y}{extra}>{body}</svg>\n'


GROUNDS = {"light": (PAPER, INK), "dark": (NIGHT, INK_LIGHT), "tinted": (NIGHT, "#d2d0d6")}


def icon(appearance="light", small=False, mac=True):
    """The app icon. Full bleed (iOS, Icon Composer layers) or, for macOS, masked on Apple's grid: an 824 px
    rounded square, corner radius 185, centred on the 1024 canvas. The comb carries no accent colour."""
    bg, ink = GROUNDS[appearance]
    art = f'<rect width="1024" height="1024" fill="{bg}"/>{comb(SMALL if small else ICON, ink)}'
    if not mac:
        return svg("0 0 1024 1024", art, f"{NAME} app icon")
    cid = f"bb-mac-{appearance}{'-small' if small else ''}"  # unique when several share a page
    return svg("0 0 1024 1024",
               f'<defs><clipPath id="{cid}"><rect x="100" y="100" width="824" height="824" rx="185"/></clipPath></defs>'
               f'<g clip-path="url(#{cid})"><g transform="translate(100 100) scale(0.8046875)">{art}</g></g>',
               f"{NAME} app icon")


# IBM Plex declares "Plex" a Reserved Font Name: a modified version (a subset is one) must not use it, so the
# subsets are renamed. Copyright and licence notices (name IDs 0, 7, 13, 14) keep their text.
RENAME = {"IBM Plex Sans": "BugBane Sans", "IBMPlexSans": "BugBaneSans", "IBM Plex Mono": "BugBane Mono",
          "IBMPlexMono": "BugBaneMono"}
NOTICE_IDS = {0, 7, 13, 14}


def _rename(tt):
    for rec in tt["name"].names:
        if rec.nameID in NOTICE_IDS:
            continue
        text = rec.toUnicode()
        for old, new in RENAME.items():
            text = text.replace(old, new)
        rec.string = text
        if "Plex" in text:
            raise SystemExit(f"name ID {rec.nameID} still says Plex: {text}")


def subset_font(src, out, axes, rename=False):
    tt = TTFont(font(src), recalcTimestamp=False)  # keep the source's dates, so re-running changes nothing
    if axes:
        buf = io.BytesIO()
        instancer.instantiateVariableFont(tt, axes).save(buf)  # reload: subsetting a partial instance in memory fails
        tt = TTFont(io.BytesIO(buf.getvalue()), recalcTimestamp=False)
    opts = subset.Options()
    opts.flavor = "woff2"
    opts.layout_features = ["kern", "liga", "calt", "mark", "mkmk", "ccmp", "locl", "tnum", "lnum"]
    opts.name_IDs = ["*"]
    opts.notdef_outline = True
    sub = subset.Subsetter(opts)
    sub.populate(unicodes=UNICODES)
    sub.subset(tt)
    if rename:
        _rename(tt)
    tt.flavor = "woff2"
    tt.save(out)
    return out.stat().st_size


def main():
    brand = ROOT / "assets/brand"
    brand.mkdir(parents=True, exist_ok=True)
    out = {}
    for tone, ink in (("", INK), ("-on-dark", INK_LIGHT)):
        out[f"mark{tone}.svg"] = svg(mark_view(), comb(MARK, ink), NAME)
        for small, suffix in ((False, ""), (True, "-small")):
            inner, view = lockup(small)
            out[f"lockup{suffix}{tone}.svg"] = svg(view, inner.replace("currentColor", ink), NAME)
    out["mark-mono.svg"] = svg(mark_view(), comb(MARK, "#000"), NAME)
    out["app-icon.svg"] = icon("light")                    # the Mac icon (default appearance)
    out["app-icon-small.svg"] = icon("light", small=True)  # its 16 and 32 px slots
    out["app-icon-dark.svg"] = icon("dark")
    for appearance in ("light", "dark", "tinted"):         # full-bleed masters for iOS and Icon Composer
        out[f"app-icon-ios-{appearance}.svg"] = icon(appearance, mac=False)
    for f in brand.glob("*.svg"):
        if f.name not in out:
            f.unlink()  # a retired asset
    for name, text in out.items():
        (brand / name).write_text(text)

    # symbols for the app and the report, in one colour (currentColor)
    lk, lk_view = lockup(False)
    lks, lks_view = lockup(True)
    symbols = (f'<symbol id="mark" viewBox="{mark_view()}">{comb(MARK)}</symbol>'
               f'<symbol id="lockup" viewBox="{lk_view}">{lk}</symbol>'
               f'<symbol id="lockup-small" viewBox="{lks_view}">{lks}</symbol>')
    (ROOT / "app/ui/brand.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" style="position:absolute" aria-hidden="true">'
        f"<!-- generated by scripts/brand_assets.py --><defs>{symbols}</defs></svg>\n")
    index = ROOT / "app/ui/index.html"
    html = index.read_text()
    block = f"<!-- brand:begin (scripts/brand_assets.py) -->{symbols}<!-- brand:end -->"
    html, n = re.subn(r"<!-- brand:begin.*?<!-- brand:end -->", lambda m: block, html, flags=re.S)
    if n != 1:
        raise SystemExit("app/ui/index.html: brand markers not found")
    _, _, w, h = lks_view.split()  # the <use> box starts at 0 0; the symbol's own viewBox does the offset
    html, n = re.subn(r'<svg class="lockup"[^>]*>', f'<svg class="lockup" viewBox="0 0 {w} {h}" role="img" aria-label="{NAME}">', html)
    if n != 1:
        raise SystemExit("app/ui/index.html: the toolbar lockup is missing")
    index.write_text(html)

    fonts = ROOT / "app/fonts"
    fonts.mkdir(exist_ok=True)
    sizes = {
        "Newsreader.woff2": subset_font("Newsreader[opsz,wght].ttf", fonts / "Newsreader.woff2", {"wght": (400, 500)}),
        "BugBaneSans.woff2": subset_font("IBMPlexSans[wdth,wght].ttf", fonts / "BugBaneSans.woff2",
                                         {"wdth": 100, "wght": (400, 600)}, rename=True),
        "BugBaneMono-Regular.woff2": subset_font("IBMPlexMono-Regular.ttf", fonts / "BugBaneMono-Regular.woff2", None,
                                                 rename=True),
    }
    for lic in ("OFL-Newsreader.txt", "OFL-IBMPlexSans.txt", "OFL-IBMPlexMono.txt"):
        (fonts / lic).write_bytes(font(lic).read_bytes())
    for k, v in sizes.items():
        print(f"app/fonts/{k}: {v // 1024} KB")
    print(f"assets/brand: {len(list(brand.glob('*.svg')))} files; app/ui/brand.svg and index.html updated")


if __name__ == "__main__":
    main()

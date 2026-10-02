#!/usr/bin/env python3
"""Known-answer detection report: replay every public indicator through the checks and show the result.

Uses only the indicator lists downloaded by setup.sh and hand-made artifacts; reads nothing from a
phone. Exit code 1 if any indicator is missed.

  .tools/pmd3/bin/python scripts/detection_report.py            (or any Python with the repo's deps)
  ... --markdown        table for docs
"""
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "app"), str(ROOT / "tests")]

import replay as R  # noqa: E402
from scan import iocs  # noqa: E402


def short(feed):
    return feed.replace("raw.githubusercontent.com_", "").replace("mvt-project_mvt-indicators_main_", "mvt/") \
        .replace("AmnestyTech_investigations_master_", "amnesty/").replace("AssoEchap_stalkerware-indicators_master_", "echap/")


def main():
    index = iocs.load()
    if not index.size:
        sys.exit("No indicator lists found. Run ./setup.sh first.")
    outcomes = R.replay(index)
    tables = {k: getattr(index, k) for k in R.KINDS}
    per_feed = defaultdict(lambda: Counter())
    for kind, table in tables.items():
        for value, ind in table.items():
            per_feed[ind.feed]["total"] += 1
            per_check = outcomes.get((kind, value))
            if per_check is None:
                per_feed[ind.feed]["not_replayed"] += 1
            elif all(per_check.values()):
                per_feed[ind.feed]["caught"] += 1
            else:
                per_feed[ind.feed]["missed"] += 1
    md = "--markdown" in sys.argv
    rows = [(short(f), c["total"], c["caught"], c["missed"], c["not_replayed"]) for f, c in sorted(per_feed.items())]
    totals = [sum(r[i] for r in rows) for i in range(1, 5)]
    head = ("Indicator list", "Indicators", "Caught", "Missed", "Not replayed")
    if md:
        print("| " + " | ".join(head) + " |\n|---|---:|---:|---:|---:|")
        for r in [*rows, ("**Total**", *totals)]:
            print("| " + " | ".join(str(x) for x in r) + " |")
    else:
        w = max(len(r[0]) for r in rows) + 2
        print(f"{head[0]:{w}}" + "".join(f"{h:>14}" for h in head[1:]))
        for r in [*rows, ("TOTAL", *totals)]:
            print(f"{r[0]:{w}}" + "".join(f"{x:>14}" for x in r[1:]))
    def section(title):
        print(f"\n### {title}\n" if md else f"\n{title}:")

    def line(text):
        print(f"- {text}" if md else f"  {text}")

    section("Checks exercised per kind of indicator")
    for kind, checks_ in R.KIND_CHECKS.items():
        n = sum(1 for (k, _) in outcomes if k == kind)
        line(f"{kind}: {n} replayed -> {', '.join(checks_)}")
    missed = R.misses(outcomes)
    if missed:
        section(f"MISSED ({len(missed)})")
        for kind, value, check in missed[:50]:
            line(f"{kind}: `{value}` (check: {check})" if md else f"{kind}: {value}  (check: {check})")
    section("Not replayed (needs a different artifact than the ones this harness builds)")
    notes = Counter()
    for kind, table in tables.items():
        for value in table:
            if (kind, value) not in outcomes:
                notes["directory path" if value.endswith("/") else
                      "contains spaces or parentheses" if not R._plain(value) else
                      "relative path" if kind == "file_paths" and not value.startswith("/") else "other"] += 1
    for why, n in notes.most_common():
        line(f"{n} {why}")
    if not notes:
        line("none")
    print("\nWhat this shows: the checks raise every replayable public indicator, with the right family and "
          "level, and stay quiet for everyday software. What it does not show: detection of spyware that has "
          "no published indicator, or that hides its traces. A clean result never means 'safe'.")
    sys.exit(1 if missed else 0)


if __name__ == "__main__":
    main()

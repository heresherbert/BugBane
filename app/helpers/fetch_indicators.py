"""Download the public spyware indicator lists, verifying them before they replace the current copies.

Replaces `mvt download-iocs` and writes the same files to the same folder (MVT and BugBane's checks both read
them), but refuses what MVT would accept blindly:

- the index comes only from MVT's indicator repository, and lists only from the GitHub repositories in SOURCES;
  a new source is refused (and reported) until it has been reviewed and added here;
- TLS is verified against certifi's roots; every download has a size limit;
- a list must be a STIX2 bundle with at least one indicator;
- a list that suddenly loses more than half of its indicators is refused and the previous copy kept, so an
  emptied or truncated list can't silently hide spyware;
- a new copy is written next to the old one and swapped in only when complete.

Runs with the MVT environment's Python (it has PyYAML and certifi). Prints one JSON summary line; writes
bugbane-indicators.json (SHA-256, indicator count and time per list) next to the indicators folder.

Usage: fetch_indicators.py --dest <indicators folder> [--strict]
  --strict: exit 1 if any list was refused or failed (CI uses it to notice upstream changes the same day).
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path

INDEX_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
RAW = "https://raw.githubusercontent.com/{}/{}/{}/{}"
SOURCES = {"mvt-project/mvt-indicators", "AmnestyTech/investigations", "AssoEchap/stalkerware-indicators"}
MAX_INDEX = 1 << 20      # 1 MiB
MAX_LIST = 64 << 20      # 64 MiB; the largest list today is a few MB
SHRINK_LIMIT = 0.5       # refuse a list with fewer than half the indicators of the copy it would replace...
SHRINK_MIN = 20          # ...when that copy had at least this many


def _context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def fetch(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "BugBane indicator update"})
    with urllib.request.urlopen(req, timeout=30, context=_context()) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"larger than {limit} bytes")
    return data


def file_name(url):
    # MVT's naming (lstrip removes leading characters from the set "htps:/"), so MVT finds the same files
    return url.lstrip("https://").replace("/", "_")


def count_indicators(data):
    """Number of STIX indicators in a bundle; ValueError if it isn't one."""
    bundle = json.loads(data)
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("not a STIX2 bundle")
    return sum(1 for o in bundle["objects"] if isinstance(o, dict) and o.get("type") == "indicator")


def list_url(entry):
    """The download URL of an index entry, or ValueError if its source isn't allowed."""
    if entry.get("type") != "github":
        raise ValueError(f"source type {entry.get('type')!r} not allowed")
    gh = entry.get("github") or {}
    owner, repo, branch, path = gh.get("owner", ""), gh.get("repo", ""), gh.get("branch", "main"), gh.get("path", "")
    if f"{owner}/{repo}" not in SOURCES:
        raise ValueError(f"source {owner}/{repo} not allowed")
    if not path.endswith(".stix2") or ".." in path.split("/") or not branch or "/" in branch:
        raise ValueError(f"unexpected path {branch}:{path}")
    return RAW.format(owner, repo, branch, path)


def update(dest, fetch=fetch):
    try:
        from yaml import safe_load as parse_index
    except ImportError:  # outside MVT's environment (tests): the index is then expected as JSON
        parse_index = json.loads
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    manifest_path = dest.parent / "bugbane-indicators.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError):
        manifest = {}
    lists = manifest.get("lists", {})
    summary = {"updated": [], "kept": [], "refused": [], "failed": []}
    try:
        index = parse_index(fetch(INDEX_URL, MAX_INDEX))
        entries = index.get("indicators") if isinstance(index, dict) else None
        if not isinstance(entries, list) or not entries:
            raise ValueError("index has no indicator lists")
    except Exception as e:  # noqa: BLE001 — any failure keeps every current list
        summary["failed"].append({"list": "index", "error": str(e)[:200]})
        return summary
    for entry in entries:
        name = (entry or {}).get("name", "?") if isinstance(entry, dict) else "?"
        try:
            url = list_url(entry)
        except ValueError as e:
            summary["refused"].append({"list": name, "error": str(e)})
            continue
        target = dest / file_name(url)
        try:
            data = fetch(url, MAX_LIST)
            count = count_indicators(data)
        except Exception as e:  # noqa: BLE001
            summary["failed"].append({"list": name, "error": str(e)[:200]})
            continue
        previous = 0
        if target.exists():
            try:
                previous = count_indicators(target.read_bytes())
            except ValueError:
                previous = 0
        if count == 0 or (previous >= SHRINK_MIN and count < previous * SHRINK_LIMIT):
            summary["kept"].append({"list": name, "error": f"{count} indicators instead of {previous}: kept the "
                                                            "current copy"})
            continue
        with tempfile.NamedTemporaryFile(dir=dest, prefix=".download-", delete=False) as tmp:
            tmp.write(data)
        os.replace(tmp.name, target)
        lists[target.name] = {"name": name, "url": url, "sha256": hashlib.sha256(data).hexdigest(),
                              "indicators": count, "fetched": dt.datetime.now(dt.timezone.utc).isoformat()}
        summary["updated"].append(name)
    manifest = {"lists": lists, "checked": dt.datetime.now(dt.timezone.utc).isoformat()}
    with tempfile.NamedTemporaryFile("w", dir=dest.parent, prefix=".manifest-", delete=False) as tmp:
        json.dump(manifest, tmp, indent=1)
    os.replace(tmp.name, manifest_path)
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dest", required=True)
    p.add_argument("--strict", action="store_true")
    args = p.parse_args()
    summary = update(args.dest)
    print(json.dumps({"updated": len(summary["updated"]), **{k: summary[k] for k in ("kept", "refused", "failed")}}))
    problems = summary["kept"] or summary["refused"] or summary["failed"]
    sys.exit(1 if not summary["updated"] or (args.strict and problems) else 0)


if __name__ == "__main__":
    main()

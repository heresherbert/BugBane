"""Load MVT's downloaded STIX2 bundles into exact-match lookup tables.

Matching is deliberately strict: process names match whole basenames,
domains match on label boundaries (evil.com matches cdn.evil.com, never
notevil.com), and directory indicators (paths ending in "/") match what lies
inside them on path-component boundaries (/a/dir/ matches /a/dir/x, never
/a/dir2/x). Loose substring matching flagged Apple's `accessoryupdaterd`
as Pegasus's `updaterd` during the first manual scan.
"""
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


def mvt_data_folder():
    """Where `mvt download-iocs` keeps its data, by MVT's own rule: $MVT_DATA_FOLDER, else the
    platform's user data folder (appdirs' user_data_dir("mvt"))."""
    if os.environ.get("MVT_DATA_FOLDER"):
        return Path(os.environ["MVT_DATA_FOLDER"])
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/mvt"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "mvt"


MVT_INDICATORS_DIR = mvt_data_folder() / "indicators"

# Human-readable names for STIX malware objects (None = generic label, not shown as a family)
DISPLAY_NAMES = {
    "OperationTriangulation": "Operation Triangulation", "RCSLab": "RCS Lab (Hermit)",
    "WyrmSpy_DragonEgg": "WyrmSpy/DragonEgg", "KingSpawn": "QuaDream KingSpawn",
    "Wintego Helios": "Wintego Helios", "MercenarySpywareCampaign": None,
}

# Stalkerware/"watchware" (parental-control) feeds vs. mercenary spyware.
# The difference drives how loudly a hit is reported.
STALKERWARE_FEEDS = ("stalkerware",)


@dataclass
class Indicator:
    value: str
    kind: str  # domain | process | file_path | file_name | app_id | email | url
    malware: str
    feed: str
    category: str  # mercenary | stalkerware


@dataclass
class IOCIndex:
    domains: dict = field(default_factory=dict)
    processes: dict = field(default_factory=dict)
    file_paths: dict = field(default_factory=dict)
    file_names: dict = field(default_factory=dict)
    app_ids: dict = field(default_factory=dict)
    feeds: list = field(default_factory=list)

    def match_domain(self, host):
        """Return the Indicator for host or any parent domain of it."""
        if not host:
            return None
        labels = host.lower().rstrip(".").split(".")
        for i in range(len(labels) - 1):
            hit = self.domains.get(".".join(labels[i:]))
            if hit:
                return hit
        return None

    def match_process(self, path_or_name):
        name = os.path.basename((path_or_name or "").rstrip("/"))
        return self.processes.get(name)

    def match_path(self, path):
        if not path:
            return None
        if path in self.file_paths:
            return self.file_paths[path]
        # directory indicators: the folder itself, or anything inside it (the "/" is the boundary)
        for directory in self._directories():
            if path.startswith(directory) or path + "/" == directory:
                return self.file_paths[directory]
        return self.file_names.get(os.path.basename(path))

    def _directories(self):
        """Directory indicators, deepest first, so the most specific one names the family.

        Only folders at least four levels deep (/private/var/tmp/icloud_dump/): a broad indicator such as
        /private/var/tmp/ would otherwise flag everything iOS keeps there. Those still match exactly."""
        cached = getattr(self, "_dirs", None)
        if cached is None or cached[0] != len(self.file_paths):
            dirs = sorted((p for p in self.file_paths if p.endswith("/") and p.count("/") >= 5), key=len, reverse=True)
            cached = self._dirs = (len(self.file_paths), dirs)
        return cached[1]

    @property
    def size(self):
        return sum(len(t) for t in (self.domains, self.processes, self.file_paths, self.file_names, self.app_ids))


PATTERN = re.compile(r"\[(?P<obj>[\w-]+):(?P<prop>[\w.]+)\s*=\s*'(?P<val>(?:[^'\\]|\\.)*)'\]")
KINDS = {
    ("domain-name", "value"): "domains",
    ("process", "name"): "processes",
    ("file", "path"): "file_paths",
    ("file", "name"): "file_names",
    ("app", "id"): "app_ids",
}
KIND_LABELS = {"domains": "domain", "processes": "process", "file_paths": "file path",
               "file_names": "file name", "app_ids": "app"}


def load(indicators_dir=MVT_INDICATORS_DIR):
    index = IOCIndex()
    for bundle_path in sorted(Path(indicators_dir).glob("*.stix2")):
        try:
            bundle = json.loads(bundle_path.read_text())
        except (OSError, ValueError):
            continue
        feed = bundle_path.stem
        category = "stalkerware" if any(k in feed.lower() for k in STALKERWARE_FEEDS) else "mercenary"
        objects = bundle.get("objects", [])
        malware = {o["id"]: DISPLAY_NAMES.get(o.get("name"), o.get("name")) or "spyware campaign"
                   for o in objects if o.get("type") == "malware"}
        owner = {r["source_ref"]: malware.get(r["target_ref"]) for r in objects
                 if r.get("type") == "relationship" and r.get("target_ref") in malware}
        default_name = next(iter(malware.values()), feed)
        feed_names = set()
        for o in objects:
            if o.get("type") != "indicator":
                continue
            m = PATTERN.search(o.get("pattern", ""))
            if not m:
                continue
            table = KINDS.get((m["obj"], m["prop"]))
            if not table:
                continue
            value = m["val"].replace("\\'", "'")
            if table == "domains":
                value = value.lower().rstrip(".")
            # single characters and bare slashes make useless, noisy indicators
            if len(value.strip("/")) < 3:
                continue
            name = owner.get(o["id"]) or default_name
            if name != "spyware campaign":
                feed_names.add(name)
            getattr(index, table).setdefault(value, Indicator(value, KIND_LABELS[table], name, feed, category))
        index.feeds.append({"feed": feed, "category": category, "families": sorted(feed_names)})
    return index

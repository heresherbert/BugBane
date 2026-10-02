"""Known-answer replay: plant public indicators in hand-made artifacts and see which checks fire.

Every indicator in the loaded feeds is a question with a known answer: "if this value shows up in
<artifact>, does the matching check raise it?" This module builds stand-ins for what a phone leaves
behind (process list, shutdown log, crash reports, Firefox history in a backup, MVT output) from
nothing but those public values, runs the real checks over them, and reports what was and wasn't
caught. No file here comes from a device, and nothing here touches one.

`replay(index)` returns {(kind, value): {check: caught?}}, used by tests/test_replay.py and by
scripts/detection_report.py.
"""
import json
import plistlib
import re
import sqlite3
import tempfile
from pathlib import Path
from unittest import mock

from scan import checks

PS_HEADER = "USER UID PRSNA PID PPID F %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND"
APP_STORE = "Apple iPhone OS Application Signing"
NEUTRAL_DIR = "/opt/replay"  # matches no implant prefix, so only the indicator itself can raise an alert
LOG_TMP_PREFIXES = ("/private/var/tmp/", "/tmp/")  # the only file paths the log search looks for
KINDS = ("app_ids", "processes", "file_paths", "file_names", "domains")

# Which checks are expected to raise each kind of indicator (the coverage promise).
KIND_CHECKS = {
    "app_ids": ("apps",),
    "processes": ("processes", "jetsam", "shutdown", "crashes"),
    "file_paths": ("processes", "shutdown", "crashes", "logs"),
    "file_names": ("processes", "shutdown", "crashes"),
    "domains": ("browsers",),
}


# --- builders: stand-ins for what a phone leaves behind ---------------------------------------

def stix_bundle(malware, patterns):
    """A minimal STIX2 bundle in the shape the public feeds use."""
    objects = [{"type": "malware", "id": "malware--1", "name": malware}]
    for n, pattern in enumerate(patterns):
        objects.append({"type": "indicator", "id": f"indicator--{n}", "pattern": pattern})
        objects.append({"type": "relationship", "source_ref": f"indicator--{n}", "target_ref": "malware--1"})
    return {"type": "bundle", "objects": objects}


def app(bundle_id, **entitlements):
    return {"ApplicationType": "User", "CFBundleDisplayName": bundle_id, "SignerIdentity": APP_STORE,
            "Entitlements": entitlements}


def ps_line(pid, cmd):
    return f"root 0 - {pid} 1 4004 0.0 0.0 0 0 0 0 - ?? Ss Mon08PM 0:00.01 {cmd}"


def write_ps(root, executables):
    Path(root, "ps.txt").write_text("\n".join([PS_HEADER, *(ps_line(n, e) for n, e in enumerate(executables, 1))]))


def write_shutdown(root, clients):
    extra = Path(root, "system_logs.logarchive/Extra")
    extra.mkdir(parents=True, exist_ok=True)
    lines = ["SIGTERM: [1767489112] (shutdown)"] + [f"\t\tremaining client pid: {n} ({c})"
                                                    for n, c in enumerate(clients, 1)] + ["SIGTERM: [1789843019]"]
    (extra / "shutdown.0.log").write_text("\n".join(lines))


def write_ips(path, header, body):
    Path(path).write_text(json.dumps(header) + "\n" + json.dumps(body))


def write_jetsam(directory, process_names):
    write_ips(Path(directory, "JetsamEvent-2026-09-20-040000.ips"), {"bug_type": "298", "name": "JetsamEvent"},
              {"processes": [{"name": n} for n in process_names]})


def write_crash(directory, n, proc_path):
    write_ips(Path(directory, f"crash-{n}.ips"),
              {"bug_type": "309", "name": f"replay{n}", "timestamp": "2026-09-20 04:10:00"},
              {"procPath": proc_path, "exception": {"type": "EXC_BAD_ACCESS"}})


def write_firefox_backup(root, urls, visited_ms=1780617600000):
    """A decrypted backup folder whose Firefox history holds `urls` (visit times in ms, as MVT sees them)."""
    root = Path(root)
    (root / "ab").mkdir(parents=True, exist_ok=True)
    file_id = "ab" + "0" * 38
    places = sqlite3.connect(root / "ab" / file_id)
    places.executescript("create table moz_places (id integer primary key, url text);"
                         "create table moz_historyvisits (id integer primary key, place_id integer, visit_date integer);")
    places.executemany("insert into moz_places values (?, ?)", list(enumerate(urls, 1)))
    places.executemany("insert into moz_historyvisits values (?, ?, ?)",
                       [(n, n, visited_ms) for n in range(1, len(urls) + 1)])
    places.commit()
    places.close()
    manifest = sqlite3.connect(root / "Manifest.db")
    manifest.execute("create table Files (fileID text, domain text, relativePath text, flags integer)")
    manifest.execute("insert into Files values (?, 'AppDomain-org.mozilla.ios.Firefox', 'profile.profile/places.db', 1)",
                     (file_id,))
    manifest.commit()
    manifest.close()
    return root


def write_ne(root, configs):
    """logs/Networking/com.apple.networkextension.plist as an NSKeyedArchiver blob of NEConfiguration objects."""
    objs = ["$null", {"$classname": "NEConfiguration"}]
    for c in configs:
        obj = {"$class": plistlib.UID(1)}
        for k, v in c.items():
            objs.append(v if not isinstance(v, bool) else {"$classname": "NE" + k})
            obj[k] = plistlib.UID(len(objs) - 1)
        objs.append(obj)
    net = Path(root, "logs/Networking")
    net.mkdir(parents=True, exist_ok=True)
    (net / "com.apple.networkextension.plist").write_bytes(
        plistlib.dumps({"$archiver": "NSKeyedArchiver", "$objects": objs, "$top": {}}, fmt=plistlib.FMT_BINARY))


def write_mvt_detected(out, module, entries):
    """entries: [(indicator, value)]. Mirrors the *_detected.json files `mvt-ios check-backup` writes."""
    Path(out).mkdir(parents=True, exist_ok=True)
    detected = [{"matched_indicator": {"value": ind.value, "type": ind.kind, "name": ind.malware,
                                       "stix2_file_name": ind.feed + ".stix2"},
                 "event": {"isodate": "2026-09-20 04:10:00.000000"}} for ind, value in entries]
    Path(out, f"{module}_detected.json").write_text(json.dumps(detected))
    Path(out, f"{module}.json").write_text(json.dumps([{} for _ in range(len(entries) + 2)]))


# --- replay -----------------------------------------------------------------------------------

def _record(outcomes, kind, ind, check, caught):
    outcomes.setdefault((kind, ind.value), {})[check] = bool(caught)


def _plain(value):
    """Values the artifact formats can carry: no whitespace (ps splits on it), no parentheses (shutdown.log)."""
    return not re.search(r"[\s()]", value)


def replay_apps(index, outcomes):
    apps = {v: app(v) for v in index.app_ids}
    found = {i["detail"].split(";")[0]: i for i in checks.check_apps(apps, index)["items"] if i["key"] == "i.apps.ioc"}
    for value, ind in index.app_ids.items():
        hit = found.get(value)
        _record(outcomes, "app_ids", ind, "apps", hit and hit["level"] == "alert" and hit["params"]["malware"] == ind.malware)


def _executables(index, kind):
    """(indicator, executable path an implant would show up as) for a process / path / file-name indicator."""
    if kind == "processes":
        return [(ind, f"{NEUTRAL_DIR}/{v}") for v, ind in index.processes.items() if _plain(v)]
    if kind == "file_names":
        return [(ind, f"{NEUTRAL_DIR}/{v}") for v, ind in index.file_names.items() if _plain(v)]
    # a directory indicator is caught through something running from inside it
    return [(ind, v + "replay-payload" if v.endswith("/") else v) for v, ind in index.file_paths.items()
            if _plain(v) and v.startswith("/") and (not v.endswith("/") or v.count("/") >= 5)]


def replay_executables(index, outcomes):
    """Process, path and file-name indicators through the process list, shutdown log and crash reports."""
    for kind in ("processes", "file_names", "file_paths"):
        pairs = _executables(index, kind)
        if not pairs:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # running processes
            write_ps(root, [exe for _, exe in pairs])
            by_pid = {n: ind for n, (ind, _) in enumerate(pairs, 1)}
            caught = {int(re.match(r"pid (\d+):", i["detail"]).group(1)): i
                      for i in checks.check_processes(root, index)["items"] if i["key"] == "i.proc.ioc"}
            for pid, ind in by_pid.items():
                _record(outcomes, kind, ind, "processes", pid in caught and caught[pid]["params"]["malware"] == ind.malware)
            # restart diary (shutdown.log)
            write_shutdown(root, [exe for _, exe in pairs])
            shut = {i["detail"] for i in checks.check_shutdown_log(root, index)["items"] if i["key"] == "i.shut.ioc"}
            for ind, exe in pairs:
                _record(outcomes, kind, ind, "shutdown", exe in shut)
            # crash reports
            crashes = root / "crashes"
            crashes.mkdir()
            for n, (_, exe) in enumerate(pairs, 1):
                write_crash(crashes, n, exe)
            hit_files = {i["detail"].split(":")[0] for i in checks.check_crashes([crashes], index)["items"]
                         if i["key"] == "i.crash.ioc"}
            for n, (ind, _) in enumerate(pairs, 1):
                _record(outcomes, kind, ind, "crashes", f"crash-{n}.ips" in hit_files)
    # memory-pressure snapshots list processes by name only
    names = [ind for v, ind in index.processes.items() if _plain(v)]
    if names:
        with tempfile.TemporaryDirectory() as tmp:
            write_jetsam(tmp, [ind.value for ind in names])
            caught = {i["params"]["name"] for i in checks.check_jetsam([Path(tmp)], index)["items"]}
            for ind in names:
                _record(outcomes, "processes", ind, "jetsam", ind.value in caught)


def replay_logs(index, outcomes):
    """The log search: every temp-folder path must be in the search, and a log line naming it must alert."""
    tmp_paths = {v: ind for v, ind in index.file_paths.items() if v.startswith(LOG_TMP_PREFIXES) and not v.endswith("/")}
    if not tmp_paths:
        return
    seen = {}

    def fake_log_show(cmd, **kwargs):
        seen["predicate"] = cmd[cmd.index("--predicate") + 1]
        lines = ["Filtering the log data using predicate"] + [f"2026-09-20 04:10:00 kernel: touched {p}" for p in tmp_paths]
        return mock.Mock(stdout="\n".join(lines))

    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "system_logs.logarchive").mkdir()
        with mock.patch.object(checks.subprocess, "run", fake_log_show):
            result = checks.check_unified_logs(tmp, index)
    hit_lines = " ".join(i["detail"] for i in result["items"])
    for value, ind in tmp_paths.items():
        _record(outcomes, "file_paths", ind, "logs", f'"{value}"' in seen.get("predicate", "") and value in hit_lines)


def replay_domains(index, outcomes):
    """Every domain, and a subdomain of it, visited in Firefox; stalkerware sites only warn, mercenary alerts."""
    urls, host_of = [], {}
    for value, ind in index.domains.items():
        for host in (value, f"www.{value}"):
            host_of[host] = ind
            urls.append(f"https://{host}/")
    with tempfile.TemporaryDirectory() as tmp:
        backup = write_firefox_backup(tmp, urls)
        result = checks.check_browser_history(backup, index, set())
    flagged = {}
    for i in result["items"]:
        m = re.match(r"Firefox: (\S+) \(", i["detail"])
        if m:
            flagged[m.group(1)] = i
    for value, ind in index.domains.items():
        # A feed may list a subdomain of its own (sometimes under another family): the most specific
        # entry for a host is the right answer for that host.
        def caught(host):
            want = index.domains.get(host, ind)
            return (host in flagged and flagged[host]["params"]["malware"] == want.malware
                    and flagged[host]["level"] == ("alert" if want.category == "mercenary" else "warn"))
        _record(outcomes, "domains", ind, "browsers", caught(value) and caught(f"www.{value}"))


def replay(index):
    outcomes = {}
    replay_apps(index, outcomes)
    replay_executables(index, outcomes)
    replay_logs(index, outcomes)
    replay_domains(index, outcomes)
    return outcomes


def misses(outcomes):
    """[(kind, value, check)] for everything that should have been caught and wasn't."""
    return sorted((kind, value, check) for (kind, value), per_check in outcomes.items()
                  for check, caught in per_check.items() if not caught)

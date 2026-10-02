"""The individual security checks.

Each check returns a dict the UI renders directly:
    id, status (ok | info | warn | alert | skipped), summary {key, params}, items[]
Titles and descriptions come from the translation files (chk.<id>.title / .what).
Items carry a level, a translation key + params, and an untranslated technical
`detail` for experts. See scan/i18n.py for the parameter formats.

Wording rule (in app/i18n/*.json): explain findings the way you'd explain them to
a teenager. Say what we saw, why it matters, and what to do.
"""
import datetime as dt
import glob
import json
import os
import plistlib
import re
import sqlite3
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

LEVELS = ("ok", "info", "warn", "alert")
APP_STORE_SIGNER = "Apple iPhone OS Application Signing"
STANDARD_PREFIXES = (
    "/System/", "/usr/", "/sbin/", "/bin/", "/kernel/", "/Applications/", "/Developer/",
    "/private/var/containers/Bundle/Application/", "/var/containers/Bundle/Application/",
    "/private/preboot/Cryptexes/", "/System/Cryptexes/",
)
# Where Pegasus and similar implants have historically lived
IMPLANT_PREFIXES = ("/private/var/db/", "/private/var/tmp/", "/var/db/", "/var/tmp/", "/private/var/root/")
BROWSING_MODULES = ("webkit", "safari", "firefox", "chrome", "browser", "history", "favicon")
MESSAGE_MODULES = ("sms", "whatsapp", "imessage", "message")
# Published DarkSword / Coruna log markers (iVerify, GTIG, Lookout, Mar 2026)
LOG_MARKERS = ("[DarkSword", "Running on non-A18", "/private/var/tmp/keychain-2.db",
               "/private/var/tmp/persona.kb", "/private/var/tmp/wifi_passwords.txt", "/private/var/tmp/icloud_dump")
EXPLOIT_CRASH_SIGNS = (
    (re.compile(r"com\.apple\.WebKit"), "EXC_ARM_DA_ALIGN"),
    (re.compile(r"^mediaplaybackd$"), "CPU_RESOURCE"),
)
BURST_PROCESSES = re.compile(r"WebKit|imagent|IMTranscoderAgent|BlastDoor|MessagesBlastDoorService|mediaplaybackd|"
                             r"MobileSMS|IMDPersistenceAgent|mediaserverd|assetsd")
# Remote-support / screen-sharing apps: legitimate, but a staple of tech-support scams
REMOTE_ACCESS_APPS = re.compile(r"^(com\.teamviewer\.|com\.anydesk\.|com\.splashtop\.|com\.rustdesk\.|"
                                r"com\.zoho\.assist|com\.logmein\.|com\.realvnc\.|com\.getscreen\.|"
                                r"com\.bomgar\.|com\.beyondtrust\.|com\.gotoassist\.)")
NET_KINDS = (("VPN", "vpn"), ("AppVPN", "appvpn"), ("AlwaysOnVPN", "alwayson"), ("ContentFilter", "filter"),
             ("DNSProxy", "dnsproxy"), ("DNSSettings", "dns"), ("URLFilter", "url"), ("Relay", "relay"))
HEAVY_NET_KINDS = {"alwayson", "filter", "dnsproxy", "url", "relay"}


def is_standard(path):
    return path == "/kernel" or path.startswith(STANDARD_PREFIXES)


def result(check_id, items=None, summary=None, params=None, status=None):
    items = items or []
    if status is None:
        status = max((i["level"] for i in items), key=LEVELS.index, default="ok")
    return {"id": check_id, "status": status, "summary": {"key": summary, "params": params or {}}, "items": items}


def item(level, key, params=None, detail=""):
    return {"level": level, "key": key, "params": params or {}, "detail": detail}


def skipped(check_id, key):
    return result(check_id, [], key, status="skipped")


# A skip for one of these means the phone had nothing of that kind to check, not that the check couldn't
# run, so it doesn't make a result partial.
NOTHING_TO_CHECK = {"chk.browsers.nohist", "chk.crashes.skip", "chk.jetsam.skip"}
SNAPSHOT_SKIPS = {"chk.nosnapshot", "chk.shutdown.skip", "chk.logs.skip"}
BACKUP_SKIPS = {"chk.mvt.skip", "chk.browsers.skip"}


def partial(results, mode):
    """The checks that couldn't run, and the advice that fits them: (ids, translation key)."""
    by_design = {"mvt", "browsers"} if mode == "quick" else set()
    missed = [r for r in results if r["status"] == "skipped" and r["id"] not in by_design
              and r["summary"]["key"] not in NOTHING_TO_CHECK]
    keys = {r["summary"]["key"] for r in missed}
    fix = ("v.partial.fix.snapshot" if keys & SNAPSHOT_SKIPS else
           "v.partial.fix.backup" if keys & BACKUP_SKIPS else "v.partial.fix.other")
    return [r["id"] for r in missed], fix


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


# Monitoring apps whose makers also sell everyday products: a visit to the maker's websites
# (accounts, analytics, downloads) is then the usual reason for a browsing hit. Only
# well-established facts; brand names are not translated.
VENDORS = {
    "FamiSafe": ("Wondershare", "Filmora, PDFelement, Dr.Fone, UniConverter, media.io"),
    "KasperskySafeKids": ("Kaspersky", "Kaspersky antivirus, Kaspersky VPN, Kaspersky Password Manager"),
    "MicrosoftFamilySafe": ("Microsoft", "Windows, Office, Outlook, Xbox"),
}


def _hit(indicator, source, vendor_installed):
    """Level and message for an indicator hit, given where it was seen."""
    params = {"malware": indicator.malware}
    if indicator.category == "mercenary":
        key = "hit.merc.msg" if any(k in source for k in MESSAGE_MODULES) else "hit.merc"
        return "alert", key, params
    if any(k in source for k in BROWSING_MODULES) and not vendor_installed:
        # e.g. a shared corporate analytics domain of a company that also sells a monitoring app
        vendor = VENDORS.get(indicator.malware)
        if vendor:
            return "warn", "hit.stalk.web.vendor", {**params, "vendor": vendor[0], "products": vendor[1]}
        return "warn", "hit.stalk.web", params
    return "alert", "hit.stalk", params


def merge_vendor_web_hits(results):
    """Report a monitoring-app maker's websites once: later checks note "also seen here" as info."""
    seen = set()
    for r in results:
        changed = False
        for i in r["items"]:
            if i["key"] not in ("hit.stalk.web", "hit.stalk.web.vendor"):
                continue
            malware = i["params"]["malware"]
            if malware in seen:
                i.update(level="info", key="hit.stalk.web.also", params={"malware": malware})
                changed = True
            seen.add(malware)
        if changed and r["status"] in LEVELS:
            r["status"] = max((i["level"] for i in r["items"]), key=LEVELS.index, default="ok")
    return results


def _vendor_installed(iocs, malware, installed_ids):
    return bool({k for k, v in iocs.app_ids.items() if v.malware == malware} & installed_ids)


# --- 1. Apps -----------------------------------------------------------------

def check_apps(apps, iocs):
    if not apps:
        return skipped("apps", "chk.apps.skip")
    user = {bid: a for bid, a in apps.items() if a.get("ApplicationType") == "User"}
    items = []
    for bid, a in sorted(user.items(), key=lambda kv: (kv[1].get("CFBundleDisplayName") or kv[0]).lower()):
        name = a.get("CFBundleDisplayName") or a.get("CFBundleName") or bid
        ent = a.get("Entitlements") or {}
        hit = iocs.app_ids.get(bid)
        if hit:
            items.append(item("alert", "i.apps.ioc", {"name": name, "malware": hit.malware}, f"{bid}; {hit.feed}"))
        signer = a.get("SignerIdentity")
        if signer and signer != APP_STORE_SIGNER:
            items.append(item("warn", "i.apps.sideload", {"name": name}, f"{bid}; signer: {signer}"))
        elif ent.get("beta-reports-active"):
            items.append(item("info", "i.apps.testflight", {"name": name}, bid))
        if REMOTE_ACCESS_APPS.match(bid):
            items.append(item("warn", "i.apps.remote", {"name": name}, bid))
        if ent.get("com.apple.developer.family-controls"):
            items.append(item("warn", "i.apps.screentime", {"name": name}, bid))
        if ent.get("com.apple.developer.networking.networkextension") or ent.get("com.apple.developer.networking.vpn.api"):
            items.append(item("info", "i.apps.vpn", {"name": name}, bid))
    levels = {i["level"] for i in items}
    tail = "chk.apps.tail.alert" if "alert" in levels else "chk.apps.tail.warn" if "warn" in levels else "chk.apps.tail.ok"
    if not user:
        return result("apps", [], "chk.apps.none")
    return result("apps", items, "chk.apps.sum", {"n": len(user), "tail": {"t": tail}})


# --- 2. Profiles / MDM -------------------------------------------------------

def check_profiles(profiles):
    if profiles is None:
        return skipped("profiles", "chk.profiles.skip")
    meta = profiles.get("ProfileMetadata") or {}
    manifest = profiles.get("ProfileManifest") or {}
    items = []
    for pid in profiles.get("OrderedIdentifiers") or list(meta):
        m = meta.get(pid, {})
        org = m.get("PayloadOrganization") or {"t": "i.profile.unknown_org"}
        items.append(item("warn", "i.profile", {"name": m.get("PayloadDisplayName") or pid, "org": org},
                          json.dumps(manifest.get(pid, {}), default=str)[:400]))
    if not items:
        return result("profiles", [], "chk.profiles.none")
    return result("profiles", items, "chk.profiles.sum", {"n": len(items)})


# --- 3. VPN / DNS / filters --------------------------------------------------

def _unarchive_ne(plist_path):
    d = plistlib.load(open(plist_path, "rb"))
    objs = d.get("$objects", [])

    def deref(v):
        return objs[v.data] if isinstance(v, plistlib.UID) else v

    configs = []
    for o in objs:
        if isinstance(o, dict) and "$class" in o and deref(o["$class"]).get("$classname") == "NEConfiguration":
            c = {k: deref(v) for k, v in o.items() if k != "$class"}
            configs.append({k: (None if v == "$null" else v) for k, v in c.items()})
    return configs


def check_network_config(sysdiag_root):
    path = next(iter(glob.glob(f"{sysdiag_root}/logs/Networking/com.apple.networkextension.plist")), None) \
        if sysdiag_root else None
    if not path:
        return skipped("network", "chk.nosnapshot")
    try:
        configs = _unarchive_ne(path)
    except Exception:
        return skipped("network", "chk.network.unreadable")
    items = []
    for c in configs:
        if c.get("Grade") == 2 and not c.get("ProfileInfo"):
            continue  # Apple's own internal configurations
        name = c.get("ApplicationName") or c.get("Name") or "?"
        app = c.get("Application") or "-"
        kinds = [label for key, label in NET_KINDS if c.get(key)]
        from_profile = bool(c.get("ProfileInfo"))
        if HEAVY_NET_KINDS & set(kinds) or from_profile:
            items.append(item("warn", "i.net.heavy", {
                "name": name, "kinds": [{"t": f"net.kind.{k}"} for k in kinds],
                "profile": {"t": "net.from_profile"} if from_profile else ""}, f"app {app}"))
        elif kinds:
            items.append(item("info", "i.net.vpn", {"name": name}, f"app {app}"))
    if not items:
        return result("network", [], "chk.network.none")
    return result("network", items, "chk.network.sum", {"n": len(items)})


# --- 4. Running processes ----------------------------------------------------

def _uuid_paths(sysdiag_root):
    paths = {}
    spindump = Path(sysdiag_root, "spindump-nosymbols.txt")
    if spindump.exists():
        for line in spindump.open(errors="replace"):
            m = re.search(r"<([0-9A-F-]{36})>\s+(/\S.*)$", line)
            if m:
                paths.setdefault(m.group(1), m.group(2).strip())
    return paths


def _task_uuids(sysdiag_root):
    uuids, current = {}, None
    taskinfo = Path(sysdiag_root, "taskinfo.txt")
    if taskinfo.exists():
        for line in taskinfo.open(errors="replace"):
            m = re.match(r'process: "(.+)" \[(\d+)\]', line.strip())
            if m:
                current = m.group(2)
                continue
            m = re.match(r"executable uuid: ([0-9A-F-]{36})", line.strip())
            if m and current:
                uuids[current] = m.group(1)
    return uuids


def check_processes(sysdiag_root, iocs):
    ps = Path(sysdiag_root or "", "ps.txt")
    if not sysdiag_root or not ps.exists():
        return skipped("processes", "chk.nosnapshot")
    rows = []
    for line in ps.read_text(errors="replace").splitlines()[1:]:
        parts = line.split(None, 17)
        if len(parts) >= 18:
            rows.append((parts[3], parts[17]))
    uuid_paths, task_uuids = _uuid_paths(sysdiag_root), _task_uuids(sysdiag_root)
    items, unresolved = [], 0
    for pid, cmd in rows:
        exe = cmd.split(" ")[0]
        if exe.startswith("(") and exe.endswith(")"):
            continue  # zombie / the ps command itself
        if not exe.startswith("/"):
            exe = uuid_paths.get(task_uuids.get(pid, ""), exe)
        hit = iocs.match_process(exe) or iocs.match_path(exe)
        detail = f"pid {pid}: {cmd[:200]}"
        if hit:
            items.append(item("alert", "i.proc.ioc", {"name": os.path.basename(exe), "malware": hit.malware}, detail))
        elif exe.startswith(IMPLANT_PREFIXES):
            items.append(item("alert", "i.proc.implant", {}, detail))
        elif exe.startswith("/") and not is_standard(exe):
            items.append(item("warn", "i.proc.odd", {}, detail))
        elif not exe.startswith("/"):
            unresolved += 1
    if unresolved:
        items.append(item("info", "i.proc.unresolved", {"n": unresolved}))
    return result("processes", items, "chk.processes.sum", {"n": len(rows)})


# --- 5. Memory-pressure snapshots (Jetsam) ------------------------------------

def check_jetsam(crash_dirs, iocs):
    names, files = defaultdict(set), 0
    for d in crash_dirs:
        for f in glob.glob(f"{d}/**/JetsamEvent*.ips", recursive=True):
            try:
                _header, body = Path(f).read_text(errors="replace").split("\n", 1)
                data = json.loads(body)
                files += 1
            except ValueError:
                continue
            for p in data.get("processes", []):
                if p.get("name"):
                    names[p["name"]].add(os.path.basename(f))
    if not files:
        return skipped("jetsam", "chk.jetsam.skip")
    items = [item("alert", "i.jetsam.ioc", {"name": n, "malware": iocs.processes[n].malware}, ", ".join(sorted(fs))[:300])
             for n, fs in names.items() if n in iocs.processes]
    return result("jetsam", items, "chk.jetsam.sum", {"n": len(names), "files": files})


# --- 6. shutdown.log ---------------------------------------------------------

def check_shutdown_log(sysdiag_root, iocs):
    logs = sorted(glob.glob(f"{sysdiag_root}/system_logs.logarchive/Extra/shutdown*.log")) if sysdiag_root else []
    if not logs:
        return skipped("shutdown", "chk.shutdown.skip")
    text = "\n".join(Path(p).read_text(errors="replace") for p in logs)
    stamps = sorted(int(x) for x in re.findall(r"SIGTERM: \[(\d+)\]", text))
    paths = set(re.findall(r"remaining client pid: \d+ \((.*?)\)", text))
    items = []
    for p in sorted(paths):
        exe = re.sub(r"/[0-9A-F-]{36}$", "", p)
        hit = iocs.match_process(exe) or iocs.match_path(exe)
        if hit:
            items.append(item("alert", "i.shut.ioc", {"malware": hit.malware}, p))
        elif exe.startswith(IMPLANT_PREFIXES):
            items.append(item("alert", "i.shut.implant", {}, p))
        elif not is_standard(exe):
            items.append(item("warn", "i.shut.odd", {}, p))
    if not stamps:
        items.append(item("info", "i.shut.empty"))
        return result("shutdown", items, "chk.shutdown.empty")
    return result("shutdown", items, "chk.shutdown.sum",
                  {"n": len(stamps), "first": {"d": stamps[0]}, "last": {"d": stamps[-1]}})


# --- 7. Crash reports ---------------------------------------------------------

def check_crashes(crash_dirs, iocs):
    reports = []
    for d in crash_dirs:
        for f in glob.glob(f"{d}/**/*.ips", recursive=True):
            try:
                header, body = Path(f).read_text(errors="replace").split("\n", 1)
                h = json.loads(header)
            except ValueError:
                continue
            exc = re.search(r'"exception"\s*:\s*\{[^}]*"type"\s*:\s*"([^"]+)"', body[:400000])
            path = re.search(r'"procPath"\s*:\s*"([^"]+)"', body[:400000])
            reports.append({"file": os.path.basename(f), "bug_type": str(h.get("bug_type")),
                            "name": h.get("name") or h.get("app_name") or "", "exc": exc.group(1) if exc else "",
                            "path": path.group(1) if path else "", "ts": h.get("timestamp", "")})
    if not reports:
        return skipped("crashes", "chk.crashes.skip")
    items = []
    for r in reports:
        for pattern, sign in EXPLOIT_CRASH_SIGNS:
            if pattern.search(r["name"]) and sign in (r["exc"] + r["file"]):
                items.append(item("warn", "i.crash.sign", {"name": r["name"]}, f"{r['file']} {r['exc']}"))
        if r["path"]:
            hit = iocs.match_process(r["path"]) or iocs.match_path(r["path"])
            if hit or r["path"].startswith(IMPLANT_PREFIXES):
                items.append(item("alert", "i.crash.ioc", {}, f"{r['file']}: {r['path']}"))
    crashes = [r for r in reports if r["bug_type"] == "309" and BURST_PROCESSES.search(r["name"])]
    for hour, n in Counter(r["ts"][:13] for r in crashes if r["ts"]).items():
        if n >= 3:
            items.append(item("warn", "i.crash.burst", {"n": n, "hour": f"{hour}:00"}))
    app_crashes = sum(1 for r in reports if r["bug_type"] == "309")
    return result("crashes", items, "chk.crashes.sum", {"n": len(reports), "c": app_crashes})


# --- 8. Unified logs ---------------------------------------------------------

def check_unified_logs(sysdiag_root, iocs, timeout=900):
    archive = Path(sysdiag_root or "", "system_logs.logarchive")
    if not sysdiag_root or not archive.exists():
        return skipped("logs", "chk.logs.skip")
    # Only files dropped in temp folders: normal iOS never writes these names there,
    # while other indicator paths (e.g. /private/var/logs/keybagd/) also show up in healthy logs.
    needles = list(LOG_MARKERS) + [p for p in iocs.file_paths
                                   if p.startswith(("/private/var/tmp/", "/tmp/")) and not p.endswith("/")]
    predicate = " OR ".join(f'eventMessage CONTAINS "{n.replace(chr(34), "")}"' for n in needles)
    try:
        out = subprocess.run(["/usr/bin/log", "show", "--archive", str(archive), "--style", "compact",
                              "--predicate", predicate], capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return skipped("logs", "chk.logs.timeout")
    items = [item("alert", "i.log.hit", {}, line[:300]) for line in out.splitlines()[1:]
             if any(n in line for n in needles)]
    if not items:
        return result("logs", [], "chk.logs.ok")
    return result("logs", items, "chk.logs.hits", {"n": len(items)})


# --- 9. MVT backup results ---------------------------------------------------

def check_mvt_results(mvt_out, iocs, installed_ids):
    if not mvt_out or not Path(mvt_out).exists():
        return skipped("mvt", "chk.mvt.skip")
    from .iocs import Indicator
    items = []
    for f in sorted(glob.glob(f"{mvt_out}/*_detected.json")):
        module = os.path.basename(f).replace("_detected.json", "")
        for det in _load_json(f) or []:
            mi = det.get("matched_indicator") or {}
            value = mi.get("value", "")
            ind = iocs.domains.get(value) or iocs.processes.get(value) or iocs.file_paths.get(value) or iocs.app_ids.get(value)
            if ind is None:
                cat = "stalkerware" if "stalkerware" in mi.get("stix2_file_name", "") else "mercenary"
                ind = Indicator(value, mi.get("type", ""), mi.get("name", "unknown"), mi.get("stix2_file_name", ""), cat)
            level, key, params = _hit(ind, module, _vendor_installed(iocs, ind.malware, installed_ids))
            ev = det.get("event") or {}
            when = ev.get("last_seen_isodate") or ev.get("isodate") or det.get("event_time") or ""
            items.append(item(level, key, params,
                              f"{module}: {value} ({ind.malware}) {when[:19] + ' UTC' if when else ''} {ev.get('domain', '')}".strip()))
    counts = {}
    for f in glob.glob(f"{mvt_out}/*.json"):
        name = os.path.basename(f)
        if not name.endswith("_detected.json") and name not in ("alerts.json", "info.json", "command.json"):
            data = _load_json(f)
            if isinstance(data, list):
                counts[name[:-5]] = len(data)
    return result("mvt", items, "chk.mvt.sum", {
        "total": sum(counts.values()), "sms": counts.get("sms", 0),
        "web": counts.get("webkit_resource_load_statistics", 0), "usage": counts.get("datausage", 0)})


# --- 10. Browser history MVT can't read --------------------------------------

def _manifest_file(backup_dec, domain_like, path):
    con = sqlite3.connect(f"file:{backup_dec}/Manifest.db?mode=ro", uri=True)
    row = con.execute("select fileID from Files where domain like ? and relativePath=? and flags=1",
                      (domain_like, path)).fetchone()
    con.close()
    if row:
        p = Path(backup_dec, row[0][:2], row[0])
        return p if p.exists() else None


def check_browser_history(backup_dec, iocs, installed_ids):
    if not backup_dec or not Path(backup_dec, "Manifest.db").exists():
        return skipped("browsers", "chk.browsers.skip")
    sources = [("Firefox", "%Firefox%", "profile.profile/places.db",
                "select p.url, max(v.visit_date) from moz_places p left join moz_historyvisits v "
                "on v.place_id=p.id group by p.id", 1000)]
    items, total = [], 0
    for browser, dom, rel, query, ts_div in sources:
        f = _manifest_file(backup_dec, dom, rel)
        if not f:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp, "h.db")
            copy.write_bytes(f.read_bytes())
            try:
                rows = sqlite3.connect(copy).execute(query).fetchall()
            except sqlite3.Error:
                continue
        total += len(rows)
        seen = set()
        for url, ts in rows:
            host = urlsplit(url or "").hostname
            ind = iocs.match_domain(host)
            if ind and host not in seen:
                seen.add(host)
                when = dt.datetime.fromtimestamp(ts / ts_div).strftime("%Y-%m-%d %H:%M") if ts else ""
                level, key, params = _hit(ind, "history", _vendor_installed(iocs, ind.malware, installed_ids))
                items.append(item(level, key, params, f"{browser}: {host} ({ind.malware}) {when}".strip()))
    if not total:
        return skipped("browsers", "chk.browsers.nohist")
    return result("browsers", items, "chk.browsers.sum", {"n": total})


# --- 11. iOS version ---------------------------------------------------------

def _version(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def check_ios_version(device, latest=None):
    ios = device.get("ios")
    if not ios:
        return skipped("ios", "chk.ios.skip")
    if latest and _version(latest) > _version(ios):
        return result("ios", [item("warn", "i.ios.update", {"latest": latest, "ios": ios})],
                      "chk.ios.update", {"latest": latest})
    return result("ios", [], "chk.ios.latest" if latest else "chk.ios.offline", {"ios": ios})

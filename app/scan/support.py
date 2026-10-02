"""Support log: a plain-text troubleshooting file the user can read and send.

It must never carry data from the iPhone. It lists versions, the steps of the
current check (status, translation keys and numeric parameters only), the
check-level verdicts without their items, and the tails of the app and server
logs after scrubbing identifiers, names, paths and the launch token.
"""
import datetime as dt
import platform
import re
import subprocess
from importlib import metadata
from pathlib import Path

from .paths import tools_folder

HEADER = """BugBane support log
Generated: {now} (local time)

This log is for troubleshooting. It contains no data from your iPhone: no name, no identifiers,
no apps, no messages, no browsing. Please read it before you send it.
"""

_PATTERNS = [
    (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{12,16}\b"), "<id>"),        # UDID (newer iPhones)
    (re.compile(r"\b[0-9A-Fa-f]{24,64}\b"), "<id>"),                     # UDID (older), hashes
    (re.compile(r"([?&]t=)[\w-]+"), r"\1<token>"),                       # launch token in URLs
    (re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)*\.[A-Za-z]{2,}\b"), "<email>"),
    (re.compile(r"/Users/[^/\s'\"]+"), "/Users/<user>"),
]


def scrub(text, secrets=()):
    """Remove anything that could identify the user or the phone."""
    for value, label in secrets:
        if value and len(value) >= 3:
            text = text.replace(value, label)
    text = text.replace(str(Path.home()), "~")
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _numeric(params):
    out = []
    for k, v in (params or {}).items():
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            out.append(f"{k}={v}")
        elif isinstance(v, dict) and isinstance(v.get("gb"), (int, float)):
            out.append(f"{k}={v['gb']} GB")
    return " ".join(out)


def _installed(root, env, dist):
    """The version of dist installed in a tool environment: runtime/<env>/site in the app bundle,
    .tools/<env>/lib/python3.*/site-packages in a checkout."""
    base = tools_folder(root) / env
    sites = [base / "site", *sorted(base.glob("lib/python3*/site-packages"))]
    found = list(metadata.distributions(name=dist, path=[str(p) for p in sites if p.is_dir()]))
    return found[0].version if found else "?"


def _mac_model():
    try:
        return subprocess.run(["/usr/sbin/sysctl", "-n", "hw.model"], capture_output=True, text=True,
                              timeout=5).stdout.strip() or "?"
    except (OSError, subprocess.SubprocessError):
        return "?"


def _tail(path, n):
    try:
        return path.read_text(errors="replace").splitlines()[-n:]
    except OSError:
        return []


def build(*, root, app_version, notice_version, snapshot, log_lines, server_log, indicators_dir,
          free_gb, pending_restores, secrets):
    """snapshot: the ScanSession fields needed here (phase, mode, device, steps, results)."""
    lines = [HEADER.format(now=f"{dt.datetime.now():%Y-%m-%d %H:%M}")]
    stix = list(indicators_dir.glob("*.stix2")) if indicators_dir.exists() else []
    newest = max((p.stat().st_mtime for p in stix), default=0)
    lines += [
        f"App: BugBane {app_version} (privacy notice {notice_version})",
        f"macOS: {platform.mac_ver()[0] or '?'} ({platform.machine()}), Mac model: {_mac_model()}",
        f"Tools: pymobiledevice3 {_installed(root, 'pmd3', 'pymobiledevice3')}, "
        f"MVT {_installed(root, 'mvt', 'mvt')}, Python {platform.python_version()}",
        f"Indicator files: {len(stix)}, newest "
        + (f"{dt.datetime.fromtimestamp(newest):%Y-%m-%d %H:%M}" if newest else "none"),
        f"Free space on this Mac: {free_gb:.1f} GB",
        f"Temporary backup passwords waiting to be restored: {pending_restores}",
        "",
        "Check",
        f"  phase: {snapshot.get('phase')}, mode: {snapshot.get('mode')}",
    ]
    d = snapshot.get("device") or {}
    if d:
        storage = d.get("storage") or {}
        used = f", storage used {storage['used'] / 1e9:.0f} of {storage['capacity'] / 1e9:.0f} GB" \
            if storage.get("capacity") else ""
        enc = {True: "yes", False: "no"}.get(d.get("backup_encrypted"), "?")
        lines.append(f"  iPhone: {d.get('model') or '?'}, iOS {d.get('ios') or '?'} ({d.get('build') or '?'})"
                     f"{used}, backups encrypted: {enc}")
    for s in snapshot.get("steps") or []:
        detail = s.get("detail") or {}
        lines.append(f"  {s['id']:<12} {s['status']:<8} {detail.get('key', '')} {_numeric(detail.get('params'))}"
                     .rstrip())
    r = snapshot.get("results")
    if r:
        lines.append(f"  verdict: {r.get('verdict')}; partial: {', '.join(r.get('partial') or []) or 'none'}")
        lines.append("  checks: " + ", ".join(f"{c['id']}={c['status']}" for c in r.get("checks", [])))
    lines += ["", "App log (latest lines)"] + [f"  {l}" for l in log_lines[-40:]]
    lines += ["", "Server log (latest lines)"] + [f"  {l}" for l in _tail(server_log, 60)]
    return scrub("\n".join(lines) + "\n", secrets)

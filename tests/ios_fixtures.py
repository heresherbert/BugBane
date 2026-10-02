"""Per-iOS-release sysdiagnose fixtures: the forensic artifacts that move between iOS versions.

Apple changes where and how an iPhone records things between releases. A check that reads iOS 27's
layout can silently read *nothing* on the next version, and a clean result would then be clean only
because nothing was looked at. These fixtures pin the layout we expect per release, so a format change
breaks a test here before it reaches a user (docs/VALIDATION.md, "iOS artifact notes").

A PROFILE is one iOS release's quirks. `build_sysdiagnose(root, profile, ...)` lays out a
`sysdiagnose_<date>` tree in that release's shape; the tests plant a known indicator in each artifact
and confirm the real check still catches it.

Provenance of each profile is recorded in its `source`:
  observed  - seen on a real device in this project
  reported  - from published research and Apple's notes, not yet seen on a device
Only differences we can point to are encoded; nothing about a future iOS is invented.
"""
from dataclasses import dataclass, field
from pathlib import Path

import replay as R


@dataclass
class Profile:
    ios: str                      # a representative version for this release line
    shutdown_name: str            # "shutdown.log" (iOS 26.x) vs "Extra/shutdown.0.log" (iOS 27)
    shutdown_appends: bool        # 26.0-26.1 overwrite on reboot (one cycle); 26.2+ append (many)
    pathless_daemons: tuple = ()  # daemons ps.txt lists with no path; resolved via taskinfo UUID -> spindump
    source: str = "reported"
    note: str = ""


# One entry per release line where an artifact we read is known to differ. Keep the comment's citation.
PROFILES = {
    # iOS 26.0/26.1: shutdown.log overwritten each boot -> a single SIGTERM cycle only.
    "26.1": Profile("26.1", "shutdown.log", shutdown_appends=False, source="reported",
                    note="shutdown.log overwritten on reboot"),
    # iOS 26.2+: shutdown.log appended again -> several cycles accumulate.
    "26.5": Profile("26.5", "shutdown.log", shutdown_appends=True,
                    pathless_daemons=("assetsd", "cloudphotod", "rtadvd"), source="observed",
                    note="capture steps exercised on a device on this line"),
    # iOS 27: the restart diary is Extra/shutdown.0.log.
    "27.0": Profile("27.0", "shutdown.0.log", shutdown_appends=True,
                    pathless_daemons=("assetsd", "cloudphotod", "rtadvd"), source="observed",
                    note="quick and full checks run on a device on this line"),
}

CLEAN_DAEMONS = ("/sbin/launchd", "/usr/libexec/locationd", "/usr/sbin/mediaserverd",
                 "/usr/libexec/backboardd", "/System/Library/CoreServices/SpringBoard.app/SpringBoard")
BOOT_STAMPS = (1767489112, 1778000000, 1789843019)


def _write_shutdown(sysdiag, profile, extra_clients=()):
    extra = sysdiag / "system_logs.logarchive/Extra"
    extra.mkdir(parents=True, exist_ok=True)
    cycles = BOOT_STAMPS if profile.shutdown_appends else BOOT_STAMPS[-1:]
    lines = []
    for stamp in cycles:
        lines.append(f"SIGTERM: [{stamp}] (shutdown)")
        clients = [f"{d}/1024C867-0265-374A-AF6A-98390BD24D5D" for d in CLEAN_DAEMONS[:3]] + list(extra_clients)
        lines += [f"\t\tremaining client pid: {n} ({c})" for n, c in enumerate(clients, 1)]
    (extra / profile.shutdown_name).write_text("\n".join(lines))


def _write_ps_with_resolution(sysdiag, profile, hidden_implant=None):
    """ps.txt plus taskinfo/spindump so pathless daemons resolve. hidden_implant (name, full_path)
    is a process ps.txt shows with no path, reachable only through the UUID chain."""
    execs = list(CLEAN_DAEMONS)
    pathless = [(name, f"/usr/libexec/{name}") for name in profile.pathless_daemons]
    if hidden_implant:
        pathless.append(hidden_implant)
    lines = [R.PS_HEADER]
    task_uuids, uuid_paths, pid = [], [], 1
    for exe in execs:
        lines.append(R.ps_line(pid, exe)); pid += 1
    for name, real_path in pathless:
        uuid = f"{pid:08d}-0000-0000-0000-000000000000"
        lines.append(R.ps_line(pid, name))          # no leading slash: needs resolution
        task_uuids.append(f'process: "{name}" [{pid}]\nexecutable uuid: {uuid}')
        uuid_paths.append(f"  <{uuid}>  {real_path}")
        pid += 1
    (sysdiag / "ps.txt").write_text("\n".join(lines))
    (sysdiag / "taskinfo.txt").write_text("\n".join(task_uuids) + "\n")
    (sysdiag / "spindump-nosymbols.txt").write_text("\n".join(uuid_paths) + "\n")


def build_sysdiagnose(root, profile, *, shutdown_implant=None, process_implant=None, ne_configs=()):
    """A sysdiagnose_<date> tree in `profile`'s shape. Implants are (name, path) planted so that only
    reading that iOS's layout catches them. Returns the sysdiagnose_* root (what the checks receive)."""
    root = Path(root)
    sysdiag = root / f"sysdiagnose_2026.09.30_{profile.ios.replace('.', '-')}"
    sysdiag.mkdir(parents=True, exist_ok=True)
    _write_shutdown(sysdiag, profile, extra_clients=[shutdown_implant[1]] if shutdown_implant else [])
    _write_ps_with_resolution(sysdiag, profile, hidden_implant=process_implant)
    # a minimal but present unified-log archive and networking plist, so those checks aren't structurally skipped
    (sysdiag / "system_logs.logarchive").mkdir(exist_ok=True)
    if ne_configs:
        R.write_ne(sysdiag, list(ne_configs))
    (sysdiag / "crashes_and_spins").mkdir(exist_ok=True)
    return sysdiag

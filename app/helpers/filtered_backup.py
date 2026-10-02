#!/usr/bin/env python3
"""Database-only iPhone backup that fits on a small disk.

Before a backup, iOS asks the computer how much space it has and refuses unless it
could store a *complete* backup (it counts every clone and hardlink at full size, so a
phone using 47 GB can demand 150 GB). We keep only databases and settings files
(`--only-regex`), which is a few GB, so we answer with a large figure instead. The
caller must watch the real free space and stop the backup if it runs low (the app
stops at 3 GB free).

Usage: filtered_backup.py <backup_dir>      (device from PYMOBILEDEVICE3_UDID)
"""
import sys

from pymobiledevice3.__main__ import main
from pymobiledevice3.services import device_link

KEEP = r"\.(db|sqlite|sqlite3|sqlitedb|storedata|plist|kvstore)(-wal|-shm)?$"
REPORTED_FREE = 250 * 10 ** 9  # a plausible figure; comfortably above what iOS asks for


async def _report_ample_space(self, _message):
    self._reported_free_space = REPORTED_FREE
    await self.status_response(0, status_dict=REPORTED_FREE)


device_link.DeviceLink.get_free_disk_space = _report_ample_space

if __name__ == "__main__":
    verbose = ["-vvv"] if "--verbose" in sys.argv else []
    targets = [a for a in sys.argv[1:] if a != "--verbose"]
    if not targets:
        sys.exit("usage: filtered_backup.py [--verbose] <backup-folder>")
    target = targets[0]
    sys.argv = ["pymobiledevice3", *verbose, "backup2", "backup", "--full", "--only-regex", KEEP, target]
    sys.exit(main())

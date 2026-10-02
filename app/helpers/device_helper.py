#!/usr/bin/env python3
"""Small JSON-speaking bridge to pymobiledevice3 for the scan app.

Runs inside the pymobiledevice3 virtualenv. Every sub-command prints exactly
one JSON object on stdout, so the app never scrapes human-readable CLI output.

  usb                          UDIDs of USB-connected iPhones (cheap, for polling)
  devices                      USB-connected iPhones with name, model, iOS, pairing state
  status  --udid U             pairing / lock state, model, iOS, backup encryption, storage
  pair    --udid U             show "Trust This Computer?" and wait for the answer
  encryption --udid U on|off   password from BUGBANE_PW (never argv)
  sysdiag-ls --udid U          files in DiagnosticLogs/sysdiagnose with size + mtime
  pull    --udid U --remote P --out DIR   copy a crash-report path to the Mac
  forget  --udid U             remove this Mac from the iPhone's trusted computers and
                               delete the Mac's pairing records for it
"""
import argparse
import asyncio
import json
import os
import posixpath
import sys

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import (
    NotPairedError,
    PairingDialogResponsePendingError,
    PasswordRequiredError,
    UserDeniedPairingError,
)
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.pair_records import get_home_folder
from pymobiledevice3.services.crash_reports import SYSDIAGNOSE_DIR, CrashReportsManager
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service


def emit(obj):
    print(json.dumps(obj, default=str))


async def usb_devices():
    return [d for d in await usbmux.list_devices() if d.connection_type == "USB"]


async def cmd_usb(_args):
    """Just the UDIDs of USB-connected iPhones (no lockdown session: cheap enough to poll)."""
    emit({"udids": [d.serial for d in await usb_devices()]})


async def cmd_devices(_args):
    devices = []
    for d in await usb_devices():
        entry = {"udid": d.serial}
        try:
            lockdown = await create_using_usbmux(serial=d.serial, autopair=False)
            entry.update(name=lockdown.all_values.get("DeviceName"),
                         model=lockdown.all_values.get("ProductType"),
                         ios=lockdown.all_values.get("ProductVersion"),
                         paired=lockdown.paired)
            await lockdown.close()
        except Exception as exc:
            entry["error"] = type(exc).__name__
        devices.append(entry)
    emit({"devices": devices})


async def cmd_status(args):
    lockdown = await create_using_usbmux(serial=args.udid, autopair=False)
    try:
        values = lockdown.all_values
        result = {
            "udid": args.udid,
            "paired": lockdown.paired,
            "name": values.get("DeviceName"),
            "model": values.get("ProductType"),
            "ios": values.get("ProductVersion"),
            "build": values.get("BuildVersion"),
        }
        if lockdown.paired:
            disk = await lockdown.get_value("com.apple.disk_usage")
            capacity = disk.get("TotalDataCapacity", 0)
            result["storage"] = {
                "capacity": capacity,
                # purgeable caches are excluded from backups, so "used" ignores them
                "used": capacity - disk.get("TotalDataAvailable", 0),
            }
            async with Mobilebackup2Service(lockdown) as backup:
                result["backup_encrypted"] = await backup.get_will_encrypt()
        emit(result)
    finally:
        await lockdown.close()


async def cmd_pair(args):
    try:
        lockdown = await create_using_usbmux(serial=args.udid, autopair=True, pair_timeout=args.timeout)
        emit({"paired": lockdown.paired})
        await lockdown.close()
    except PasswordRequiredError:
        emit({"paired": False, "reason": "locked"})
    except UserDeniedPairingError:
        emit({"paired": False, "reason": "denied"})
    except PairingDialogResponsePendingError:
        emit({"paired": False, "reason": "pending"})


async def cmd_encryption(args):
    password = os.environ.get("BUGBANE_PW", "")
    if not password:
        emit({"ok": False, "error": "BUGBANE_PW not set"})
        return
    lockdown = await create_using_usbmux(serial=args.udid, autopair=False)
    try:
        async with Mobilebackup2Service(lockdown) as backup:
            current = await backup.get_will_encrypt()
            wanted = args.mode == "on"
            if current != wanted:
                if wanted:
                    await backup.change_password(args.workdir, new=password)
                else:
                    await backup.change_password(args.workdir, old=password)
            emit({"ok": True, "encrypted": await backup.get_will_encrypt()})
    finally:
        await lockdown.close()


async def cmd_sysdiag_ls(args):
    lockdown = await create_using_usbmux(serial=args.udid, autopair=False)
    try:
        async with CrashReportsManager(lockdown) as crash:
            files = []
            try:
                names = await crash.afc.listdir(SYSDIAGNOSE_DIR)
            except Exception:
                names = []
            for name in names:
                if name in (".", ".."):
                    continue
                try:
                    st = await crash.afc.stat(posixpath.join(SYSDIAGNOSE_DIR, name))
                    files.append({"name": name, "size": int(st.get("st_size", 0)),
                                  "mtime": str(st.get("st_mtime"))})
                except Exception:
                    files.append({"name": name, "size": None, "mtime": None})
            emit({"files": files, "device_time": str(await lockdown.get_date())})
    finally:
        await lockdown.close()


async def cmd_pull(args):
    lockdown = await create_using_usbmux(serial=args.udid, autopair=False)
    try:
        async with CrashReportsManager(lockdown) as crash:
            await crash.pull(args.out, entry=args.remote, match=args.match, progress_bar=False)
        emit({"ok": True})
    finally:
        await lockdown.close()


async def cmd_forget(args):
    done = {}
    try:
        lockdown = await create_using_usbmux(serial=args.udid, autopair=False)
        await lockdown.unpair()
        await lockdown.close()
        done["device"] = True
    except Exception as exc:
        done["device_error"] = type(exc).__name__
    # pymobiledevice3's own cached copy
    for f in get_home_folder().glob(f"{args.udid}*.plist"):
        f.unlink(missing_ok=True)
        done["cache"] = True
    # the system (usbmuxd) copy
    try:
        async with await usbmux.create_mux() as mux:
            if isinstance(mux, usbmux.PlistMuxConnection):
                await mux._send_receive({"MessageType": "DeletePairRecord", "PairRecordID": args.udid})
                done["usbmuxd"] = True
    except Exception as exc:
        done["usbmuxd_error"] = type(exc).__name__
    emit({"ok": bool(done.get("device")), **done})


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("devices")
    sub.add_parser("usb")
    for name in ("status", "pair", "encryption", "sysdiag-ls", "pull", "forget"):
        p = sub.add_parser(name)
        p.add_argument("--udid", required=True)
        if name == "pair":
            p.add_argument("--timeout", type=float, default=5)
        if name == "encryption":
            p.add_argument("mode", choices=("on", "off"))
            p.add_argument("--workdir", default=".")
        if name == "pull":
            p.add_argument("--remote", required=True)
            p.add_argument("--out", required=True)
            p.add_argument("--match")
    args = parser.parse_args()
    handler = {"devices": cmd_devices, "usb": cmd_usb, "status": cmd_status, "pair": cmd_pair,
               "encryption": cmd_encryption, "sysdiag-ls": cmd_sysdiag_ls, "pull": cmd_pull,
               "forget": cmd_forget}[args.cmd]
    try:
        asyncio.run(handler(args))
    except NotPairedError:
        emit({"error": "not_paired"})
    except PasswordRequiredError:
        emit({"error": "locked"})
    except Exception as exc:
        emit({"error": type(exc).__name__, "detail": str(exc)[:300]})
        sys.exit(1)


if __name__ == "__main__":
    main()

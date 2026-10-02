"""Scan orchestration: consent, device detection, pairing, evidence capture, analysis.

One ScanSession lives for the whole app run. The UI polls `snapshot()` and
answers prompts through `act()`.

Privacy model (mirrors what the UI promises):
- Nothing leaves this Mac. The only network calls download public indicator
  lists (MVT) and Apple's public iOS version catalogue (no device data sent).
- Raw phone data lives under evidence/<case>/ only while a check runs and is
  erased right after the analysis, on stop, on quit, and at the next start if
  the app crashed. It survives only if the user explicitly keeps it for an
  expert (a `.keep` marker), and is then erasable from History.
- History stores results (findings), never phone data, and only on request.
- Consent is logged anonymously (time, notice version, language).
"""
import datetime as dt
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tarfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import checks, iocs as ioc_module, recovery, support
from .paths import EVIDENCE, HISTORY, ROOT, RUN, TOOLS

PMD3 = TOOLS / "pmd3/bin/pymobiledevice3"
PMD3_PY = TOOLS / "pmd3/bin/python"
MVT = TOOLS / "mvt/bin/mvt"
MVT_IOS = TOOLS / "mvt/bin/mvt-ios"
MVT_PY = TOOLS / "mvt/bin/python"
HELPER = ROOT / "app/helpers/device_helper.py"
FILTERED_BACKUP = ROOT / "app/helpers/filtered_backup.py"
DECRYPT = ROOT / "app/helpers/partial_decrypt.py"
APP_VERSION = "0.74"
NOTICE_VERSION = "2026-09-23"

GB = 1024 ** 3
MIN_FREE_DURING_BACKUP = 3 * GB
BACKUP_SPACE_NEEDED = 8 * GB  # database-only copy + its decrypted twin, with headroom
BACKUP_ATTEMPTS = 3
SYSDIAG_TIMEOUT = 30 * 60
IOC_MAX_AGE = 24 * 3600
UPDATE_REPO = "heresherbert/BugBane"
UPDATE = {}  # {"latest": "0.69", "url": "https://github.com/..."} once a newer public release is known
_IOC_LOCK = threading.Lock()  # the launch-time refresh and a check's own refresh never download at once
KEEP_MARKER = ".keep"
APPLE_ROOTS = Path(__file__).with_name("apple_roots.pem")

STEPS = ("prepare", "apps", "crashes", "sysdiagnose", "backup", "decrypt", "analyze", "report")
QUICK_SKIP = {"backup", "decrypt"}


def helper(*args, env=None, timeout=60):
    """Run the device helper and return its JSON answer."""
    try:
        proc = subprocess.run([str(PMD3_PY), str(HELPER), *args], capture_output=True, text=True,
                              timeout=timeout, env={**os.environ, **(env or {})})
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    for line in reversed(proc.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return {"error": "no_output", "detail": proc.stderr[-300:]}


def free_space(path=ROOT):
    return shutil.disk_usage(path).free


def fmt_gb(n):
    """A size for the UI, which formats it per language (212.4 GB / 212,4 GB)."""
    return {"gb": round(n / 1e9, 1)}


def sweep_leftovers():
    """Erase raw data left by a crashed or force-quit run (anything not explicitly kept)."""
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for case in EVIDENCE.iterdir():
        if case.is_dir() and not (case / KEEP_MARKER).exists():
            shutil.rmtree(case, ignore_errors=True)


class Cancelled(Exception):
    pass


class ScanSession:
    def __init__(self):
        self.lock = threading.RLock()
        self.answer = threading.Event()
        self._generation = 0
        self.reset()
        threading.Thread(target=self._watch_devices, daemon=True).start()

    # ---- state -------------------------------------------------------------

    def reset(self):
        with getattr(self, "lock", threading.RLock()):
            self.phase = "connect"  # connect | trust | ready | running | done
            self.devices = []
            self.device = None
            self.trust_hint = None
            self.mode = "full"
            self.consent = None
            self.steps = []
            self.prompt = None
            self.results = None
            self.history_id = None
            self.case_dir = None
            self.kept = False
            self.log = []
            self._password = None
            self._temp_password = False
            self._response = None
            self._backup_thread = None
            self._backup_result = None
            self._logs_future = None
            self._missing = 0
            self.raw_deleted = False
            self.usb_udids = []  # UDIDs of plugged-in iPhones from the cheap USB poll (no lockdown session)
            self.restore_state = None  # None | working | done | failed (see restore card in the UI)
            self.restore_error = None

    def snapshot(self):
        with self.lock:
            return {
                "phase": self.phase, "devices": self.devices, "device": self.device,
                "trust_hint": self.trust_hint, "mode": self.mode, "steps": self.steps,
                "prompt": self.prompt, "results": self.results, "history_id": self.history_id,
                "consent": bool(self.consent), "raw_deleted": self.raw_deleted, "kept": self.kept,
                "free_space": fmt_gb(free_space()), "log": self.log[-8:],
                "restore": self._restore_snapshot(), "update": dict(UPDATE) or None,
            }

    def _restore_snapshot(self):
        # A plugged-in iPhone is matched to a pending record by the hash of its USB UDID. This uses only
        # the USB list the watcher already has (no lockdown session, nothing read off the phone), so the
        # "Switch it back now" button can appear before the scan-consent step.
        here = {recovery.device_id(u) for u in self.usb_udids}
        return {"pending": [{**e, "connected": e["id"] in here} for e in recovery.pending()],
                "state": self.restore_state, "error": self.restore_error}

    def _cancelled(self):
        """True when this worker thread belongs to a scan the user abandoned."""
        return getattr(threading.current_thread(), "generation", self._generation) != self._generation

    def _thread(self, target):
        t = threading.Thread(target=target, daemon=True)
        t.generation = self._generation
        t.start()
        return t

    def _log(self, text):
        with self.lock:
            self.log.append(f"{dt.datetime.now():%H:%M:%S} {text}")

    def _step(self, step_id, status=None, detail=None, progress=None):
        """detail: a translation key, or (key, params)."""
        with self.lock:
            for s in self.steps:
                if s["id"] == step_id:
                    if status:
                        s["status"] = status
                    if detail is not None:
                        key, params = detail if isinstance(detail, tuple) else (detail, {})
                        s["detail"] = {"key": key, "params": params}
                    if progress is not None:
                        s["progress"] = progress

    def _ask(self, prompt):
        """Show a prompt in the UI and block until the user answers it."""
        with self.lock:
            self.prompt = prompt
            self._response = None
            self.answer.clear()
        while not self.answer.wait(0.5):
            if self._cancelled():
                raise Cancelled()
        with self.lock:
            self.prompt = None
            return self._response

    # ---- actions from the UI -------------------------------------------------

    def act(self, payload):
        kind = payload.get("type")
        handlers = {
            "consent": self._consent, "start": self._start, "select_device": self._select_device,
            "stop": lambda p: self._abandon(erase=True), "keep_evidence": lambda p: self._keep_evidence(),
            "erase_evidence": lambda p: self._erase_case(), "save_history": lambda p: self._save_history(),
            "finish": self._finish, "restore_encryption": lambda p: self._restore_pending(),
            "restore_dismiss": lambda p: self._restore_dismiss(p),
        }
        if kind in handlers:
            return handlers[kind](payload)
        with self.lock:
            if not self.prompt or self.prompt.get("type") != payload.get("prompt"):
                return {"ok": False, "error": "no matching question is open"}
            self._response = payload
            self.answer.set()
        return {"ok": True}

    def _consent(self, payload):
        if not (payload.get("own") and payload.get("process")):
            return {"ok": False, "error": "consent_required"}
        with self.lock:
            self.consent = {"history": bool(payload.get("history")), "lang": payload.get("lang", "en"),
                            "at": int(time.time())}
        RUN.mkdir(parents=True, exist_ok=True)
        log = RUN / "consent-log.csv"
        new = not log.exists()
        with log.open("a") as f:  # anonymous: no device or personal data
            if new:
                f.write("timestamp,app_version,notice_version,language,history_opt_in\n")
            f.write(f"{dt.datetime.now().isoformat(timespec='seconds')},{APP_VERSION},{NOTICE_VERSION},"
                    f"{self.consent['lang']},{int(self.consent['history'])}\n")
        return {"ok": True}

    def _select_device(self, payload):
        with self.lock:
            self.device = next((d for d in self.devices if d["udid"] == payload.get("udid")), self.device)
        return {"ok": True}

    def _abandon(self, erase):
        """Stop whatever runs, restore the phone's settings, and (optionally) erase raw data."""
        self._restore_encryption()
        with self.lock:
            self._generation += 1
            self.answer.set()
            case, kept, device, consent = self.case_dir, self.kept, self.device, self.consent
        if erase and case and not kept:
            shutil.rmtree(case, ignore_errors=True)
        with self.lock:
            self.reset()
            self.consent = consent  # consent covers the session until the user finishes
            if device:
                self.devices, self.device, self.phase = [device], device, "ready"
        return {"ok": True}

    def shutdown(self):
        self._abandon(erase=True)

    # ---- device detection & pairing ---------------------------------------

    def _watch_devices(self):
        while True:
            try:
                if self.phase in ("connect", "trust", "ready"):
                    self._refresh_devices()
            except Exception as exc:  # keep watching whatever happens
                self._log(f"device watch: {exc}")
            time.sleep(1.5)

    def _refresh_devices(self):
        usb = helper("usb", timeout=15)
        if "udids" not in usb:
            return  # usbmuxd hiccup: keep the current picture rather than flicker
        udids = set(usb["udids"])
        with self.lock:
            if not udids:
                self._missing += 1
                if self._missing >= 2:  # two misses in a row = really unplugged
                    self.devices, self.device, self.trust_hint = [], None, None
                    self.usb_udids = []
                    if self.phase in ("trust", "ready"):
                        self.phase = "connect"
                return
            self._missing = 0
            self.usb_udids = sorted(udids)
            if not self.consent:
                # Before the owner agrees, only notice that an iPhone is plugged in: no lockdown
                # session, so nothing is read from any phone (not even its name).
                return
            known = {d["udid"] for d in self.devices}
            steady = udids == known and self.phase == "ready" and self.device and self.device.get("build")
        if steady:
            return  # nothing changed; don't open lockdown sessions every poll
        found = helper("devices", timeout=30).get("devices")
        if found is None:
            return
        with self.lock:
            self.devices = found
            if not found:
                return
            if not self.device or self.device["udid"] not in {d["udid"] for d in found}:
                self.device = found[0]
            udid = self.device["udid"]
            if self.phase == "ready" and self.device.get("build"):
                return  # already trusted and described
        current = next(d for d in found if d["udid"] == udid)
        if not current.get("paired"):
            with self.lock:
                self.phase = "trust"
                if not self.consent:
                    # Never ask a phone to trust this Mac before its owner agreed to the check
                    # (this also keeps a just-"forgotten" iPhone from being re-paired after Finish).
                    return
            answer = helper("pair", "--udid", udid, "--timeout", "4", timeout=30)
            with self.lock:
                self.trust_hint = answer.get("reason") or answer.get("error")
            if not answer.get("paired"):
                return
        status = helper("status", "--udid", udid, timeout=30)
        with self.lock:
            if status.get("paired"):
                self.device = {**current, **status}
                self.trust_hint = None
                if status.get("backup_encrypted") is False and recovery.has(udid):
                    recovery.forget(udid)  # switched off elsewhere (Finder, Reset All Settings)
                if self.phase in ("connect", "trust"):
                    self.phase = "ready"
            elif status.get("error") == "locked":
                self.trust_hint = "locked"

    # ---- scan --------------------------------------------------------------

    def _start(self, payload):
        with self.lock:
            if not self.consent:
                return {"ok": False, "error": "consent_required"}
            if self.phase != "ready" or not self.device:
                return {"ok": False, "error": "no_device"}
            self.mode = "quick" if payload.get("mode") == "quick" else "full"
            self.phase = "running"
            self.steps = [{"id": i, "status": "skipped" if self.mode == "quick" and i in QUICK_SKIP else "pending",
                           "detail": None, "progress": None} for i in STEPS]
            self.case_dir = EVIDENCE / f"{dt.datetime.now():%Y-%m-%d_%H%M%S}_{secrets.token_hex(3)}"
            self.case_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.case_dir, 0o700)
        self._thread(self._run)
        return {"ok": True}

    def _env(self, **extra):
        return {**os.environ, "PYMOBILEDEVICE3_UDID": self.device["udid"], **extra}

    def _run_cmd(self, cmd, env=None, on_output=None, timeout=None, guard=None):
        """Run a command, streaming stdout+stderr chunks (split on \\r and \\n) to on_output."""
        proc = subprocess.Popen([str(c) for c in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=env or self._env(), bufsize=0)
        started, tail, buf = time.time(), [], b""
        os.set_blocking(proc.stdout.fileno(), False)
        while True:
            chunk = proc.stdout.read(65536) or b""
            buf += chunk
            *lines, buf = re.split(rb"[\r\n]", buf)
            for raw in lines:
                line = raw.decode(errors="replace").strip()
                if line:
                    tail = (tail + [line])[-40:]
                    if on_output:
                        on_output(line)
            if proc.poll() is not None and not chunk:
                break
            if self._cancelled() or (timeout and time.time() - started > timeout) or (guard and guard()):
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(5)
                return -1, tail
            if not chunk:
                time.sleep(0.2)
        return proc.returncode, tail

    def _run(self):
        steps = {
            "prepare": self._prepare, "apps": self._apps, "crashes": self._crashes,
            "sysdiagnose": self._sysdiagnose, "backup": self._backup, "decrypt": self._decrypt,
            "analyze": self._analyze, "report": self._report,
        }
        # keep the Mac from sleeping mid-check (a sleeping Mac drops the backup); ends with the check
        awake = subprocess.Popen(["/usr/bin/caffeinate", "-i", "-s", "-w", str(os.getpid())]) \
            if Path("/usr/bin/caffeinate").exists() else None
        try:
            for step in self.steps:
                sid = step["id"]
                # the backup may already be running (or finished) in the background
                background = sid == "backup" and self._backup_thread is not None
                if step["status"] != "pending" and not background:
                    continue
                if step["status"] == "pending":
                    self._step(sid, "active")
                try:
                    outcome = steps[sid]()
                except Cancelled:
                    raise
                except Exception as exc:
                    self._log(f"{sid} failed: {exc!r}")
                    self._step(sid, "error", ("d.error", {"e": str(exc)[:200]}))
                    continue
                if step["status"] == "active":
                    self._step(sid, {"skip": "skipped", "error": "error"}.get(outcome, "done"))
            with self.lock:
                self.phase = "done"
            if self.consent and self.consent.get("history"):
                self._save_history()
            if not self._has_alerts():
                self._erase_case()
        except Cancelled:
            pass
        finally:
            if awake:
                awake.terminate()
            if not self._cancelled():
                self._restore_encryption()
                self._password = None

    def _device_present(self):
        usb = helper("usb", timeout=15)
        return "udids" not in usb or self.device["udid"] in usb["udids"]  # unsure = assume present

    # Individual steps -------------------------------------------------------

    def _prepare(self):
        d = self.device
        with _IOC_LOCK:
            if indicators_stale():
                self._step("prepare", detail="d.prepare.ioc")
                self._run_cmd([MVT, "--disable-update-check", "download-iocs"], timeout=300)
        self._adopt_saved_password()
        if self.mode == "full":
            free = free_space()
            if free < BACKUP_SPACE_NEEDED:
                answer = self._ask({"type": "low_space",
                                    "params": {"need": fmt_gb(BACKUP_SPACE_NEEDED), "free": fmt_gb(free)}})
                if answer.get("choice") == "quick":
                    self._switch_to_quick()
        self._step("prepare", detail=("d.prepare.device", {"name": d.get("name") or "iPhone", "ios": d.get("ios")}))

    def _adopt_saved_password(self):
        """An earlier check was interrupted after switching encryption on: reuse its password,
        and switch encryption off at the end of this check (quick or full)."""
        d = self.device
        saved = recovery.password_for(d["udid"]) if d.get("backup_encrypted") else None
        if saved:
            self._password, self._temp_password = saved, True
            self._log("using the saved temporary backup password")

    def _switch_to_quick(self):
        with self.lock:
            self.mode = "quick"
            for s in self.steps:
                if s["id"] in QUICK_SKIP and s["status"] == "pending":
                    s["status"] = "skipped"

    def _apps(self):
        for name, cmd in (("apps.json", ["apps", "list"]), ("profiles.json", ["profile", "list"])):
            out = subprocess.run([str(PMD3), *cmd], capture_output=True, text=True, env=self._env(), timeout=180)
            (self.case_dir / name).write_text(out.stdout)
        apps = checks._load_json(self.case_dir / "apps.json") or {}
        users = sum(1 for a in apps.values() if a.get("ApplicationType") == "User")
        self._step("apps", detail=("d.apps.done", {"n": users}))

    def _crashes(self):
        out = self.case_dir / "crashes"
        out.mkdir(exist_ok=True)
        self._run_cmd([PMD3, "crash", "pull", out, "--match", r"^(?!sysdiagnose).*"], timeout=900)
        self._step("crashes", detail=("d.crashes.done", {"n": sum(1 for _ in out.rglob("*.ips"))}))

    def _sysdiag_files(self):
        answer = helper("sysdiag-ls", "--udid", self.device["udid"], timeout=60)
        return {f["name"]: f for f in answer.get("files", [])}

    def _sysdiagnose(self):
        before = set(self._sysdiag_files())
        with self.lock:
            self.prompt = {"type": "press_buttons"}
            self._response = None
            self.answer.clear()
        started, pressed_at, target, sizes = time.time(), None, None, []
        while True:
            if self._cancelled():
                raise Cancelled()
            if self.answer.is_set() and (self._response or {}).get("choice") == "skip":
                with self.lock:
                    self.prompt = None
                return "skip"
            files = self._sysdiag_files()
            in_progress = [n for n in files if n.startswith("IN_PROGRESS_") and n not in before]
            new_archives = [n for n in files if n.endswith(".tar.gz") and not n.startswith("IN_PROGRESS_")
                            and n not in before]
            if (in_progress or new_archives) and not pressed_at:
                pressed_at = time.time()
                with self.lock:
                    self.prompt = None
                self._step("sysdiagnose", detail="d.sys.preparing")
                if self.mode == "full":
                    # start the copy while the iPhone builds the snapshot (saves ~10 minutes)
                    self._backup_thread = self._thread(self._backup_in_background)
            if new_archives and not in_progress:
                target = sorted(new_archives)[-1]
                sizes.append(files[target]["size"])
                if len(sizes) >= 2 and sizes[-1] == sizes[-2]:
                    break
            if pressed_at:
                self._step("sysdiagnose", progress=min(95, int((time.time() - pressed_at) / 600 * 100)))
            if time.time() - started > SYSDIAG_TIMEOUT:
                with self.lock:
                    self.prompt = None
                self._step("sysdiagnose", "error", "d.sys.timeout")
                return "error"
            time.sleep(3)
        self._step("sysdiagnose", detail="d.sys.copying", progress=97)
        dest = self.case_dir / "sysdiagnose"
        dest.mkdir(exist_ok=True)
        helper("pull", "--udid", self.device["udid"], "--remote", f"/DiagnosticLogs/sysdiagnose/{target}",
               "--out", str(dest), timeout=1800)
        archive = next(dest.rglob("*.tar.gz"), None)
        if not archive:
            self._step("sysdiagnose", "error", "d.sys.copyfail")
            return "error"
        self._step("sysdiagnose", detail="d.sys.unpacking")
        with tarfile.open(archive) as tar:
            tar.extractall(dest / "x", filter="data")
        archive.unlink()
        # The unified-log search takes several minutes: start it now, while the backup is copying.
        sysdiag = next(iter(sorted((dest / "x").glob("sysdiagnose_*"))), None)
        if sysdiag:
            self._logs_future = ThreadPoolExecutor(max_workers=1).submit(
                lambda: checks.check_unified_logs(sysdiag, ioc_module.load()))
        self._step("sysdiagnose", "done", "d.sys.done", progress=100)

    def _backup_in_background(self):
        try:
            self._backup_result = self._do_backup()
        except Cancelled:
            self._backup_result = "cancelled"
        except Exception as exc:
            self._log(f"backup failed: {exc!r}")
            self._backup_result = "error"

    def _backup(self):
        if self._backup_thread is None:  # snapshot skipped/failed: run the backup now
            self._backup_result = self._do_backup()
        else:
            self._backup_thread.join()
        if self._backup_result == "cancelled":
            raise Cancelled()
        return self._backup_result

    def _get_password(self):
        if self.device.get("backup_encrypted"):
            answer = self._ask({"type": "backup_password"})
            if answer.get("choice") == "forgot":
                return None
            return answer.get("password") or None
        # Backups aren't encrypted yet: switch encryption on with a throwaway password,
        # because encrypted backups include much more (Safari history, call logs, Wi-Fi, Health).
        # It is switched off again at the end, restoring the phone's original setting.
        udid = self.device["udid"]
        password = secrets.token_urlsafe(18)
        try:
            # saved *before* the phone changes, so a crash can never strand an unknown password
            recovery.remember(udid, self.device.get("model"), password)
        except Exception as exc:
            self._log(f"keychain: {exc}")
            self._skip_reason = "d.backup.nokeychain"
            return None
        self._password, self._temp_password = password, True
        with self.lock:
            self.prompt = {"type": "passcode_on_phone"}
        answer = helper("encryption", "--udid", udid, "on", "--workdir", str(self.case_dir),
                        env={"BUGBANE_PW": password}, timeout=300)
        with self.lock:
            self.prompt = None
        if not answer.get("ok") or not answer.get("encrypted"):
            self._log(f"enable encryption: {answer.get('error')}")
            if helper("status", "--udid", udid, timeout=60).get("backup_encrypted"):
                # switched on after all (e.g. the answer timed out): carry on with our password
                time.sleep(5)
                return password
            recovery.forget(udid)
            self._password, self._temp_password = None, False
            return None
        time.sleep(5)  # the phone drops a backup that starts while its backup service is still closing
        return password

    def _do_backup(self):
        self._skip_reason = "d.backup.nopw"
        password = self._password or self._get_password()
        if not password:
            self._step("backup", "skipped", self._skip_reason)
            self._step("decrypt", "skipped")
            return "skip"
        self._password = password
        dest = self.case_dir / "backup"
        dest.mkdir(exist_ok=True)
        self._step("backup", "active", "d.backup.passcode")

        def on_output(line):
            m = re.search(r"(\d+(?:\.\d+)?)/100", line)
            if m:
                self._step("backup", detail="d.backup.copying", progress=int(float(m.group(1))))
            elif "enter the device passcode" in line:
                self._log("iPhone asked for its passcode")
                with self.lock:
                    self.prompt = {"type": "passcode_on_phone"}
            elif "passcode prompt dismissed" in line:
                self._log("passcode entered on the iPhone")
                with self.lock:
                    if self.prompt and self.prompt.get("type") == "passcode_on_phone":
                        self.prompt = None

        low_space = lambda: free_space() < MIN_FREE_DURING_BACKUP
        for attempt in range(BACKUP_ATTEMPTS):
            # database-only backup: photos and videos never touch this Mac (see filtered_backup.py)
            code, tail = self._run_cmd([PMD3_PY, FILTERED_BACKUP, dest], on_output=on_output,
                                       timeout=4 * 3600, guard=low_space)
            with self.lock:
                if self.prompt and self.prompt.get("type") == "passcode_on_phone":
                    self.prompt = None
            if self._cancelled():
                raise Cancelled()
            if code != 0 and not self._device_present():
                self._log("backup stopped: iPhone disconnected")
                shutil.rmtree(dest, ignore_errors=True)  # an interrupted backup can't be analysed
                self._step("backup", "error", "d.backup.unplugged")
                self._step("decrypt", "skipped")
                return "error"
            dropped = any("terminated abruptly" in line for line in tail)
            if not dropped or next(dest.glob("*/Status.plist"), None) or attempt == BACKUP_ATTEMPTS - 1:
                break
            self._step("backup", detail="d.backup.retry")
            shutil.rmtree(dest, ignore_errors=True)
            dest.mkdir()
            time.sleep(5)
        if low_space():
            shutil.rmtree(dest, ignore_errors=True)
            self._step("backup", "error", "d.backup.lowspace")
            self._step("decrypt", "skipped")
            return "error"
        if code != 0 or not next(dest.glob("*/Status.plist"), None):
            self._log("backup tail: " + " | ".join(tail[-5:]))
            self._step("backup", "error", "d.backup.failed")
            self._step("decrypt", "skipped")
            return "error"
        size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
        self._step("backup", "done", ("d.backup.done", {"size": fmt_gb(size)}), progress=100)
        return "done"

    def _decrypt(self):
        if not self._password or not any((self.case_dir / "backup").glob("*/Manifest.plist")):
            return "skip"
        dest = self.case_dir / "backup-dec"
        for attempt in range(3):
            def on_output(line):
                m = re.search(r"(\d+) files decrypted", line)
                if m:
                    self._step("decrypt", detail=("d.decrypt.progress", {"n": int(m.group(1))}))
            code, tail = self._run_cmd([MVT_PY, DECRYPT, self.case_dir / "backup", dest], on_output=on_output,
                                       env={**os.environ, "MVT_IOS_BACKUP_PASSWORD": self._password}, timeout=3600)
            if code != 2:
                break
            if attempt == 2:
                return "skip"
            answer = self._ask({"type": "backup_password", "retry": True})
            if answer.get("choice") == "forgot" or not answer.get("password"):
                return "skip"
            self._password = answer["password"]
        # the decrypted copy is all we analyse; drop the big encrypted one now
        shutil.rmtree(self.case_dir / "backup", ignore_errors=True)
        m = next((re.search(r"Done: (\d+) files", l) for l in tail if l.startswith("Done:")), None)
        self._step("decrypt", detail=("d.decrypt.done", {"n": int(m.group(1)) if m else 0}))

    def _restore_encryption(self):
        """If we switched backup encryption on, switch it back off.

        The Keychain record is dropped only once the phone confirms encryption is off; otherwise
        the UI offers to finish the job (restore card) the next time this iPhone is connected.
        """
        if not (self._temp_password and self._password and self.device):
            return
        udid = self.device["udid"]
        answer = helper("encryption", "--udid", udid, "off", "--workdir", str(self.case_dir or RUN),
                        env={"BUGBANE_PW": self._password}, timeout=300)
        if answer.get("ok") and answer.get("encrypted") is False:
            self._temp_password = False
            recovery.forget(udid)
            with self.lock:
                if self.device:
                    self.device["backup_encrypted"] = False
        else:
            self._log(f"restore encryption: {answer.get('error') or 'still on'}")

    def _restore_pending(self):
        """Restore card: switch off the encryption an interrupted check left on, for the connected iPhone.

        Clicking the button is the user's explicit request to undo a change BugBane made; it only switches
        a backup setting off and reads nothing from the phone, so it doesn't wait for the scan-consent step.
        """
        with self.lock:
            if self.phase == "running" or self.restore_state == "working":
                return {"ok": False, "error": "busy"}
            pending_ids = {e["id"] for e in recovery.pending()}
            udid = next((u for u in self.usb_udids if recovery.device_id(u) in pending_ids), None)
            if not udid:
                return {"ok": False, "error": "no_device"}
            self.restore_state, self.restore_error = "working", None

        def work():
            password = recovery.password_for(udid)
            # The iPhone may ask for its passcode here (seen on iOS 26/27, not iOS 18); the working card
            # tells the user to watch the phone. A no-response comes back as a timeout, handled below.
            answer = helper("encryption", "--udid", udid, "off", "--workdir", str(RUN),
                            env={"BUGBANE_PW": password or ""}, timeout=300) if password else {"error": "no_password"}
            with self.lock:
                if answer.get("ok") and answer.get("encrypted") is False:
                    recovery.forget(udid)
                    if self.device and self.device.get("udid") == udid:
                        self.device["backup_encrypted"] = False
                    self.restore_state = "done"
                else:
                    err = answer.get("error")
                    self._log(f"restore card: {err}")
                    self.restore_state = "failed"
                    self.restore_error = ("locked" if err == "locked"
                                          else "timeout" if err == "timeout" else "other")

        self._thread(work)
        return {"ok": True}

    def _restore_dismiss(self, payload):
        """The user fixed it another way (or the phone is gone): drop the reminder and its password."""
        entry = payload.get("id")
        if entry in {e["id"] for e in recovery.pending()}:
            recovery.forget(did=entry)
        with self.lock:
            self.restore_state = self.restore_error = None
        return {"ok": True}

    def _analyze(self):
        self._restore_encryption()
        index = ioc_module.load()
        case = self.case_dir
        sysdiag = next(iter(sorted((case / "sysdiagnose/x").glob("sysdiagnose_*"))), None) \
            if (case / "sysdiagnose/x").exists() else None
        backup_dec = case / "backup-dec" if (case / "backup-dec/Manifest.db").exists() else None
        apps = checks._load_json(case / "apps.json") or {}
        profiles = checks._load_json(case / "profiles.json")
        installed = {b for b, a in apps.items() if a.get("ApplicationType") == "User"}
        crash_dirs = [case / "crashes"] + ([sysdiag / "crashes_and_spins"] if sysdiag else [])
        mvt_out = case / "mvt"

        def run_mvt():
            if not backup_dec:
                return None
            self._run_cmd([MVT_IOS, "--disable-update-check", "--disable-indicator-update-check",
                           "check-backup", "-o", mvt_out, backup_dec], timeout=3600)
            return mvt_out

        self._step("analyze", detail="d.analyze.list", progress=5)
        with ThreadPoolExecutor(max_workers=3) as pool:
            mvt_future = pool.submit(run_mvt)
            logs_future = self._logs_future or pool.submit(checks.check_unified_logs, sysdiag, index)
            latest_future = pool.submit(latest_ios, self.device.get("model"))
            results = [
                checks.check_apps(apps, index),
                checks.check_profiles(profiles),
                checks.check_network_config(sysdiag),
                checks.check_processes(sysdiag, index),
                checks.check_jetsam(crash_dirs, index),
                checks.check_shutdown_log(sysdiag, index),
                checks.check_crashes(crash_dirs, index),
            ]
            self._step("analyze", detail="d.analyze.mvt", progress=35)
            results.append(checks.check_mvt_results(mvt_future.result(), index, installed))
            results.append(checks.check_browser_history(backup_dec, index, installed))
            self._step("analyze", detail="d.analyze.logs", progress=70)
            results.append(logs_future.result())
            results.append(checks.check_ios_version(self.device, latest_future.result()))
        checks.merge_vendor_web_hits(results)
        order = {"alert": 0, "warn": 1, "info": 2, "ok": 3, "skipped": 4}
        results.sort(key=lambda r: order.get(r["status"], 5))
        verdict = ("alert" if any(r["status"] == "alert" for r in results) else
                   "warn" if any(r["status"] == "warn" for r in results) else "ok")
        partial, partial_fix = checks.partial(results, self.mode)
        d = self.device
        with self.lock:
            self.results = {
                "verdict": verdict, "checks": results, "mode": self.mode, "finished": int(time.time()),
                "partial": partial, "partial_fix": partial_fix,
                "last_restart": _last_boot(sysdiag),
                # only what's needed to recognise the phone in History; no serial number or UDID
                "device": {"name": d.get("name"), "model": d.get("model"), "ios": d.get("ios")},
                "indicators": {"total": index.size, "feeds": len(index.feeds),
                               "families": sorted({f for feed in index.feeds for f in feed["families"]
                                                   if feed["category"] == "mercenary"})},
            }

    def _report(self):
        # Reports are rendered on demand from the results (never written to disk).
        self._step("report", detail="d.report.done")

    def _has_alerts(self):
        return bool(self.results and self.results["verdict"] == "alert")

    def support_log(self, extra_secrets=()):
        """Plain-text troubleshooting log with nothing from the iPhone in it (see scan/support.py)."""
        with self.lock:
            devices = [d for d in [self.device, *self.devices] if d]
            snap = {"phase": self.phase, "mode": self.mode, "device": dict(self.device or {}),
                    "steps": [dict(s) for s in self.steps], "results": self.results}
            log_lines = list(self.log)
            secrets_ = [(d.get("name"), "<iPhone name>") for d in devices] + \
                       [(d.get("udid"), "<id>") for d in devices] + [(self._password, "<password>")]
        secrets_.append((str(ROOT), "<app folder>"))
        return support.build(root=ROOT, app_version=APP_VERSION, notice_version=NOTICE_VERSION, snapshot=snap,
                             log_lines=log_lines, server_log=RUN / "server.log",
                             indicators_dir=ioc_module.MVT_INDICATORS_DIR, free_gb=free_space() / 1e9,
                             pending_restores=len(recovery.pending()), secrets=[*secrets_, *extra_secrets])

    # ---- after the scan --------------------------------------------------

    def _erase_case(self):
        """Erase the raw phone data of the current check (results stay on screen)."""
        with self.lock:
            case = self.case_dir
            self.kept = False
        if case and case.exists():
            shutil.rmtree(case, ignore_errors=True)
        with self.lock:
            self.raw_deleted = True
            if self.history_id and self.results:
                save_history_entry(self.history_id, {**self.results, "evidence": None})
        return {"ok": True}

    def _keep_evidence(self):
        with self.lock:
            if not self.case_dir or not self.results:
                return {"ok": False}
            (self.case_dir / KEEP_MARKER).write_text("kept for expert review at the user's request\n")
            self.kept = True
        self._save_history()
        return {"ok": True}

    def _save_history(self):
        with self.lock:
            if not self.results:
                return {"ok": False}
            if not self.history_id:
                self.history_id = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"
            evidence = self.case_dir.name if self.kept and self.case_dir else None
            save_history_entry(self.history_id, {**self.results, "evidence": evidence})
        return {"ok": True, "id": self.history_id}

    def _finish(self, payload):
        """End the session: forget the iPhone if asked, erase everything not explicitly kept."""
        forgot = False
        if payload.get("forget") and self.device:
            forgot = bool(helper("forget", "--udid", self.device["udid"], timeout=60).get("ok"))
        with self.lock:
            case, kept, saved = self.case_dir, self.kept, bool(self.history_id)
        if case and not kept:
            shutil.rmtree(case, ignore_errors=True)
        with self.lock:
            self._generation += 1
            self.reset()
        return {"ok": True, "forgot": forgot, "saved": saved, "kept": kept}


# ---- History (results only) ---------------------------------------------------

def indicators_stale():
    files = list(ioc_module.MVT_INDICATORS_DIR.glob("*.stix2"))
    return time.time() - max((p.stat().st_mtime for p in files), default=0) > IOC_MAX_AGE


def refresh_indicators():
    """Download the public indicator lists if they are more than a day old. Runs when the app opens (and again
    before each check), so new spyware fingerprints arrive without an app update. Touches no device."""
    with _IOC_LOCK:
        if indicators_stale():
            subprocess.run([str(MVT), "--disable-update-check", "download-iocs"], capture_output=True, timeout=300)


def check_for_update():
    """Ask GitHub whether a newer public release exists. Sends nothing about the person, the Mac or the phone."""
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{UPDATE_REPO}/releases/latest",
                                     headers={"Accept": "application/vnd.github+json", "User-Agent": "BugBane"})
        with urllib.request.urlopen(req, timeout=8) as r:
            release = json.load(r)
    except Exception:
        return None
    latest, url = str(release.get("tag_name", "")).lstrip("v"), str(release.get("html_url", ""))
    if checks._version(latest) > checks._version(APP_VERSION) and url.startswith(f"https://github.com/{UPDATE_REPO}/"):
        UPDATE.update(latest=latest, url=url)
    return dict(UPDATE) or None


def on_launch():
    """Every time the app opens: look for a newer BugBane, then bring the threat lists up to date."""
    check_for_update()
    try:
        refresh_indicators()
    except Exception:
        pass  # offline or MVT missing: the check refreshes again before it runs


def save_history_entry(entry_id, results):
    HISTORY.mkdir(parents=True, exist_ok=True)
    path = HISTORY / f"{entry_id}.json"
    path.write_text(json.dumps(results, indent=1))
    os.chmod(path, 0o600)


def list_history():
    entries = []
    for f in sorted(HISTORY.glob("*.json"), reverse=True):
        r = _normalise(checks._load_json(f))
        if r:
            entries.append({"id": f.stem, "finished": r.get("finished"), "verdict": r.get("verdict"),
                            "partial": bool(r.get("partial")), "mode": r.get("mode"),
                            "device": r.get("device"), "evidence": bool(r.get("evidence"))})
    return entries


def _normalise(r):
    """Recompute partial for entries saved by older versions (they counted "nothing to check" skips)."""
    if r and r.get("checks"):
        r["partial"], r["partial_fix"] = checks.partial(r["checks"], r.get("mode"))
    return r


def get_history(entry_id):
    if not re.fullmatch(r"[\w-]+", entry_id or ""):
        return None
    return _normalise(checks._load_json(HISTORY / f"{entry_id}.json"))


def delete_history(entry_id=None):
    if entry_id and not re.fullmatch(r"[\w-]+", entry_id):
        return {"ok": False}
    targets = [HISTORY / f"{entry_id}.json"] if entry_id else list(HISTORY.glob("*.json"))
    for f in targets:
        r = checks._load_json(f) or {}
        if r.get("evidence") and re.fullmatch(r"[\w-]+", r["evidence"]):
            shutil.rmtree(EVIDENCE / r["evidence"], ignore_errors=True)
        f.unlink(missing_ok=True)
    return {"ok": True}


def erase_history_evidence(entry_id):
    r = get_history(entry_id)
    if r and r.get("evidence") and re.fullmatch(r"[\w-]+", r["evidence"]):
        shutil.rmtree(EVIDENCE / r["evidence"], ignore_errors=True)
        save_history_entry(entry_id, {**r, "evidence": None})
    return {"ok": True}


# ---- helpers --------------------------------------------------------------------

def latest_ios(model):
    """Newest iOS Apple offers this model, from Apple's public catalogue.

    The whole catalogue is downloaded and filtered here, so the phone's model never leaves this Mac.
    Returns None when offline.
    """
    if not model:
        return None
    try:
        # Apple signs gdmf.apple.com with its own root, which an embedded Python's list lacks
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(APPLE_ROOTS)
        with urllib.request.urlopen("https://gdmf.apple.com/v2/pmv", timeout=8, context=ctx) as r:
            catalogue = json.load(r)
        versions = [a["ProductVersion"] for a in catalogue.get("PublicAssetSets", {}).get("iOS", [])
                    if model in a.get("SupportedDevices", [])]
        return max(versions, key=checks._version) if versions else None
    except Exception:
        return None


def _last_boot(sysdiag):
    """Unix time of the last restart: newest shutdown.log entry."""
    if not sysdiag:
        return None
    stamps = []
    for log in Path(sysdiag, "system_logs.logarchive/Extra").glob("shutdown*.log"):
        stamps += [int(x) for x in re.findall(r"SIGTERM: \[(\d+)\]", log.read_text(errors="replace"))]
    return max(stamps) if stamps else None

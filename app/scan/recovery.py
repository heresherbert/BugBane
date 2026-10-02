"""Crash-safe record of the temporary backup password.

When a full check finds that the iPhone's backups aren't encrypted, it switches
encryption on with a throwaway password and switches it off again at the end.
If the app dies in between, the phone would be left with a backup password
nobody knows. So the password is saved in the macOS Keychain *before* the
phone is changed, and removed only once the phone reports encryption is off.

- Keychain item: service SERVICE, account = hashed UDID. Its label and comment
  explain what it is, so a user can find it in Keychain Access even without
  the app (Finder can switch encryption off with it).
- Index file run/restore-pending.json: which phones are waiting, with a hashed
  id, the model and the date only. It holds no password and no raw UDID.
"""
import datetime as dt
import hashlib
import json
import subprocess
import threading

from .paths import RUN

SERVICE = "Bugbane temporary backup password"
COMMENT = ("Bugbane set this backup password while checking this iPhone and uses it to switch backup "
           "encryption off again. Finder can do the same: untick Encrypt local backup and enter it.")
INDEX = RUN / "restore-pending.json"
_lock = threading.Lock()


def device_id(udid):
    return hashlib.sha256(udid.encode()).hexdigest()[:32]


class MacKeychain:
    """Generic passwords in the login keychain, via /usr/bin/security.

    Secrets go in on stdin (interactive mode), never on the command line.
    """

    def set(self, account, password, label):
        if not _safe(account) or not _safe(password):
            raise ValueError("unexpected characters")
        cmd = (f'add-generic-password -U -s "{SERVICE}" -a {account} -l "{label}" '
               f'-j "{COMMENT}" -w {password}\n')
        proc = subprocess.run(["/usr/bin/security", "-i"], input=cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 or "error" in proc.stderr.lower():
            raise RuntimeError(f"keychain: {proc.stderr.strip()[:200]}")

    def get(self, account):
        proc = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"],
                              capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() if proc.returncode == 0 else None

    def delete(self, account):
        subprocess.run(["/usr/bin/security", "delete-generic-password", "-s", SERVICE, "-a", account],
                       capture_output=True, text=True, timeout=30)


def _safe(value):
    """Token for `security -i`: our passwords are token_urlsafe and ids are hex."""
    return bool(value) and all(c.isalnum() or c in "-_" for c in value)


KEYCHAIN = MacKeychain()


def _read():
    try:
        return json.loads(INDEX.read_text())
    except (OSError, ValueError):
        return {}


def _write(entries):
    INDEX.parent.mkdir(exist_ok=True)
    tmp = INDEX.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=1))
    tmp.replace(INDEX)


def remember(udid, model, password):
    """Save the password before the phone's encryption is switched on. Raises if it can't be saved."""
    did = device_id(udid)
    since = dt.date.today().isoformat()
    KEYCHAIN.set(did, password, f"Bugbane temporary backup password ({model or 'iPhone'}, {since})")
    with _lock:
        entries = _read()
        entries[did] = {"model": model, "since": since}
        _write(entries)


def has(udid):
    """Index-only check (no Keychain access), cheap enough for device polling."""
    with _lock:
        return device_id(udid) in _read()


def password_for(udid):
    did = device_id(udid)
    with _lock:
        if did not in _read():
            return None
    return KEYCHAIN.get(did)


def forget(udid=None, did=None):
    """The phone's encryption is off again (or the user dismissed the reminder): drop the record."""
    did = did or device_id(udid)
    KEYCHAIN.delete(did)
    with _lock:
        entries = _read()
        if entries.pop(did, None) is not None:
            _write(entries)


def pending():
    """[{id, model, since}] for phones still waiting for their setting to be restored."""
    with _lock:
        return [{"id": k, **v} for k, v in sorted(_read().items(), key=lambda kv: kv[1].get("since", ""))]

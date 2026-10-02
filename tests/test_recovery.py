"""A check must never leave an iPhone with a backup password nobody knows."""
import json
import threading

import pytest

from scan import pipeline, recovery

UDID = "00008110-000A1B2C3D4E5F"


class FakeKeychain:
    def __init__(self, fail=False):
        self.items, self.fail = {}, fail

    def set(self, account, password, label):
        if self.fail:
            raise RuntimeError("keychain locked")
        self.items[account] = password

    def get(self, account):
        return self.items.get(account)

    def delete(self, account):
        self.items.pop(account, None)


class FakePhone:
    """Stands in for device_helper: records calls, answers like the real bridge."""

    def __init__(self, keychain, on_ok=True, off_ok=True, status_encrypted=False):
        self.keychain, self.calls = keychain, []
        self.on_ok, self.off_ok, self.status_encrypted = on_ok, off_ok, status_encrypted
        self.saved_before_on = None

    def __call__(self, *args, env=None, timeout=60):
        self.calls.append(args)
        if args[0] == "encryption":  # encryption --udid U on|off --workdir W
            if args[3] == "on":
                self.saved_before_on = env["BUGBANE_PW"] in self.keychain.items.values()
                return {"ok": True, "encrypted": True} if self.on_ok else {"error": "timeout"}
            return {"ok": True, "encrypted": False} if self.off_ok else {"error": "locked"}
        if args[0] == "status":
            return {"paired": True, "backup_encrypted": self.status_encrypted}
        return {}


@pytest.fixture
def keychain(monkeypatch, tmp_path):
    kc = FakeKeychain()
    monkeypatch.setattr(recovery, "KEYCHAIN", kc)
    monkeypatch.setattr(recovery, "INDEX", tmp_path / "restore-pending.json")
    monkeypatch.setattr(pipeline.time, "sleep", lambda s: None)
    return kc


@pytest.fixture
def session(keychain, tmp_path):
    s = pipeline.ScanSession.__new__(pipeline.ScanSession)  # no device-watch thread
    s.lock, s.answer, s._generation = threading.RLock(), threading.Event(), 0
    s.reset()
    s.device = {"udid": UDID, "model": "iPhone14,5", "backup_encrypted": False, "paired": True}
    s.case_dir = tmp_path
    return s


def test_index_holds_no_password_or_udid(keychain):
    recovery.remember(UDID, "iPhone14,5", "secret-pw")
    raw = recovery.INDEX.read_text()
    assert "secret-pw" not in raw and UDID not in raw
    assert [e["model"] for e in recovery.pending()] == ["iPhone14,5"]
    assert recovery.has(UDID) and recovery.password_for(UDID) == "secret-pw"
    recovery.forget(UDID)
    assert not recovery.pending() and not keychain.items


def test_password_is_saved_before_the_phone_changes(session, keychain, monkeypatch):
    phone = FakePhone(keychain)
    monkeypatch.setattr(pipeline, "helper", phone)
    password = session._get_password()
    assert password and phone.saved_before_on is True
    assert recovery.password_for(UDID) == password


def test_no_keychain_means_no_change_to_the_phone(session, monkeypatch):
    monkeypatch.setattr(recovery, "KEYCHAIN", FakeKeychain(fail=True))
    phone = FakePhone(recovery.KEYCHAIN)
    monkeypatch.setattr(pipeline, "helper", phone)
    assert session._get_password() is None
    assert session._skip_reason == "d.backup.nokeychain"
    assert not [c for c in phone.calls if c[0] == "encryption"]


def test_failed_switch_on_leaves_no_record(session, keychain, monkeypatch):
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain, on_ok=False, status_encrypted=False))
    assert session._get_password() is None
    assert not recovery.pending() and not keychain.items


def test_unclear_switch_on_that_took_effect_keeps_going(session, keychain, monkeypatch):
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain, on_ok=False, status_encrypted=True))
    password = session._get_password()
    assert password and session._temp_password and recovery.password_for(UDID) == password


def test_record_stays_until_the_phone_confirms(session, keychain, monkeypatch):
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain, off_ok=False))
    session._get_password()
    session._restore_encryption()
    assert recovery.has(UDID)  # still on: the restore card will offer to finish
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain))
    session.device["backup_encrypted"] = True
    session._adopt_saved_password()  # the next check picks the saved password up...
    session._restore_encryption()    # ...and switches encryption off at its end
    assert not recovery.has(UDID) and not keychain.items


def test_failed_restore_is_retried_at_the_end_of_the_check(session, keychain, monkeypatch):
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain, off_ok=False))
    session._get_password()
    session._restore_encryption()    # start of the analysis: the phone doesn't confirm
    assert session._temp_password
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain))
    session._restore_encryption()    # end of the check tries again
    assert not session._temp_password and not recovery.has(UDID)


def test_restore_card_flow(session, keychain, monkeypatch):
    recovery.remember(UDID, "iPhone14,5", "pw-from-crash")
    session.phase = "ready"
    session.usb_udids = [UDID]
    snap = session._restore_snapshot()
    assert snap["pending"][0]["connected"] is True
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain))
    assert session._restore_pending()["ok"]
    for _ in range(100):
        if session.restore_state != "working":
            break
        threading.Event().wait(0.01)
    assert session.restore_state == "done" and not recovery.pending()


def test_dismiss_drops_the_reminder(session, keychain):
    recovery.remember(UDID, "iPhone14,5", "pw")
    session._restore_dismiss({"id": recovery.pending()[0]["id"]})
    assert not recovery.pending() and not keychain.items


def test_no_phone_is_read_before_consent(session, monkeypatch):
    calls = []
    monkeypatch.setattr(pipeline, "helper", lambda *a, **k: calls.append(a[0]) or {"udids": [UDID]})
    session.device, session.consent = None, None
    session._refresh_devices()
    assert calls == ["usb"]  # presence only: no lockdown session, no name, no pairing


def test_restore_card_shows_and_works_before_consent(session, keychain, monkeypatch):
    """After a crash, the phone is matched by its USB UDID (no lockdown session), so the button
    appears and works even before the scan-consent step."""
    recovery.remember(UDID, "iPhone14,5", "pw-from-crash")
    session.device, session.consent = None, None        # pre-consent: nothing read from the phone yet
    session.usb_udids = [UDID]                            # ...but the cheap USB poll saw it plugged in
    snap = session._restore_snapshot()
    assert snap["pending"][0]["connected"] is True
    monkeypatch.setattr(pipeline, "helper", FakePhone(keychain))
    assert session._restore_pending()["ok"] is True
    for _ in range(200):
        if session.restore_state != "working":
            break
        threading.Event().wait(0.01)
    assert session.restore_state == "done" and not recovery.pending() and not keychain.items


def test_restore_button_absent_when_phone_not_plugged_in(session):
    recovery.remember(UDID, "iPhone14,5", "pw")
    session.usb_udids = []                                # nothing on USB
    assert session._restore_snapshot()["pending"][0]["connected"] is False
    assert session._restore_pending() == {"ok": False, "error": "no_device"}


def test_restore_timeout_is_reported_distinctly(session, keychain, monkeypatch):
    """A phone that never answers (e.g. a passcode prompt left unanswered) is a timeout, not a generic fail."""
    recovery.remember(UDID, "iPhone14,5", "pw")
    session.usb_udids = [UDID]
    monkeypatch.setattr(pipeline, "helper", lambda *a, **k: {"error": "timeout"})
    session._restore_pending()
    for _ in range(200):
        if session.restore_state != "working":
            break
        threading.Event().wait(0.01)
    assert session.restore_state == "failed" and session.restore_error == "timeout"
    assert recovery.has(UDID)  # password kept: the user can try again

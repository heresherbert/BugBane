"""The support log must be useful for troubleshooting and carry nothing from the iPhone."""
from pathlib import Path

from scan import support

UDID = "00008110-000A1B2C3D4E5F"


def test_scrub_removes_identifiers():
    text = (f"device {UDID} old a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 at {Path.home()}/x "
            "/Users/someone/y http://127.0.0.1:17651/?t=abcDEF_123-x mail me@example.com name: Anna's iPhone "
            "/opt/homebrew/Cellar/python@3.12/3.12.4")
    out = support.scrub(text, [("Anna's iPhone", "<iPhone name>")])
    for leaked in (UDID, "a1b2c3d4e5f6", str(Path.home()), "someone", "abcDEF_123", "me@example.com", "Anna"):
        assert leaked not in out, leaked
    assert "t=<token>" in out and "<iPhone name>" in out
    assert "python@3.12" in out  # not an email address


def test_build_keeps_steps_but_not_personal_params(tmp_path):
    (tmp_path / "server.log").write_text(f"BugBane running at http://127.0.0.1:1/?t=SECRETTOKEN\nerror for {UDID}\n")
    snapshot = {
        "phase": "done", "mode": "full",
        "device": {"udid": UDID, "name": "Anna's iPhone", "model": "iPhone14,5", "ios": "27.0", "build": "24A1",
                   "storage": {"capacity": 128e9, "used": 40e9}, "backup_encrypted": True},
        "steps": [{"id": "prepare", "status": "done",
                   "detail": {"key": "d.prepare.device", "params": {"name": "Anna's iPhone", "ios": "27.0"}}},
                  {"id": "backup", "status": "done", "detail": {"key": "d.backup.done", "params": {"size": {"gb": 0.9}}}},
                  {"id": "decrypt", "status": "done", "detail": {"key": "d.decrypt.done", "params": {"n": 5189}}}],
        "results": {"verdict": "warn", "partial": [], "device": {"name": "Anna's iPhone"},
                    "checks": [{"id": "apps", "status": "warn", "items": [{"key": "i.app.remote", "params": {"name": "AnyDesk"}}]}]},
    }
    text = support.build(root=tmp_path, app_version="0.2.0", notice_version="n", snapshot=snapshot,
                         log_lines=[f"12:00:00 backup tail: {UDID} failed"], server_log=tmp_path / "server.log",
                         indicators_dir=tmp_path / "none", free_gb=27.8, pending_restores=0,
                         secrets=[("Anna's iPhone", "<iPhone name>"), (UDID, "<id>"), ("SECRETTOKEN", "<token>")])
    assert "iPhone14,5" in text and "d.backup.done size=0.9 GB" in text and "n=5189" in text
    assert "apps=warn" in text and "verdict: warn" in text
    for leaked in ("Anna", UDID, "SECRETTOKEN", "AnyDesk"):
        assert leaked not in text, leaked

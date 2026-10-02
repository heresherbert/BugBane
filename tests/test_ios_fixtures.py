"""Every check must keep reading each iOS release's layout; a format change must break a test here.

See tests/ios_fixtures.py for the per-release quirks and their provenance.
"""
import json

import pytest

import ios_fixtures as F
import replay as R
from scan import checks, iocs

PROFILES = list(F.PROFILES.values())
ids = [p.ios for p in PROFILES]


@pytest.fixture
def index(tmp_path):
    (tmp_path / "x.stix2").write_text(json.dumps(R.stix_bundle("Pegasus", [
        "[process:name='roleaccountd']", "[file:path='/private/var/tmp/implant']"])))
    return iocs.load(tmp_path)


@pytest.mark.parametrize("profile", PROFILES, ids=ids)
def test_restart_diary_is_read_on_every_release(profile, index, tmp_path):
    """The restart diary ('shutdown.log' on iOS 26, 'shutdown.0.log' on iOS 27) must be found and an
    implant client inside it flagged - whichever name and however many boot cycles this release writes."""
    implant = ("subridged", "/private/var/db/com.apple.xpc.roleaccountd.staging/subridged")
    sysdiag = F.build_sysdiagnose(tmp_path, profile, shutdown_implant=implant)
    r = checks.check_shutdown_log(sysdiag, index)
    assert r["status"] == "alert", f"shutdown check went blind on iOS {profile.ios}"
    assert ("alert", "i.shut.implant") in {(i["level"], i["key"]) for i in r["items"]}
    # the boot count reflects overwrite (one cycle) vs append (several) - so the UI's "last restart" is right
    expected = len(F.BOOT_STAMPS) if profile.shutdown_appends else 1
    assert r["summary"]["params"]["n"] == expected


@pytest.mark.parametrize("profile", PROFILES, ids=ids)
def test_pathless_daemons_resolve_to_catch_a_hidden_process(profile, index, tmp_path):
    """Daemons ps.txt lists without a path (assetsd, cloudphotod...) are resolved via taskinfo UUID ->
    spindump. An implant hiding the same way must still be caught through that chain."""
    if not profile.pathless_daemons:
        pytest.skip(f"iOS {profile.ios}: no pathless daemons recorded")
    # ps.txt shows only "roleaccountd"; the path (outside any implant folder) lives in spindump, so
    # only UUID resolution + name match can catch it
    hidden = ("roleaccountd", "/usr/local/bin/roleaccountd")
    sysdiag = F.build_sysdiagnose(tmp_path, profile, process_implant=hidden)
    r = checks.check_processes(sysdiag, index)
    caught = {(i["key"], i["params"].get("malware")) for i in r["items"]}
    assert ("i.proc.ioc", "Pegasus") in caught, f"UUID resolution broke on iOS {profile.ios}"
    # and the ordinary pathless daemons did NOT become false positives
    assert not any(i["key"] == "i.proc.odd" for i in r["items"])


@pytest.mark.parametrize("profile", PROFILES, ids=ids)
def test_no_check_is_structurally_blind(profile, index, tmp_path):
    """On a complete (clean) capture for each release, no sysdiagnose-based check may skip for a
    "layout not found" reason. Legitimate skips (no backup, quick mode) are elsewhere."""
    sysdiag = F.build_sysdiagnose(tmp_path, profile,
                                  ne_configs=[{"Name": "Corp VPN", "Application": "com.corp", "VPN": True}])
    structural = {"chk.nosnapshot", "chk.shutdown.skip", "chk.network.unreadable"}
    for check, args in (
        (checks.check_processes, (sysdiag, index)),
        (checks.check_shutdown_log, (sysdiag, index)),
        (checks.check_network_config, (sysdiag,)),
    ):
        r = check(*args)
        assert r["summary"]["key"] not in structural, f"{check.__name__} blind on iOS {profile.ios}: {r['summary']['key']}"


def test_profiles_cover_the_documented_differences():
    """Guard the guard: each difference in docs/VALIDATION.md's iOS artifact notes shows up in a profile."""
    names = {p.shutdown_name for p in PROFILES}
    assert names == {"shutdown.log", "shutdown.0.log"}           # both restart-diary layouts
    assert any(not p.shutdown_appends for p in PROFILES)         # the overwrite-on-reboot line
    assert any(p.shutdown_appends for p in PROFILES)             # the append-again line
    assert any(p.pathless_daemons for p in PROFILES)             # UUID-resolution path
    assert all(p.source in ("observed", "reported") for p in PROFILES)


def test_clean_capture_raises_nothing_on_every_release(index, tmp_path):
    """A clean capture must stay clean on all releases (guards against a fixture that always alerts)."""
    for profile in PROFILES:
        sysdiag = F.build_sysdiagnose(tmp_path / profile.ios, profile)
        assert checks.check_shutdown_log(sysdiag, index)["status"] == "ok"
        assert checks.check_processes(sysdiag, index)["status"] in ("ok", "info")

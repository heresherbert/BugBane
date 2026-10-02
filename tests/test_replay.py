"""Known-answer tests: does every check catch what the public indicator lists say it should?

Two layers. The synthetic answer key always runs (CI too). The live sweep replays every indicator
in the feeds downloaded by setup.sh and is skipped when they aren't there. See tests/replay.py.
"""
import json
import os

import pytest

import replay as R
from scan import checks, iocs

LIVE_FEEDS = list(iocs.MVT_INDICATORS_DIR.glob("*.stix2"))
# CI sets this so a failed download can't turn the live sweep into a silent skip
REQUIRE_FEEDS = os.environ.get("BUGBANE_REQUIRE_LIVE_FEEDS") == "1"
needs_feeds = pytest.mark.skipif(not LIVE_FEEDS and not REQUIRE_FEEDS,
                                 reason="indicator feeds not downloaded (run ./setup.sh)")

# Everyday things that must never be flagged: Apple daemons (incl. the one substring matching once
# confused with Pegasus's `updaterd`), and sites people visit every day.
CLEAN_EXECUTABLES = [
    "/sbin/launchd", "/usr/libexec/securityd", "/usr/libexec/locationd", "/usr/sbin/mediaserverd",
    "/usr/libexec/assetsd", "/usr/libexec/cloudphotod", "/usr/libexec/rtadvd", "/usr/libexec/backboardd",
    "/System/Library/PrivateFrameworks/MobileAccessoryUpdater.framework/Support/accessoryupdaterd",
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard", "/usr/libexec/UserEventAgent",
    "/usr/libexec/nsurlsessiond", "/usr/sbin/wifid", "/usr/libexec/trustd", "/usr/libexec/identityservicesd",
]
CLEAN_HOSTS = [
    "www.apple.com", "icloud.com", "www.google.com", "www.youtube.com", "en.wikipedia.org", "www.amazon.com",
    "www.microsoft.com", "www.cloudflare.com", "www.mozilla.org", "github.com", "web.whatsapp.com",
    "www.facebook.com", "www.instagram.com", "www.telex.hu", "www.index.hu", "www.otpbank.hu",
]


@pytest.fixture
def synthetic(tmp_path):
    """A small hand-made feed set with every indicator kind, in both categories."""
    (tmp_path / "x_pegasus.stix2").write_text(json.dumps(R.stix_bundle("Pegasus", [
        "[process:name='bh']", "[process:name='roleaccountd']", "[file:path='/private/var/db/implant.db']",
        "[file:path='/private/var/tmp/persona.kb']", "[file:name='stage2.plist']", "[domain-name:value='evil.example']",
        "[file:path='/private/var/tmp/icloud_dump/']",
        "[app:id='com.merc.agent']"])))
    (tmp_path / "echap_generated_stalkerware.stix2").write_text(json.dumps(R.stix_bundle("SpyCo", [
        "[domain-name:value='tracker.example']", "[app:id='com.spyco.app']"])))
    return iocs.load(tmp_path)


# --- the synthetic answer key -------------------------------------------------------------------

def test_every_planted_indicator_is_caught(synthetic):
    outcomes = R.replay(synthetic)
    assert R.misses(outcomes) == []
    # ...and each kind really went through every check we promise (an empty replay proves nothing)
    exercised = {(kind, check) for (kind, _), per_check in outcomes.items() for check in per_check}
    promised = {(kind, check) for kind, checks_ in R.KIND_CHECKS.items() for check in checks_}
    assert exercised == promised


def test_replay_covers_every_kind_of_indicator():
    """A new indicator table must come with a replay, not be silently ignored."""
    assert set(R.KIND_CHECKS) == set(R.KINDS) == {f for f in iocs.IOCIndex.__dataclass_fields__ if f != "feeds"}


def test_replay_notices_when_a_check_stops_working(synthetic, monkeypatch):
    """The harness itself must be able to fail: break a matcher and the miss must show up."""
    monkeypatch.setattr(iocs.IOCIndex, "match_process", lambda self, path: None)
    missed = {(kind, check) for kind, _, check in R.misses(R.replay(synthetic))}
    assert ("processes", "processes") in missed and ("processes", "jetsam") not in missed  # jetsam looks names up directly


def test_clean_phone_raises_nothing(synthetic, tmp_path):
    R.write_ps(tmp_path, CLEAN_EXECUTABLES)
    assert checks.check_processes(tmp_path, synthetic)["status"] in ("ok", "info")
    R.write_shutdown(tmp_path, [f"{p}/1024C867-0265-374A-AF6A-98390BD24D5D" for p in CLEAN_EXECUTABLES[:6]])
    assert checks.check_shutdown_log(tmp_path, synthetic)["status"] == "ok"
    backup = R.write_firefox_backup(tmp_path / "bk", [f"https://{h}/" for h in CLEAN_HOSTS])
    assert checks.check_browser_history(backup, synthetic, set())["items"] == []
    assert checks.check_apps({"com.apple.mobilesafari": {"ApplicationType": "System"}, "org.mozilla.ios.Firefox": R.app("Firefox")},
                             synthetic)["items"] == []


def test_lookalikes_are_not_flagged(synthetic):
    # substring and prefix tricks: exact process names and domain label boundaries only
    assert synthetic.match_process("/usr/libexec/roleaccountd2") is None
    assert synthetic.match_process("/usr/libexec/xbh") is None
    for host in ("notevil.example", "evil.example.invalid", "evil-example.com", "xtracker.example"):
        assert synthetic.match_domain(host) is None, host
    assert synthetic.match_domain("cdn.eu.evil.example").malware == "Pegasus"


def test_mvt_findings_are_graded_by_kind_and_place(synthetic, tmp_path):
    merc, stalk = synthetic.domains["evil.example"], synthetic.domains["tracker.example"]
    R.write_mvt_detected(tmp_path, "webkit_resource_load_statistics", [(merc, merc.value), (stalk, stalk.value)])
    R.write_mvt_detected(tmp_path, "sms", [(merc, merc.value), (stalk, stalk.value)])
    items = {(i["level"], i["key"], i["params"]["malware"], i["detail"].split(":")[0])
             for i in checks.check_mvt_results(tmp_path, synthetic, set())["items"]}
    assert ("alert", "hit.merc", "Pegasus", "webkit_resource_load_statistics") in items   # mercenary spyware: always an alert
    assert ("alert", "hit.merc.msg", "Pegasus", "sms") in items                           # ...and a message link says so
    assert ("warn", "hit.stalk.web", "SpyCo", "webkit_resource_load_statistics") in items  # stalkerware site alone: look, don't panic
    assert ("alert", "hit.stalk", "SpyCo", "sms") in items                                # stalkerware link in messages: alert
    # the vendor's app actually being installed turns the website hit into a real alert
    installed = {i["level"] for i in checks.check_mvt_results(tmp_path, synthetic, {"com.spyco.app"})["items"]
                 if i["detail"].startswith("webkit") and i["params"]["malware"] == "SpyCo"}
    assert installed == {"alert"}


def test_a_planted_app_turns_the_apps_check_red(synthetic):
    r = checks.check_apps({"com.merc.agent": R.app("Innocent Notes"), "com.example.ok": R.app("Fine")}, synthetic)
    assert r["status"] == "alert"
    assert [(i["key"], i["params"]["malware"]) for i in r["items"]] == [("i.apps.ioc", "Pegasus")]


# --- the live sweep: every indicator in the downloaded feeds --------------------------------------

@pytest.fixture(scope="module")
def live_index():
    return iocs.load()


@pytest.fixture(scope="module")
def live_outcomes(live_index):
    return R.replay(live_index)


@pytest.mark.skipif(not REQUIRE_FEEDS, reason="only when BUGBANE_REQUIRE_LIVE_FEEDS=1 (CI)")
def test_live_feeds_are_there_when_required():
    assert LIVE_FEEDS, f"no indicator lists in {iocs.MVT_INDICATORS_DIR}; did `mvt download-iocs` run?"


@needs_feeds
def test_every_indicator_in_the_live_feeds_is_caught(live_outcomes):
    missed = R.misses(live_outcomes)
    assert missed == [], f"{len(missed)} misses, first: {missed[:5]}"


@needs_feeds
def test_live_replay_really_covered_the_feeds(live_index, live_outcomes):
    """Guard against a sweep that quietly skips most indicators (whitespace, odd formats...)."""
    per_kind = {kind: {v for (k, v) in live_outcomes if k == kind} for kind in R.KINDS}
    assert live_index.size > 1000
    for kind in ("app_ids", "processes", "domains"):
        table = getattr(live_index, kind)
        assert len(per_kind[kind]) >= 0.98 * len(table), (kind, len(per_kind[kind]), len(table))
    exercised = {(kind, check) for (kind, _), per_check in live_outcomes.items() for check in per_check}
    assert exercised == {(kind, check) for kind, cs in R.KIND_CHECKS.items() for check in cs}


@needs_feeds
def test_live_feeds_never_flag_everyday_things(live_index, tmp_path):
    R.write_ps(tmp_path, CLEAN_EXECUTABLES)
    r = checks.check_processes(tmp_path, live_index)
    assert [i for i in r["items"] if i["level"] in ("warn", "alert")] == []
    hosts = [h for h in CLEAN_HOSTS if live_index.match_domain(h)]
    assert hosts == [], f"popular sites are on an indicator list: {[(h, live_index.match_domain(h).malware) for h in hosts]}"


@needs_feeds
def test_live_lookalike_domains_stay_quiet(live_index):
    """`not<domain>` must not match <domain> (label boundary), and a domain with a suffix bolted on
    must not match either; a real subdomain must (the replay above covers `www.<domain>`)."""
    glued = [d for d in live_index.domains if (m := live_index.match_domain(f"not{d}")) and m.value == d]
    assert glued == [], f"substring-style matches: {glued[:5]}"
    suffixed = [d for d in live_index.domains if (m := live_index.match_domain(f"{d}.invalid")) and m.value == d]
    assert suffixed == [], f"prefix-style matches: {suffixed[:5]}"


def test_processes_inside_an_indicator_directory_are_attributed(tmp_path):
    (tmp_path / "x_kingspawn.stix2").write_text(json.dumps(R.stix_bundle("QuaDream KingSpawn", [
        "[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/PlugIns/fud.appex/']"])))
    index = iocs.load(tmp_path)
    R.write_ps(tmp_path, ["/private/var/db/com.apple.xpc.roleaccountd.staging/PlugIns/fud.appex/fud"])
    items = checks.check_processes(tmp_path, index)["items"]
    assert [(i["key"], i["params"].get("malware")) for i in items] == [("i.proc.ioc", "QuaDream KingSpawn")]


def test_directory_indicators_match_on_path_boundaries(synthetic):
    assert synthetic.match_path("/private/var/tmp/icloud_dump/keys.txt").malware == "Pegasus"
    assert synthetic.match_path("/private/var/tmp/icloud_dump/sub/dir/x").malware == "Pegasus"
    assert synthetic.match_path("/private/var/tmp/icloud_dump").malware == "Pegasus"   # the folder itself
    assert synthetic.match_path("/private/var/tmp/icloud_dump2/x") is None             # not a substring match
    assert synthetic.match_path("/private/var/tmp/icloud_dum") is None


def test_broad_directory_indicators_stay_exact(tmp_path):
    """A shallow folder like /private/var/tmp/ must not turn everything iOS keeps there into an alert."""
    (tmp_path / "x.stix2").write_text(json.dumps(R.stix_bundle("Broad", ["[file:path='/private/var/tmp/']"])))
    index = iocs.load(tmp_path)
    assert index.match_path("/private/var/tmp/com.apple.something.plist") is None
    assert index.match_path("/private/var/tmp/").malware == "Broad"


def test_the_deepest_directory_names_the_family(tmp_path):
    (tmp_path / "a.stix2").write_text(json.dumps(R.stix_bundle("Outer", ["[file:path='/private/var/db/stage/outer/']"])))
    (tmp_path / "b.stix2").write_text(json.dumps(R.stix_bundle("Inner", ["[file:path='/private/var/db/stage/outer/inner/']"])))
    index = iocs.load(tmp_path)
    assert index.match_path("/private/var/db/stage/outer/inner/x").malware == "Inner"
    assert index.match_path("/private/var/db/stage/outer/x").malware == "Outer"

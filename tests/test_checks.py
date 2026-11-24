"""Check logic on hand-made fixtures (no real phone data)."""
import json
import plistlib
import subprocess
from plistlib import UID

import pytest
from replay import write_ne
from scan import checks
from scan.iocs import IOCIndex, Indicator

APP_STORE = "Apple iPhone OS Application Signing"


def index():
    idx = IOCIndex()
    idx.processes["bh"] = Indicator("bh", "process", "Pegasus", "feed", "mercenary")
    idx.app_ids["com.spyco.app"] = Indicator("com.spyco.app", "app", "SpyCo", "feed", "stalkerware")
    return idx


def app(name, signer=APP_STORE, **ent):
    return {"ApplicationType": "User", "CFBundleDisplayName": name, "SignerIdentity": signer, "Entitlements": ent}


def keys(result):
    return {(i["level"], i["key"]) for i in result["items"]}


def test_apps():
    apps = {
        "com.example.clean": app("Clean"),
        "com.example.side": app("Side", signer="iPhone Distribution: Someone"),
        "com.example.beta": app("Beta", **{"beta-reports-active": True}),
        "com.teamviewer.teamviewerQS": app("QuickSupport"),
        "com.example.parent": app("Parent", **{"com.apple.developer.family-controls": True}),
        "com.spyco.app": app("SpyCo"),
        "com.apple.system": {"ApplicationType": "System"},
    }
    r = checks.check_apps(apps, index())
    assert r["status"] == "alert"
    assert r["summary"]["params"]["n"] == 6
    assert {("alert", "i.apps.ioc"), ("warn", "i.apps.sideload"), ("info", "i.apps.testflight"),
            ("warn", "i.apps.remote"), ("warn", "i.apps.screentime")} <= keys(r)
    assert checks.check_apps({}, index())["status"] == "skipped"
    only_apple = checks.check_apps({"com.apple.system": {"ApplicationType": "System"}}, index())
    assert only_apple["status"] == "ok" and only_apple["summary"]["key"] == "chk.apps.none"


def test_partial_counts_only_checks_that_couldnt_run():
    def r(cid, key, status="skipped"):
        return {"id": cid, "status": status, "summary": {"key": key, "params": {}}, "items": []}
    # 2026-10-01 on a real iPhone XS: no Firefox/Chrome history is nothing to check, not a missed check
    assert checks.partial([r("browsers", "chk.browsers.nohist"), r("crashes", "chk.crashes.skip"),
                           r("apps", "chk.apps.sum", "ok")], "full") == ([], "v.partial.fix.other")
    assert checks.partial([r("processes", "chk.nosnapshot"), r("mvt", "chk.mvt.skip")], "full") == \
        (["processes", "mvt"], "v.partial.fix.snapshot")
    assert checks.partial([r("mvt", "chk.mvt.skip")], "full") == (["mvt"], "v.partial.fix.backup")
    assert checks.partial([r("mvt", "chk.mvt.skip"), r("browsers", "chk.browsers.skip")], "quick") == \
        ([], "v.partial.fix.other")
    assert checks.partial([r("ios", "chk.ios.skip")], "full") == (["ios"], "v.partial.fix.other")


def test_apple_roots_cover_the_ios_catalogue():
    """gdmf.apple.com chains to Apple Root CA, which isn't in certifi's list; the app ships Apple's roots."""
    import hashlib, re, ssl
    from scan import pipeline
    pem = pipeline.APPLE_ROOTS.read_text()
    ders = [ssl.PEM_cert_to_DER_cert(c) for c in
            re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)]
    assert "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024" in \
        {hashlib.sha256(d).hexdigest() for d in ders}  # Apple Root CA
    ssl.create_default_context().load_verify_locations(pipeline.APPLE_ROOTS)


def test_profiles():
    assert checks.check_profiles({"OrderedIdentifiers": []})["status"] == "ok"
    r = checks.check_profiles({"OrderedIdentifiers": ["p1"], "ProfileMetadata": {"p1": {"PayloadDisplayName": "X"}}})
    assert r["status"] == "warn" and r["items"][0]["params"]["name"] == "X"


def test_network(tmp_path):
    write_ne(tmp_path, [{"Name": "Home VPN", "Application": "com.vpn", "VPN": True},
                        {"Name": "Filter", "Application": "com.filter", "ContentFilter": True}])
    r = checks.check_network_config(tmp_path)
    assert keys(r) == {("info", "i.net.vpn"), ("warn", "i.net.heavy")}
    assert checks.check_network_config(None)["status"] == "skipped"


PS_HEADER = "USER UID PRSNA PID PPID F %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND"


def ps_line(pid, cmd):
    return f"root 0 - {pid} 1 4004 0.0 0.0 0 0 0 0 - ?? Ss Mon08PM 0:00.01 {cmd}"


def test_processes(tmp_path):
    (tmp_path / "ps.txt").write_text("\n".join([
        PS_HEADER, ps_line(1, "/sbin/launchd"), ps_line(2, "/usr/libexec/securityd"),
        ps_line(3, "/private/var/containers/Bundle/Application/X/App.app/App"),
        ps_line(4, "/private/var/db/com.apple.xpc.roleaccountd.staging/bh"),
        ps_line(5, "/private/var/tmp/helper"), ps_line(6, "/opt/odd/tool")]))
    r = checks.check_processes(tmp_path, index())
    assert r["summary"]["params"]["n"] == 6
    assert ("alert", "i.proc.ioc") in keys(r)
    assert ("alert", "i.proc.implant") in keys(r)
    assert ("warn", "i.proc.odd") in keys(r)


def write_shutdown(root, clients):
    extra = root / "system_logs.logarchive/Extra"
    extra.mkdir(parents=True)
    lines = ["SIGTERM: [1767489112] (shutdown)"] + [
        f"\t\tremaining client pid: {n} ({c})" for n, c in enumerate(clients)] + ["SIGTERM: [1789843019]"]
    (extra / "shutdown.0.log").write_text("\n".join(lines))


def test_shutdown_log_clean(tmp_path):
    write_shutdown(tmp_path, ["/usr/libexec/locationd/1024C867-0265-374A-AF6A-98390BD24D5D",
                              "/kernel/E178C635-97A0-38AC-B350-9A2AB735BA2A"])
    r = checks.check_shutdown_log(tmp_path, index())
    assert r["status"] == "ok" and r["summary"]["params"]["n"] == 2


def test_shutdown_log_implant(tmp_path):
    write_shutdown(tmp_path, ["/private/var/db/com.apple.xpc.roleaccountd.staging/subridged"])
    assert checks.check_shutdown_log(tmp_path, index())["status"] == "alert"


def ips(path, header, body):
    path.write_text(json.dumps(header) + "\n" + json.dumps(body))


def test_crashes(tmp_path):
    ips(tmp_path / "a.ips", {"bug_type": "309", "name": "com.apple.WebKit.WebContent", "timestamp": "2026-09-20 04:10:00"},
        {"exception": {"type": "EXC_ARM_DA_ALIGN"}})
    for n in range(3):
        ips(tmp_path / f"im{n}.ips", {"bug_type": "309", "name": "imagent", "timestamp": f"2026-09-20 05:1{n}:00"}, {})
    ips(tmp_path / "ok.ips", {"bug_type": "298", "name": "", "timestamp": "2026-09-20 06:00:00"}, {"processes": []})
    r = checks.check_crashes([tmp_path], index())
    assert ("warn", "i.crash.sign") in keys(r) and ("warn", "i.crash.burst") in keys(r)
    assert r["summary"]["params"] == {"n": 5, "c": 4}


def test_ios_version():
    assert checks.check_ios_version({"ios": "26.5"}, "27.0")["status"] == "warn"
    assert checks.check_ios_version({"ios": "27.0"}, "27.0")["summary"]["key"] == "chk.ios.latest"
    assert checks.check_ios_version({"ios": "27.0"}, None)["summary"]["key"] == "chk.ios.offline"
    assert checks.check_ios_version({"ios": "26.10"}, "26.9")["status"] == "ok"  # numeric, not string, compare


def test_vendor_web_hits_are_explained_and_reported_once():
    famisafe = Indicator("300624.com", "domain", "FamiSafe", "stalkerware.stix2", "stalkerware")
    unknown = Indicator("spyco.example", "domain", "SpyCo", "stalkerware.stix2", "stalkerware")
    level, key, params = checks._hit(famisafe, "webkit_resource_load_statistics", vendor_installed=False)
    assert (level, key) == ("warn", "hit.stalk.web.vendor") and params["vendor"] == "Wondershare"
    assert checks._hit(unknown, "history", False)[1] == "hit.stalk.web"
    assert checks._hit(famisafe, "history", vendor_installed=True)[0] == "alert"  # app present: real sign

    mvt = checks.result("mvt", [checks.item("warn", key, params)], "chk.mvt.sum")
    browsers = checks.result("browsers", [checks.item("warn", "hit.stalk.web.vendor", params)], "chk.browsers.sum")
    checks.merge_vendor_web_hits([mvt, browsers])
    assert mvt["status"] == "warn" and browsers["status"] == "info"
    assert browsers["items"][0]["key"] == "hit.stalk.web.also"


def test_visit_time_handles_milliseconds_and_microseconds():
    ms = 1780617600000  # Firefox for iOS stores milliseconds
    assert checks._visit_time(ms) == checks._visit_time(ms * 1000) != ""
    assert checks._visit_time(None) == checks._visit_time(0) == checks._visit_time(10**30) == ""


def test_browser_history_survives_an_unreadable_manifest(tmp_path):
    (tmp_path / "Manifest.db").write_bytes(b"not a database")
    assert checks.check_browser_history(tmp_path, IOCIndex(), set())["status"] == "skipped"


def test_browser_web_hits_say_where_when_and_how_to_clear():
    from scan import i18n
    famisafe = Indicator("300624.com", "domain", "FamiSafe", "stalkerware.stix2", "stalkerware")
    june5 = checks._iso_epoch("2026-06-05 10:01:15.000000")
    where = checks.web_where("webkit_resource_load_statistics", june5, "AppDomain-org.mozilla.ios.Firefox")
    level, key, params = checks._hit(famisafe, "webkit_resource_load_statistics", False, where)
    assert (level, key) == ("warn", "hit.stalk.web.vendor.dated")
    en, hu = i18n.t(key, "en", params), i18n.t(key, "hu", params)
    assert "Firefox's stored website data, 5 Jun 2026" in en and "Closing tabs doesn't remove it" in en
    assert "Data Management" in en and "a Firefox tárolt webhelyadataiban (2026. jún. 5.)" in hu
    assert "{" not in en + hu and "<br>Where: Firefox" in en  # all placeholders filled; place on its own line
    history = checks.web_where("firefox_history", checks._visit_epoch(1780617600000))
    assert history["t"] == "hit.web.where.history" and history["p"]["clear"]["t"] == "hit.web.clear.firefox"
    assert checks.web_where("safari_history", june5)["p"]["browser"] == "Safari"
    # not a browser, or no time: the plain wording, as in results saved by older versions
    assert checks.web_where("sms", june5) is None and checks.web_where("firefox_history", None) is None
    assert checks._hit(famisafe, "webkit_resource_load_statistics", False, None)[1] == "hit.stalk.web.vendor"
    # reported once; the repeat keeps its own place and time
    mvt = checks.result("mvt", [checks.item(level, key, params)], "chk.mvt.sum")
    browsers = checks.result("browsers", [checks.item(*checks._hit(famisafe, "history", False, history))],
                             "chk.browsers.sum")
    checks.merge_vendor_web_hits([mvt, browsers])
    again = browsers["items"][0]
    assert again["key"] == "hit.stalk.web.also.dated" and "browsing history" in i18n.t(again["key"], "en", again["params"])
    assert checks._visit_epoch(10**30) is None and checks._iso_epoch("9999-01-01 00:00:00") is None


def test_hungarian_dates_get_no_double_full_stop():
    from scan import i18n
    where = checks.web_where("firefox_history", checks._visit_epoch(1780617600000))
    hu = i18n.t(where["t"], "hu", where["p"])
    assert ".." not in hu and "(2026. jún. 5.)" in hu


UPDATE_BRAIN = ("/private/var/MobileSoftwareUpdate/MobileAsset/AssetsV2/"
                "com_apple_MobileAsset_MobileSoftwareUpdate_UpdateBrain/0123abcd.asset/AssetData/")


def test_update_brain_is_not_odd_but_the_rest_of_the_update_folder_is(tmp_path):
    (tmp_path / "ps.txt").write_text("\n".join([
        PS_HEADER, ps_line(1, UPDATE_BRAIN + "com.apple.MobileSoftwareUpdate.UpdateBrainService"),
        ps_line(2, "/private/var/MobileSoftwareUpdate/Staging/helper"),
        ps_line(3, UPDATE_BRAIN + "../../../../../tmp/helper")]))
    r = checks.check_processes(tmp_path, index())
    odd = [i["detail"] for i in r["items"] if i["key"] == "i.proc.odd"]
    assert len(odd) == 2
    assert not any("UpdateBrainService" in d for d in odd)


LOG_HEADER = "Timestamp               Ty Process[PID:TID]\n"
LOG_LINE = "2026-09-20 04:10:00.000 Df kernel[0:1] an ordinary entry\n"
LOG_HIT = "2026-09-20 04:10:00.000 Df kernel[0:1] [DarkSword stage 1\n"


def unified_logs(tmp_path, monkeypatch, search, readable="", returncode=0):
    """check_unified_logs with `log show` replaced: `search` is the filtered output (or an exception to raise),
    `readable` the unfiltered output of the follow-up that proves the archive has entries."""
    (tmp_path / "system_logs.logarchive").mkdir()

    def run(cmd, **kwargs):
        if isinstance(search, Exception):
            raise search
        return subprocess.CompletedProcess(cmd, returncode, search, "")

    real_popen = subprocess.Popen
    monkeypatch.setattr(checks.subprocess, "run", run)
    monkeypatch.setattr(checks.subprocess, "Popen",
                        lambda cmd, **kw: real_popen(["/usr/bin/printf", "%s", readable], **kw))
    r = checks.check_unified_logs(tmp_path, index())
    return r["status"], r["summary"]["key"]


CLEAN, FAILED, HIT = ("ok", "chk.logs.ok"), ("skipped", "chk.logs.fail"), ("alert", "chk.logs.hits")


@pytest.mark.parametrize("search, readable, returncode, expected", [
    (LOG_HEADER, LOG_HEADER + LOG_LINE, 0, CLEAN),
    # Apple's `log` exits with 65 when it can't open the archive
    ("", "", 65, FAILED),
    (LOG_HEADER, LOG_HEADER + LOG_LINE, 65, FAILED),
    # it exits with 0 and prints only its header when the archive has no readable entries
    (LOG_HEADER, LOG_HEADER, 0, FAILED),
    ("", "", 0, FAILED),
    # a match always counts
    (LOG_HEADER + LOG_HIT, "", 0, HIT),
    (LOG_HEADER + LOG_HIT, "", 65, HIT),
    (subprocess.TimeoutExpired("log", 1), "", 0, ("skipped", "chk.logs.timeout")),
    (subprocess.TimeoutExpired("log", 1, output=(LOG_HEADER + LOG_HIT).encode()), "", 0, HIT),
    (FileNotFoundError(), "", 0, FAILED),
])
def test_unified_logs_only_clean_when_readable(tmp_path, monkeypatch, search, readable, returncode, expected):
    assert unified_logs(tmp_path, monkeypatch, search, readable, returncode) == expected


def test_unreadable_log_makes_the_result_partial():
    missed, fix = checks.partial([checks.skipped("logs", "chk.logs.fail")], "full")
    assert missed == ["logs"] and fix == "v.partial.fix.other"


@pytest.mark.parametrize("files, exit_code, status, key", [
    ({"sms.json": [{}, {}]}, 0, "ok", "chk.mvt.sum"),
    ({"sms.json": [{}, {}]}, 1, "skipped", "chk.mvt.fail"),
    ({"sms.json": [{}, {}]}, -1, "skipped", "chk.mvt.fail"),
    ({"sms.json": []}, 0, "skipped", "chk.mvt.fail"),
    ({}, 0, "skipped", "chk.mvt.fail"),
    ({"sms_detected.json": [{"matched_indicator": {"value": "bh", "type": "processes", "name": "Pegasus"}}]}, 1,
     "alert", "chk.mvt.sum"),
])
def test_mvt_only_clean_when_it_finished_and_read_records(tmp_path, files, exit_code, status, key):
    for name, data in files.items():
        (tmp_path / name).write_text(json.dumps(data))
    r = checks.check_mvt_results(tmp_path, index(), set(), exit_code)
    assert (r["status"], r["summary"]["key"]) == (status, key)


def test_mvt_without_a_backup_or_without_output(tmp_path):
    assert checks.check_mvt_results(None, index(), set())["summary"]["key"] == "chk.mvt.skip"
    assert checks.check_mvt_results(tmp_path / "missing", index(), set(), 1)["summary"]["key"] == "chk.mvt.fail"

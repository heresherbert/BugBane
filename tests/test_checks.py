"""Check logic on hand-made fixtures (no real phone data)."""
import json
import plistlib
from plistlib import UID

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

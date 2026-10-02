"""The indicator download must refuse unknown sources, broken lists and lists that suddenly shrink."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fetch_indicators", ROOT / "app/helpers/fetch_indicators.py")
fi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fi)


def bundle(n):
    return json.dumps({"type": "bundle", "objects": [{"type": "malware", "name": "X"}]
                       + [{"type": "indicator", "pattern": f"[domain-name:value = 'a{i}.example']"} for i in range(n)]})


def entry(owner, repo, path, name="List"):
    return {"name": name, "type": "github", "github": {"owner": owner, "repo": repo, "branch": "main", "path": path}}


def serve(entries, files):
    """A fake fetch: the index as JSON (valid YAML), lists by URL."""
    def fetch(url, limit):
        if url == fi.INDEX_URL:
            return json.dumps({"indicators": entries}).encode()
        if url not in files:
            raise OSError("404")
        return files[url].encode()
    return fetch


def url(owner, repo, path):
    return fi.RAW.format(owner, repo, "main", path)


def test_downloads_allowed_lists_under_mvts_file_names(tmp_path):
    u = url("mvt-project", "mvt-indicators", "a/pegasus.stix2")
    s = fi.update(tmp_path / "indicators", serve([entry("mvt-project", "mvt-indicators", "a/pegasus.stix2")],
                                                 {u: bundle(30)}))
    assert s["updated"] == ["List"] and not (s["refused"] or s["failed"] or s["kept"])
    f = tmp_path / "indicators" / "raw.githubusercontent.com_mvt-project_mvt-indicators_main_a_pegasus.stix2"
    assert fi.count_indicators(f.read_bytes()) == 30
    manifest = json.loads((tmp_path / "bugbane-indicators.json").read_text())
    assert manifest["lists"][f.name]["indicators"] == 30 and len(manifest["lists"][f.name]["sha256"]) == 64


def test_unknown_sources_and_odd_paths_are_refused(tmp_path):
    entries = [entry("someone-else", "lists", "x.stix2", "Foreign"),
               entry("mvt-project", "mvt-indicators", "../../etc/x.stix2", "Escape"),
               entry("mvt-project", "mvt-indicators", "notes.txt", "Not STIX"),
               {"name": "Direct", "type": "url", "download_url": "https://evil.example/x.stix2"}]
    s = fi.update(tmp_path / "indicators", serve(entries, {}))
    assert {r["list"] for r in s["refused"]} == {"Foreign", "Escape", "Not STIX", "Direct"}
    assert not list((tmp_path / "indicators").iterdir())


def test_a_list_that_shrinks_or_breaks_keeps_the_current_copy(tmp_path):
    u = url("AssoEchap", "stalkerware-indicators", "generated/stalkerware.stix2")
    entries = [entry("AssoEchap", "stalkerware-indicators", "generated/stalkerware.stix2")]
    dest = tmp_path / "indicators"
    fi.update(dest, serve(entries, {u: bundle(100)}))
    target = dest / fi.file_name(u)
    for replacement, outcome in ((bundle(40), "kept"), (bundle(0), "kept"), ("{not json", "failed"),
                                 (json.dumps({"type": "report"}), "failed")):
        s = fi.update(dest, serve(entries, {u: replacement}))
        assert s[outcome] and not s["updated"], replacement[:30]
        assert fi.count_indicators(target.read_bytes()) == 100  # untouched
    s = fi.update(dest, serve(entries, {u: bundle(80)}))  # a normal change goes through
    assert s["updated"] and fi.count_indicators(target.read_bytes()) == 80


def test_a_missing_index_changes_nothing(tmp_path):
    def down(url, limit):
        raise OSError("offline")
    s = fi.update(tmp_path / "indicators", down)
    assert s["failed"][0]["list"] == "index" and not s["updated"]


def test_oversized_downloads_are_cut_off():
    class Big:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n): return b"x" * n
    real = fi.urllib.request.urlopen
    fi.urllib.request.urlopen = lambda *a, **k: Big()
    try:
        try:
            fi.fetch("https://raw.githubusercontent.com/x", 10)
            assert False, "accepted an oversized download"
        except ValueError:
            pass
    finally:
        fi.urllib.request.urlopen = real

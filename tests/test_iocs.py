"""Indicator matching must be exact: substring matches caused a false Pegasus hit."""
import json

from scan import iocs


def bundle(malware_name, patterns):
    objects = [{"type": "malware", "id": "malware--1", "name": malware_name}]
    for n, p in enumerate(patterns):
        objects.append({"type": "indicator", "id": f"indicator--{n}", "pattern": p})
        objects.append({"type": "relationship", "source_ref": f"indicator--{n}", "target_ref": "malware--1"})
    return {"type": "bundle", "objects": objects}


def make_index(tmp_path):
    (tmp_path / "x_pegasus.stix2").write_text(json.dumps(bundle("Pegasus", [
        "[process:name='updaterd']", "[domain-name:value='evil.example']",
        "[file:path='/private/var/tmp/implant.db']", "[process:name='ab']"])))
    (tmp_path / "echap_generated_stalkerware.stix2").write_text(json.dumps(bundle("SpyCo", [
        "[domain-name:value='tracker.example']", "[app:id='com.spyco.app']"])))
    (tmp_path / "triangulation.stix2").write_text(json.dumps(bundle("OperationTriangulation", [
        "[process:name='BackupAgent']"])))
    (tmp_path / "campaign.stix2").write_text(json.dumps(bundle("MercenarySpywareCampaign", [
        "[domain-name:value='campaign.example']"])))
    return iocs.load(tmp_path)


def test_process_names_match_whole_basename_only(tmp_path):
    idx = make_index(tmp_path)
    assert idx.match_process("/private/var/db/updaterd").malware == "Pegasus"
    assert idx.match_process("/System/Library/PrivateFrameworks/MobileAccessoryUpdater.framework/Support/accessoryupdaterd") is None


def test_domains_match_on_label_boundaries(tmp_path):
    idx = make_index(tmp_path)
    assert idx.match_domain("cdn.evil.example").value == "evil.example"
    assert idx.match_domain("EVIL.example.").value == "evil.example"
    assert idx.match_domain("notevil.example") is None
    assert idx.match_domain(None) is None


def test_categories_names_and_noise(tmp_path):
    idx = make_index(tmp_path)
    assert idx.domains["tracker.example"].category == "stalkerware"
    assert idx.domains["evil.example"].category == "mercenary"
    assert idx.app_ids["com.spyco.app"].malware == "SpyCo"
    assert idx.match_path("/private/var/tmp/implant.db").malware == "Pegasus"
    assert "ab" not in idx.processes  # too short to be meaningful
    families = {f for feed in idx.feeds for f in feed["families"]}
    assert "Operation Triangulation" in families
    assert "MercenarySpywareCampaign" not in families


def test_indicator_folder_follows_mvt(monkeypatch, tmp_path):
    """The app, setup.sh (`mvt download-iocs`) and CI must look in the same place MVT writes to."""
    monkeypatch.setenv("MVT_DATA_FOLDER", str(tmp_path))
    assert iocs.mvt_data_folder() == tmp_path
    monkeypatch.delenv("MVT_DATA_FOLDER")
    monkeypatch.setattr(iocs.sys, "platform", "darwin")
    assert iocs.mvt_data_folder().parts[-3:] == ("Library", "Application Support", "mvt")
    monkeypatch.setattr(iocs.sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert iocs.mvt_data_folder() == tmp_path / "xdg" / "mvt"
    monkeypatch.delenv("XDG_DATA_HOME")
    assert iocs.mvt_data_folder().parts[-3:] == (".local", "share", "mvt")

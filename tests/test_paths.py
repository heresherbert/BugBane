"""Code, tools and data must land in the right place in every setup (checkout, legacy install, app bundle)."""
from pathlib import Path

from scan import paths


def test_checkout_keeps_everything_in_the_repo(tmp_path):
    (tmp_path / ".tools").mkdir()
    assert not paths.in_bundle(tmp_path)
    assert paths.tools_folder(tmp_path) == tmp_path / ".tools"
    assert paths.data_folder(tmp_path, environ={}) == tmp_path


def test_bundle_uses_embedded_runtime_and_keeps_data_out_of_the_bundle(tmp_path):
    res = tmp_path / "BugBane.app" / "Contents" / "Resources"
    (res / "runtime").mkdir(parents=True)
    assert paths.in_bundle(res)
    assert paths.tools_folder(res) == res / "runtime"
    data = paths.data_folder(res, environ={})
    assert data == Path.home() / "Library/Application Support/Bugbane"
    assert res not in data.parents and data != res  # the signed bundle is never written to


def test_lookalike_folders_are_not_a_bundle(tmp_path):
    for fake in ("Resources", "Contents/Resources", "BugBane/Contents/Resources", "x.app/Resources"):
        assert not paths.in_bundle(tmp_path / fake), fake


def test_data_folder_can_be_overridden(tmp_path):
    res = tmp_path / "BugBane.app" / "Contents" / "Resources"
    assert paths.data_folder(res, environ={"BUGBANE_DATA": str(tmp_path / "d")}) == tmp_path / "d"


def test_the_running_code_uses_one_data_folder():
    """Evidence, History and run state (incl. the restore index) share the data folder."""
    from scan import recovery
    for folder in (paths.EVIDENCE, paths.HISTORY, paths.RUN):
        assert folder.parent == paths.DATA
    assert recovery.INDEX.parent == paths.RUN

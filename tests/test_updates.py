"""The launch-time update check: offers only a newer release from the public repo, and stays quiet offline."""
import io
import json

from scan import pipeline


def fake(release):
    def urlopen(req, timeout=None):
        assert req.full_url == f"https://api.github.com/repos/{pipeline.UPDATE_REPO}/releases/latest"
        assert "BugBane" in req.headers.get("User-agent", "")  # GitHub requires a user agent; nothing else is sent
        return io.BytesIO(json.dumps(release).encode())
    return urlopen


def run(monkeypatch, release, version="0.68"):
    pipeline.UPDATE.clear()
    monkeypatch.setattr(pipeline, "APP_VERSION", version)
    monkeypatch.setattr(pipeline.urllib.request, "urlopen", fake(release))
    return pipeline.check_for_update()


def test_newer_release_is_offered(monkeypatch):
    url = f"https://github.com/{pipeline.UPDATE_REPO}/releases/tag/v0.69"
    assert run(monkeypatch, {"tag_name": "v0.69", "html_url": url}) == {"latest": "0.69", "url": url}


def test_same_or_older_release_is_not(monkeypatch):
    url = f"https://github.com/{pipeline.UPDATE_REPO}/releases/tag/v0.68"
    assert run(monkeypatch, {"tag_name": "v0.68", "html_url": url}) is None
    assert run(monkeypatch, {"tag_name": "v0.67", "html_url": url}) is None


def test_a_link_outside_the_public_repo_is_refused(monkeypatch):
    assert run(monkeypatch, {"tag_name": "v9.0", "html_url": "https://evil.example/download"}) is None


def test_offline_is_silent(monkeypatch):
    pipeline.UPDATE.clear()
    def down(*a, **k):
        raise OSError("offline")
    monkeypatch.setattr(pipeline.urllib.request, "urlopen", down)
    assert pipeline.check_for_update() is None

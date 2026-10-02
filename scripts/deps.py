#!/usr/bin/env python3
"""Dependency locking and vetting for BugBane's Python environments.

Every package BugBane installs is pinned to an exact version and SHA-256 hash in requirements/<env>.txt
(generated from the hand-edited requirements/<env>.in), and every change to those locks has to pass `vet`
before it is merged. Policy lives in requirements/vetting.toml.

  scripts/deps.py lock [--upgrade]   regenerate the locks from the .in files (uv, all platforms, wheels only,
                                     nothing newer than the cooldown except the explicit pins in .in)
  scripts/deps.py check              the locks match the .in files (nothing hand-edited)
  scripts/deps.py outdated           newer releases of the explicit pins that are past the cooldown
  scripts/deps.py bump               write those versions into the .in files (then run lock and vet)
  scripts/deps.py vet [--base REF]   vet what changed since REF (default: origin/main)
  scripts/deps.py vet --all          audit every locked package (daily in CI)
  scripts/deps.py sbom [VERSION]     CycloneDX SBOM of the app: embedded Python plus every locked runtime package
  scripts/deps.py snapshot           the locks as a GitHub dependency snapshot (CI submits it on every push to main,
                                     so the dependency graph and security alerts track the exact locked versions)

After reading what vet flags for review, record the package in requirements/reviewed.txt (name==version).

vet exit codes: 0 pass, 1 fail (do not merge), 2 needs a person to read the report before merging.
Runs from the dev environment (.venv); network: pypi.org, files.pythonhosted.org, api.osv.dev and Sigstore's trust root
(tuf-repo-cdn.sigstore.dev) only.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import io
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import tomllib
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
REQ = ROOT / "requirements"
ENVS = ("pmd3", "mvt", "dev")
PYTHON = "3.12"
POLICY = tomllib.loads((REQ / "vetting.toml").read_text())
COOLDOWN = dt.timedelta(days=POLICY["cooldown_days"])
SOURCE_ONLY = {canonicalize_name(k): v for k, v in POLICY.get("source_only", {}).items()}
ACCEPTED = {a["id"]: a for a in POLICY.get("accepted_advisory", [])}
EXPEDITED = {(canonicalize_name(e["package"]), e["version"]) for e in POLICY.get("expedite", [])}
# name==version lines a person has read in full after vet asked for review (requirements/reviewed.txt)
REVIEWED = {(canonicalize_name(m.group(1)), m.group(2)) for m in re.finditer(
    r"(?m)^([A-Za-z0-9._-]+)==(\S+)", (REQ / "reviewed.txt").read_text())}
NOW = dt.datetime.now(dt.timezone.utc)

# Code patterns worth a person's eyes when they appear in a new version of a package. Counted per file; only
# increases over the previous version are reported, so long-standing uses stay quiet.
PATTERNS = {
    "decode+exec": re.compile(r"(exec|eval|compile)\s*\(.*(b64decode|b32decode|a85decode|decompress|marshal|"
                              r"codecs\.decode|bytes\.fromhex|rot13)"),
    "encoded payload": re.compile(r"\b(b64decode|b32decode|b85decode|a85decode|marshal\.loads|zlib\.decompress)\s*\("),
    "dynamic import": re.compile(r"__import__\s*\(\s*['\"](base64|zlib|marshal|socket|subprocess|urllib|os|ctypes)"),
    "exec/eval": re.compile(r"(?<![\w.])(exec|eval)\s*\("),
    "process spawn": re.compile(r"\b(os\.system|os\.popen|subprocess\.\w+|pty\.spawn|os\.exec\w+)\s*\("),
    "network": re.compile(r"\b(urlopen|urllib\.request|http\.client|requests\.(get|post|put)|socket\.socket|"
                          r"httpx\.|aiohttp\.)"),
    "hard-coded IP URL": re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}"),
    "download tool": re.compile(r"\b(curl|wget)\s+(-\S+\s+)*https?://"),
    "credential paths": re.compile(r"(\.ssh/|\.aws/|\.npmrc|\.pypirc|Keychains|\.gnupg|keychain|"
                                   r"wallet\.dat|Login Data)"),
    "env harvesting": re.compile(r"os\.environ(\.copy\(\)|\.items\(\)|\))\s*$"),
}
LONG_LINE = 2000  # a .py line this long is usually minified or obfuscated code


# --- lock files ---------------------------------------------------------------------------------------

def parse_lock(text):
    """{name: {"version", "marker", "hashes"}} from a requirements file (hashed or not)."""
    out = {}
    for entry in re.sub(r"\\\n", " ", text).splitlines():
        entry = entry.split("#", 1)[0].strip()
        m = re.match(r"([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*==\s*([^\s;]+)\s*(?:;\s*([^-]*?))?\s*(--hash.*)?$", entry)
        if m:
            out[canonicalize_name(m.group(1))] = {
                "version": m.group(3), "marker": (m.group(4) or "").strip(),
                "hashes": set(re.findall(r"sha256:([0-9a-f]{64})", m.group(5) or ""))}
    return out


def explicit_pins(env):
    pins = {}
    for line in (REQ / f"{env}.in").read_text().splitlines():
        m = re.match(r"\s*([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*==\s*([^\s;#]+)", line)
        if m:
            pins[canonicalize_name(m.group(1))] = m.group(3)
    return pins


def lock_command(env, output):
    cutoff = (NOW - COOLDOWN).strftime("%Y-%m-%dT00:00:00Z")
    cmd = ["uv", "pip", "compile", f"requirements/{env}.in", "--universal", "--python-version", PYTHON,
           "--generate-hashes", "--only-binary", ":all:", "--exclude-newer", cutoff, "-o", output]
    for name in SOURCE_ONLY:
        cmd += ["--no-binary", name]
    # explicit pins in .in are chosen on purpose; vet still holds them to the cooldown
    for name in explicit_pins(env):
        cmd += ["--exclude-newer-package", f"{name}={NOW:%Y-%m-%dT%H:%M:%SZ}"]
    return cmd


def uv():
    exe = shutil.which("uv", path=str(Path(sys.executable).parent)) or shutil.which("uv")
    if not exe:
        sys.exit("uv not found: pip install -r requirements/dev.txt")
    return exe


def cmd_lock(args):
    for env in ENVS:
        cmd = lock_command(env, f"requirements/{env}.txt") + (["--upgrade"] if args.upgrade else [])
        subprocess.run([uv(), *cmd[1:], "-q"], cwd=ROOT, check=True)
        print(f"locked requirements/{env}.txt: {len(parse_lock((REQ / f'{env}.txt').read_text()))} packages")


def cmd_check(_args):
    bad = 0
    for env in ENVS:
        lock = REQ / f"{env}.txt"
        header = next((l for l in lock.read_text().splitlines() if l.startswith("#    uv pip compile")), None)
        if not header:
            print(f"{lock.name}: not generated by scripts/deps.py lock"); bad += 1; continue
        argv = shlex.split(header.lstrip("# "))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp, lock.name)
            shutil.copy(lock, out)  # same preferences: unchanged inputs must give the same file
            i = argv.index("-o") if "-o" in argv else argv.index("--output-file")
            argv[i + 1] = str(out)
            r = subprocess.run([uv(), *argv[1:], "-q"], cwd=ROOT, capture_output=True, text=True)
            if r.returncode:
                print(f"{lock.name}: does not resolve from {env}.in\n{r.stderr}"); bad += 1; continue
            strip = lambda t: [l for l in t.splitlines() if not l.startswith("#    uv pip compile")]
            if strip(out.read_text()) != strip(lock.read_text()):
                print(f"{lock.name}: differs from what {env}.in resolves to (hand-edited, or run lock)"); bad += 1
            else:
                print(f"{lock.name}: matches {env}.in")
    sys.exit(1 if bad else 0)


# --- PyPI -----------------------------------------------------------------------------------------------

def fetch(url, data=None, tries=3):
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers={"User-Agent": "bugbane-deps",
                                                                 "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == tries - 1:
                raise


def release(name, version):
    raw = fetch(f"https://pypi.org/pypi/{name}/{version}/json")
    return json.loads(raw) if raw else None


def uploaded(rel):
    times = [dt.datetime.fromisoformat(u["upload_time_iso_8601"].replace("Z", "+00:00")) for u in rel["urls"]]
    return min(times) if times else None


def pick_wheel(rel):
    """The file we inspect: the macOS arm64 build if there is one, else a pure-Python wheel, else any."""
    wheels = [u for u in rel["urls"] if u["packagetype"] == "bdist_wheel"]
    def rank(u):
        f = u["filename"]
        return (0 if "macosx" in f and ("arm64" in f or "universal2" in f) and ("cp312" in f or "abi3" in f)
                else 1 if f.endswith("-none-any.whl") else 2)
    return min(wheels, key=rank) if wheels else None


_SIGSTORE = threading.Lock()
_TRUST_ROOT_FRESH = False


def provenance(name, version, filename, sha256):
    """The verified publishers of one file, from its PyPI attestations (PEP 740), or None if it has none.

    Each attestation is verified with Sigstore (pypi-attestations): the signature, its transparency-log entry,
    that it covers exactly this file (name and SHA-256), and that the signing identity is the publisher PyPI
    recorded (e.g. a GitHub repository and workflow). Raises ValueError if an attestation does not verify."""
    global _TRUST_ROOT_FRESH
    raw = fetch(f"https://pypi.org/integrity/{name}/{version}/{filename}/provenance")
    if not raw:
        return None
    from pypi_attestations import AttestationError, Distribution, Provenance
    import logging
    logging.getLogger("sigstore").setLevel(logging.ERROR)  # "TUF repository is loaded in offline mode"
    dist = Distribution(name=filename, digest=sha256)
    pubs = set()
    for bundle in Provenance.model_validate_json(raw).attestation_bundles:
        pub = bundle.publisher
        for att in bundle.attestations:
            with _SIGSTORE:  # one trust-root refresh per run, then offline verification
                try:
                    att.verify(pub, dist, offline=_TRUST_ROOT_FRESH)
                except AttestationError as e:
                    raise ValueError(f"attestation for {filename} does not verify: {e}") from e
                _TRUST_ROOT_FRESH = True
        where = getattr(pub, "repository", None) or getattr(pub, "project", None) or "?"
        pubs.add(f"{pub.kind}:{where}")
    return sorted(pubs) or None


def download(url, sha256):
    blob = fetch(url)
    if hashlib.sha256(blob).hexdigest() != sha256:
        raise ValueError(f"hash mismatch downloading {url}")
    return blob


def wheel_files(blob):
    """{path: bytes} after checking every file against the wheel's own RECORD."""
    z = zipfile.ZipFile(io.BytesIO(blob))
    files = {n: z.read(n) for n in z.namelist() if not n.endswith("/")}
    record = next((n for n in files if n.endswith(".dist-info/RECORD")), None)
    problems = []
    if record:
        import base64, csv
        for row in csv.reader(files[record].decode().splitlines()):
            if len(row) >= 2 and row[1].startswith("sha256="):
                want = row[1][7:]
                got = base64.urlsafe_b64encode(hashlib.sha256(files.get(row[0], b"")).digest()).rstrip(b"=").decode()
                if row[0] not in files or got != want:
                    problems.append(f"RECORD mismatch: {row[0]}")
        listed = {row[0] for row in csv.reader(files[record].decode().splitlines()) if row}
        problems += [f"file not in RECORD: {n}" for n in files if n not in listed]
    else:
        problems.append("wheel has no RECORD")
    return files, problems


def scan(files):
    """{(path, pattern): [matching lines]} plus structural facts about a wheel."""
    hits, facts = {}, {"pth": set(), "native": set(), "scripts": "", "long": set()}
    for path, data in files.items():
        if path.endswith(".pth"):
            facts["pth"].add(path)
        elif path.endswith((".so", ".dylib", ".dll", ".pyd")):
            facts["native"].add(path.rsplit("/", 1)[-1])
        elif path.endswith(".dist-info/entry_points.txt"):
            facts["scripts"] = data.decode(errors="replace")
        elif path.endswith(".py"):
            for line in data.decode(errors="replace").splitlines():
                if len(line) > LONG_LINE:
                    facts["long"].add(path)
                for label, rx in PATTERNS.items():
                    if rx.search(line):
                        hits.setdefault((path, label), []).append(line.strip()[:200])
    return hits, facts


def strip_version(path):
    # foo-1.2.dist-info/RECORD -> foo-*.dist-info/RECORD, so files line up across versions
    return re.sub(r"^([^/]+?)-[^-/]+\.(dist-info|data)/", r"\1-*.\2/", path)


# --- vet ------------------------------------------------------------------------------------------------

def locks_at(ref):
    out = {}
    for env in ENVS:
        if ref is None:
            text = (REQ / f"{env}.txt").read_text()
        else:
            r = subprocess.run(["git", "show", f"{ref}:requirements/{env}.txt"], cwd=ROOT, capture_output=True,
                               text=True)
            text = r.stdout if r.returncode == 0 else ""
        out[env] = parse_lock(text)
    return out


def osv(packages):
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in packages]
    found = {}
    for i in range(0, len(queries), 500):
        body = json.dumps({"queries": queries[i:i + 500]}).encode()
        res = json.loads(fetch("https://api.osv.dev/v1/querybatch", data=body))["results"]
        for (n, v), r in zip(packages[i:i + 500], res):
            ids = [x["id"] for x in r.get("vulns", [])]
            if ids:
                found[(n, v)] = ids
    return found


def vet_package(name, version, hashes, old_version, deep):
    """Returns (fails, reviews, notes) for one locked package."""
    fails, reviews, notes = [], [], []
    rel = release(name, version)
    if not rel:
        return [f"{version} not found on PyPI"], [], []
    digests = {u["digests"]["sha256"]: u for u in rel["urls"]}
    if any(u.get("yanked") for u in rel["urls"]):
        fails.append(f"{version} is yanked")
    if not hashes:
        fails.append("no hashes in the lock")
    unknown = hashes - set(digests)
    if unknown:
        fails.append(f"{len(unknown)} hash(es) in the lock are not files of {version} on PyPI")
    wheels = [u for h, u in digests.items() if h in hashes and u["packagetype"] == "bdist_wheel"]
    if not wheels:
        allowed = SOURCE_ONLY.get(name)
        sdist = [h for h, u in digests.items() if h in hashes and u["packagetype"] == "sdist"]
        if not allowed:
            fails.append("no wheel: installing would run its setup code (add to source_only after review)")
        elif allowed["version"] != version or allowed["sha256"] not in sdist:
            fails.append(f"source-only allowance is for {allowed['version']} ({allowed['sha256'][:12]}…), "
                         f"not this file: review the new sdist")
    attested = [u for h, u in digests.items() if h in hashes and u["packagetype"] == "bdist_wheel"]
    if attested:  # verify one locked file's attestations (none = fine, but a broken one fails)
        f = min(attested, key=lambda u: u["filename"])
        try:
            prov = provenance(name, version, f["filename"], f["digests"]["sha256"])
            if prov and not deep:
                notes.append(f"attestation verified: {', '.join(prov)}")
        except ValueError as e:
            fails.append(str(e))
    changed = old_version != version
    if changed and deep and (name, version) not in EXPEDITED:  # --all audits what is merged
        when = uploaded(rel)
        if when and NOW - when < COOLDOWN:
            fails.append(f"{version} was released {when:%Y-%m-%d}, inside the {COOLDOWN.days}-day cooldown")
    if not deep or not changed:
        return fails, reviews, notes
    fails, reviews, notes = _inspect(name, version, rel, old_version, fails, reviews, notes)
    if reviews and (name, version) in REVIEWED:
        notes += [f"reviewed: {r}" for r in reviews]
        reviews = []
    return fails, reviews, notes


def _inspect(name, version, rel, old_version, fails, reviews, notes):
    """Content and provenance comparison of a changed package's wheel with its previous version."""
    new_wheel = pick_wheel(rel)
    if old_version is None:
        reviews.append(f"new in the dependency tree ({version}): check what it is and who publishes it")
    if not new_wheel:
        return fails, reviews, notes
    try:
        new_prov = provenance(name, version, new_wheel["filename"], new_wheel["digests"]["sha256"])
    except ValueError as e:
        return fails + [str(e)], reviews, notes
    try:
        new_files, problems = wheel_files(download(new_wheel["url"], new_wheel["digests"]["sha256"]))
    except ValueError as e:
        return fails + [str(e)], reviews, notes
    fails += problems[:5]
    new_hits, new_facts = scan(new_files)
    old_hits, old_facts, old_prov = {}, {"pth": set(), "native": set(), "scripts": "", "long": set()}, None
    if old_version:
        old_rel = release(name, old_version)
        old_wheel = pick_wheel(old_rel) if old_rel else None
        if old_wheel:
            try:
                old_prov = provenance(name, old_version, old_wheel["filename"], old_wheel["digests"]["sha256"])
            except ValueError as e:
                notes.append(f"previous version's {e}")
            old_files, _ = wheel_files(download(old_wheel["url"], old_wheel["digests"]["sha256"]))
            old_hits, old_facts = scan(old_files)
    if old_prov and not new_prov:
        fails.append(f"provenance lost: {old_version} had a PyPI attestation ({', '.join(old_prov)}), {version} has none")
    elif old_prov and new_prov and old_prov != new_prov:
        fails.append(f"published from a different place: {', '.join(old_prov)} -> {', '.join(new_prov)}")
    notes.append(f"provenance (verified): {', '.join(new_prov) if new_prov else 'none'}")
    if new_facts["pth"] - old_facts["pth"] or (old_version is None and new_facts["pth"]):
        reviews.append(f".pth file(s), which run at every Python start: {sorted(new_facts['pth'])}")
    added_native = new_facts["native"] - old_facts["native"]
    if old_version and added_native:
        reviews.append(f"new native libraries: {sorted(added_native)[:6]}")
    if old_version and new_facts["scripts"] != old_facts["scripts"]:
        reviews.append("console scripts / entry points changed")
    long_new = {strip_version(p) for p in new_facts["long"]} - {strip_version(p) for p in old_facts["long"]}
    if long_new and old_version:
        reviews.append(f"very long code lines (minified or obfuscated?): {sorted(long_new)[:4]}")
    old_counts = {(strip_version(p), l): len(v) for (p, l), v in old_hits.items()}
    for (path, label), lines in sorted(new_hits.items()):
        before = old_counts.get((strip_version(path), label), 0)
        if old_version and len(lines) > before:
            reviews.append(f"{label} +{len(lines) - before} in {path}: {lines[-1]}")
        elif old_version is None and label in ("decode+exec", "dynamic import", "hard-coded IP URL", "download tool",
                                               "credential paths"):
            reviews.append(f"{label} in {path}: {lines[0]}")
    return fails, reviews, notes


def cmd_vet(args):
    new = locks_at(None)
    old = {env: {} for env in ENVS} if args.all else locks_at(args.base)
    rows = {}
    for env in ENVS:
        for name, e in new[env].items():
            prev = old[env].get(name, {}).get("version")
            if not prev:  # moved between environments is not new
                prev = next((old[o][name]["version"] for o in ENVS if name in old[o]), None)
            rows.setdefault((name, e["version"]), {"hashes": set(), "old": prev, "envs": []})
            rows[(name, e["version"])]["hashes"] |= e["hashes"]
            rows[(name, e["version"])]["envs"].append(env)
    removed = sorted({n for env in ENVS for n in old[env]} - {n for env in ENVS for n in new[env]})
    to_check = sorted(rows) if args.all else sorted(k for k, r in rows.items() if r["old"] != k[1])
    deep = not args.all
    print(f"Vetting {len(to_check)} of {len(rows)} locked packages"
          + ("" if args.all else f" (changed since {args.base})") + f"; cooldown {COOLDOWN.days} days")

    results = {}
    with cf.ThreadPoolExecutor(8) as ex:
        futs = {ex.submit(vet_package, n, v, rows[(n, v)]["hashes"], None if args.all else rows[(n, v)]["old"],
                          deep): (n, v) for n, v in to_check}
        for f in cf.as_completed(futs):
            try:
                results[futs[f]] = f.result()
            except Exception as e:  # network trouble must not read as a pass
                results[futs[f]] = ([f"could not be checked: {e!r}"], [], [])
    vulns = osv(sorted(rows))  # always every package: advisories appear for old versions too
    for (n, v), ids in vulns.items():
        open_ids = [i for i in ids if i not in ACCEPTED]
        if open_ids:
            results.setdefault((n, v), ([], [], []))[0].append(f"known vulnerabilities: {', '.join(open_ids)}")

    n_fail = n_review = 0
    for (n, v) in sorted(results):
        fails, reviews, notes = results[(n, v)]
        if not (fails or reviews or (notes and not args.all)):
            continue
        old_v = rows.get((n, v), {}).get("old")
        print(f"\n{n} {old_v + ' -> ' if old_v and old_v != v else ''}{v}  [{', '.join(rows[(n, v)]['envs'])}]")
        for x in fails:
            print(f"  FAIL    {x}")
        for x in reviews[:15]:
            print(f"  REVIEW  {x}")
        if len(reviews) > 15:
            print(f"  REVIEW  … {len(reviews) - 15} more")
        for x in notes:
            print(f"  note    {x}")
        n_fail += bool(fails)
        n_review += bool(reviews) and not fails
    if removed:
        print(f"\nRemoved from the tree: {', '.join(removed)}")
    n_attested = sum(any(n.startswith(("attestation verified", "provenance (verified): ")) and not n.endswith(" none")
                         for n in r[2]) for r in results.values())
    verdict = "FAIL" if n_fail else "NEEDS REVIEW" if n_review else "PASS"
    print(f"\n{verdict}: {n_fail} failing, {n_review} to review, {len(to_check)} vetted, "
          f"{len(vulns)} with advisories (accepted: {sum(all(i in ACCEPTED for i in ids) for ids in vulns.values())}), "
          f"{n_attested} with verified PyPI attestations")
    sys.exit(1 if n_fail else 2 if n_review else 0)


# --- updates ----------------------------------------------------------------------------------------------

def newest_settled(name, current):
    """The newest stable, unyanked release of name that is past the cooldown, if newer than current."""
    data = json.loads(fetch(f"https://pypi.org/pypi/{name}/json"))
    best = None
    for ver, files in data["releases"].items():
        try:
            v = Version(ver)
        except InvalidVersion:
            continue
        if v.is_prerelease or v.is_devrelease or not files or any(f.get("yanked") for f in files):
            continue
        when = min(dt.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files)
        if NOW - when >= COOLDOWN and v > Version(current) and (best is None or v > best[0]):
            best = (v, when)
    return best


def outdated():
    found = []
    for env in ENVS:
        for name, ver in explicit_pins(env).items():
            best = newest_settled(name, ver)
            if best:
                found.append((env, name, ver, str(best[0]), best[1]))
    return found


def cmd_outdated(_args):
    rows = outdated()
    for env, name, ver, new, when in rows:
        print(f"{env:5} {name} {ver} -> {new} (released {when:%Y-%m-%d})")
    if not rows:
        print(f"All explicit pins are current (ignoring releases younger than {COOLDOWN.days} days).")


def cmd_bump(_args):
    for env, name, ver, new, _ in outdated():
        path = REQ / f"{env}.in"
        text = path.read_text()
        spelled = "[-_.]".join(map(re.escape, name.split("-")))  # pins may spell the name with _ or .
        path.write_text(re.sub(rf"(?im)^({spelled}(\[[^\]]*\])?\s*==\s*){re.escape(ver)}(?=\s|;|#|$)",
                               rf"\g<1>{new}", text))
        print(f"{env}: {name} {ver} -> {new}")
    print("Next: scripts/deps.py lock, then scripts/deps.py vet")


def _installed_on(marker, plat):
    """True if a lock entry's environment marker holds on plat ("darwin" for the app, "linux" for CI)."""
    if not marker:
        return True
    from packaging.markers import Marker
    return Marker(marker).evaluate({
        "python_version": PYTHON, "python_full_version": f"{PYTHON}.0", "implementation_name": "cpython",
        "platform_python_implementation": "CPython", "os_name": "posix", "sys_platform": plat,
        "platform_system": {"darwin": "Darwin", "linux": "Linux"}[plat]})


def _installed_somewhere(marker):
    """True if a lock entry is installed on macOS (the app) or Linux (CI); Windows-only packages are skipped."""
    return _installed_on(marker, "darwin") or _installed_on(marker, "linux")


def cmd_snapshot(_args):
    import os
    manifests = {}
    for env in ENVS:
        direct = explicit_pins(env)
        resolved = {}
        for name, e in parse_lock((REQ / f"{env}.txt").read_text()).items():
            if _installed_somewhere(e["marker"]):
                purl = f"pkg:pypi/{name}@{e['version']}"
                resolved[purl] = {"package_url": purl, "relationship": "direct" if name in direct else "indirect",
                                  "scope": "development" if env == "dev" else "runtime"}
        manifests[f"requirements/{env}.txt"] = {"name": f"requirements/{env}.txt",
                                                "file": {"source_location": f"requirements/{env}.txt"},
                                                "resolved": resolved}
    sha = os.environ.get("GITHUB_SHA") or subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                                          text=True, check=True).stdout.strip()
    print(json.dumps({
        "version": 0, "sha": sha, "ref": os.environ.get("GITHUB_REF", "refs/heads/main"),
        "job": {"correlator": "bugbane-deps-locks", "id": os.environ.get("GITHUB_RUN_ID", "local")},
        "detector": {"name": "bugbane-deps", "version": "1", "url": "https://github.com/heresherbert/BugBane"},
        "scanned": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "manifests": manifests}, indent=1))


def cmd_sbom(args):
    """CycloneDX 1.6 SBOM of what the app bundle contains (the pmd3 and mvt environments and the embedded
    Python), with the SHA-256 hashes the build accepts for each package."""
    import uuid
    conf = {}
    for line in (REQ / "runtime.conf").read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and not line.startswith("#"):
            conf[parts[0]] = parts[1]
    version = args.version or re.search(r'APP_VERSION = "([^"]+)"', (ROOT / "app/scan/pipeline.py").read_text()).group(1)
    components, refs = [], {}
    for env in ("pmd3", "mvt"):
        for name, e in parse_lock((REQ / f"{env}.txt").read_text()).items():
            if not _installed_on(e["marker"], "darwin"):  # the app is macOS only
                continue
            purl = f"pkg:pypi/{name}@{e['version']}"
            if purl in refs:
                refs[purl]["properties"].append({"name": "bugbane:environment", "value": env})
                continue
            refs[purl] = {"type": "library", "bom-ref": purl, "name": name, "version": e["version"], "purl": purl,
                          "hashes": [{"alg": "SHA-256", "content": h} for h in sorted(e["hashes"])],
                          "properties": [{"name": "bugbane:environment", "value": env}]}
            components.append(refs[purl])
    for triple in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
        if triple in conf:
            components.append({
                "type": "application", "bom-ref": f"cpython-{triple}", "name": "cpython", "version": conf["python"],
                "description": f"python-build-standalone {conf['release']} ({triple}), embedded interpreter",
                "hashes": [{"alg": "SHA-256", "content": conf[triple]}],
                "externalReferences": [{"type": "distribution", "url":
                    f"https://github.com/astral-sh/python-build-standalone/releases/download/{conf['release']}/"
                    f"cpython-{conf['python']}+{conf['release']}-{triple}-install_only.tar.gz"}]})
    print(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'bugbane-' + version)}",
        "metadata": {"timestamp": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "tools": {"components": [{"type": "application", "name": "scripts/deps.py"}]},
                     "component": {"type": "application", "bom-ref": "bugbane", "name": "BugBane", "version": version,
                                   "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
                                   "externalReferences": [{"type": "vcs",
                                                           "url": "https://github.com/heresherbert/BugBane"}]}},
        "components": components}, indent=1))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lock").add_argument("--upgrade", action="store_true", help="also move unchanged transitive pins")
    sub.add_parser("check")
    sub.add_parser("outdated")
    sub.add_parser("bump")
    sub.add_parser("snapshot")
    sub.add_parser("sbom").add_argument("version", nargs="?")
    v = sub.add_parser("vet")
    v.add_argument("--base", default="origin/main", help="git ref to compare with (default origin/main)")
    v.add_argument("--all", action="store_true", help="audit every locked package (no content diff)")
    args = p.parse_args()
    {"lock": cmd_lock, "check": cmd_check, "outdated": cmd_outdated, "bump": cmd_bump, "vet": cmd_vet,
     "snapshot": cmd_snapshot, "sbom": cmd_sbom}[args.cmd](args)


if __name__ == "__main__":
    main()

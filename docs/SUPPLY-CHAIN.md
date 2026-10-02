# Dependency integrity

BugBane checks phones for spyware, so the code it runs has to be exactly the code we meant to ship. This page
describes how every third-party component is pinned, verified and vetted, and how to check it yourself.

## What gets installed

| Component | Pinned in | Verified by |
|---|---|---|
| Embedded Python (app bundle) | `requirements/runtime.conf` | SHA-256, plus the GitHub attestation from python-build-standalone's own release workflow (`gh attestation verify`) |
| pymobiledevice3 and its dependencies | `requirements/pmd3.txt` | exact version and SHA-256 of every file, for every package |
| MVT and its dependencies | `requirements/mvt.txt` | same |
| Test and build tools | `requirements/dev.txt` | same |
| CI actions | `.github/workflows/ci.yml` | full commit SHA (a tag can be moved, a commit can't) |

The `.txt` files are **locks**: every package in the tree, transitive ones included, at one version, with the
SHA-256 of each file PyPI publishes for it. They are generated from the short, hand-edited `.in` files by
`scripts/deps.py lock` and never edited by hand; CI regenerates them and fails if they differ.

Every install (`setup.sh`, `scripts/build_app.sh`, CI) uses:

```bash
pip install --require-hashes --only-binary :all: -r requirements/<env>.txt
```

- `--require-hashes`: pip refuses any file whose SHA-256 isn't in the lock, and any package the lock doesn't
  name. A replaced file on PyPI or a mirror, or a dependency that appears out of nowhere, stops the install.
- `--only-binary :all:`: wheels only, so no package runs its own code while being installed. The single
  exception, `hexdump` 3.3 (no wheel exists), is allowed by the hash of one file that was read in full
  (`requirements/vetting.toml`).
- The app bundle removes `.pth` files (code that would run at every interpreter start) and loads packages via
  `PYTHONPATH`, which never reads them.

## The vetting gate

No dependency change is merged until `scripts/deps.py vet` passes. It compares the locks with the previous
version and, for every package that changed or is new:

- **Cooldown.** The release must have been public for at least 7 days. Compromised releases are usually found
  and pulled within days; waiting keeps them out. `lock` applies the same rule to transitive packages, so the
  resolver never picks anything younger.
- **Hashes.** Every hash in the lock must be a file PyPI lists for that exact version; nothing yanked.
- **Known vulnerabilities.** Every locked package (not only the changed ones) is checked against
  [OSV](https://osv.dev), which includes the GitHub and PyPA advisory databases.
- **Provenance.** PyPI attestations (PEP 740, Trusted Publishing) are verified cryptographically with
  [pypi-attestations](https://github.com/pypi/pypi-attestations) and Sigstore: the signature, its transparency-log
  entry, that it covers exactly the locked file's SHA-256, and that the signing identity is the publisher PyPI
  recorded (for example a GitHub repository and workflow). An attestation that doesn't verify fails, for every
  locked package, daily. For a changed package the verified publisher is compared with the previous version's: a
  package that loses its attestation, or is suddenly published from a different repository, fails.
- **Wheel integrity.** Each wheel is downloaded, hash-checked, and every file checked against the wheel's own
  `RECORD`; a changed or smuggled file fails.
- **Code review signals.** The new wheel is compared with the previous one, and increases in risky patterns
  are reported for a person to read: decoding followed by `exec`, encoded payloads, dynamic imports, process
  spawning, network calls, hard-coded IP addresses, download commands, access to credential files, very long
  (minified) lines, new `.pth` files, new native libraries and changed entry points.
- **New packages.** Anything entering the dependency tree for the first time needs a person to check what it
  is and who publishes it.

Results: **pass** (merge), **fail** (don't), or **needs review**. After reading what was flagged, the reviewer
records the package in `requirements/reviewed.txt`; review items for it then become notes, while the hard
checks above still apply.

CI runs `deps.py check` and `deps.py vet` on every push and pull request, and audits every locked package daily,
so an advisory published for a version we already ship fails the next daily run.
On every push to `main`, CI also submits the locks to GitHub's dependency graph (`deps.py snapshot`), so
GitHub's security alerts cover the exact installed versions.

## Threat data

The indicator lists are data, not code, but an attacker who could empty or swap them could hide spyware from the
check. `app/helpers/fetch_indicators.py` downloads them (when the app opens if they are more than a day old, and
before each check) and only replaces a list when:

- the index comes from MVT's indicator repository and the list from one of the allowed GitHub repositories
  (`mvt-project/mvt-indicators`, `AmnestyTech/investigations`, `AssoEchap/stalkerware-indicators`); a new source is
  refused until it has been reviewed;
- TLS verifies and the download stays within its size limit;
- it is a STIX2 bundle with at least one indicator;
- it hasn't lost more than half of its indicators compared with the current copy (a shrinking list is refused
  and the current copy kept).

New copies are written completely before they replace the old ones. `bugbane-indicators.json`, next to the
lists, records each list's SHA-256, indicator count and download time. CI runs the same downloader daily in
strict mode, so a refused, shrunken or failed list shows up the same day.

## Reproducible build and SBOM

Two builds of the same commit produce byte-identical apps: every file, including the code signature.
`scripts/repro_check.sh` builds twice in different folders and compares the SHA-256 of every file; a release is
only published if it passes. What makes it work:

- every package and the embedded Python come from hashed locks;
- bytecode is compiled as hash-based `.pyc` files (no timestamps), with a fixed hash seed, one file per process
  (marshal output otherwise depends on what else the process compiled), and paths relative to the bundle;
- pip's generated `bin/` scripts, which contain the build folder's path, are removed along with their `RECORD`
  entries.

The pip that installs the packages is the one inside the verified embedded Python; it is removed from the app
afterwards.

Each GitHub release carries two files:

- `BugBane-<version>.cdx.json`: a CycloneDX SBOM of the app, with every package, its version and accepted hashes,
  and the embedded Python;
- `BugBane-<version>-<arch>.sha256`: the SHA-256 of every file in the app as built for the release. Building the
  same tag on a Mac of the same architecture should give the same list (`scripts/repro_check.sh --manifest FILE`,
  then compare); identical results across different macOS and tool versions are not verified yet.

## Updating a dependency

```bash
scripts/deps.py outdated          # newer releases of the explicit pins, past the cooldown
scripts/deps.py bump              # write them into requirements/*.in
scripts/deps.py lock              # regenerate the locks (add --upgrade to move transitive pins too)
scripts/deps.py vet               # the gate, against origin/main
```

pymobiledevice3 drives pairing and backups, so a change to it is also tested with a full check on a real iPhone
before release. An urgent security fix may skip the cooldown through an `[[expedite]]` entry in
`requirements/vetting.toml`, after its diff has been read.

## Checking it yourself

```bash
python3.12 -m venv .venv && .venv/bin/pip install --require-hashes --only-binary :all: -r requirements/dev.txt
.venv/bin/python scripts/deps.py check        # the locks match their inputs
.venv/bin/python scripts/deps.py vet --all    # audit every locked package now
```

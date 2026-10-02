# Validation: does BugBane catch what it says it catches?

The claim we can prove is narrow and honest: **every published indicator we can replay is raised by the
right check, with the right spyware family and severity, and everyday software is not.** We prove it with
known-answer tests, not by infecting a phone. Nothing here reads from or writes to an iPhone.

## Method: known-answer replay

Every indicator in the public lists (Amnesty Tech, MVT, AssoEchap stalkerware) is a question with a known
answer: *if this value shows up in this kind of artifact, does the matching check raise it?*

`tests/replay.py` builds hand-made stand-ins for what a phone leaves behind, using only the public values:

| Indicator kind | Planted in | Check that must raise it |
|---|---|---|
| App ID | app list | apps |
| Process name | process list, memory-pressure snapshot, restart diary, crash report | processes, jetsam, shutdown, crashes |
| File path (a directory indicator: a file inside it) | process list, restart diary, crash report, system log | processes, shutdown, crashes, logs |
| File name | process list, restart diary, crash report | processes, shutdown, crashes |
| Domain (and `www.` of it) | Firefox history inside a decrypted backup | browsers |

It runs the real check functions over them and compares the result with the answer key: found, family name,
level (mercenary spyware = alert, a stalkerware maker's website alone = "worth a look").
Negative controls check that everyday things raise nothing: Apple daemons (including the one that once looked
like Pegasus's `updaterd`), popular websites, and look-alike domains (`notevil.example`, `evil.example.invalid`).

Two safety nets keep the harness honest: a test that **breaks a matcher on purpose** and expects the miss to
show up, and a **coverage matrix** that fails if a new kind of indicator is added without a replay.

## How to run

```bash
.venv/bin/pytest -q tests/test_replay.py        # synthetic answer key always; live sweep if feeds are downloaded
.venv/bin/python scripts/detection_report.py     # readable table over the real lists; add --markdown for docs
```

Locally the live sweep uses the lists `./setup.sh` downloaded, in MVT's data folder (`$MVT_DATA_FOLDER`, else
`~/Library/Application Support/mvt` on a Mac or `~/.local/share/mvt` on Linux; `scan/iocs.py` follows MVT's rule).

In CI, the **Detection replay** job downloads the lists with the app's own verified downloader (strict: a refused,
shrunken or failed list fails the run) on every push and pull request and
**daily** (the lists change without any commit here), replays all of them, and writes the table to the run's
summary page. It sets `BUGBANE_REQUIRE_LIVE_FEEDS=1`, so a failed download fails the run instead of skipping.

## Result: 2026-09-30 (7,362 indicators, 19 lists, MVT 2026.9.21)

- **7,362 replayed, 7,362 caught, 0 missed.** All 6,538 domains, 678 app IDs, 82 process names, 49 file paths
  (4 of them directories) and 15 file names, through every check that should raise them.
- Everyday controls: no alerts or warnings for standard iOS daemons; none of 16 popular sites is on a list;
  look-alike domains and folders (`notevil.example`, `/private/var/tmp/icloud_dump2/`) are not matched.
- The first run (before directory matching) caught 7,358 and could not replay the 4 directories; closing
  that gap is the only matching change the harness has driven so far.

## What this does not prove

- **Unknown or unpublished threats.** Only known indicators can be matched. A clean result means *no known
  spyware was found*, never "safe".
- **That a real infection leaves these traces on a real phone.** The replay trusts the lists' authors that
  the values appear in the artifacts we read. Real-device runs (below) check the plumbing, not the lists.
- **MVT's own parsing.** We test how we grade what MVT reports, not MVT's reading of messages or Safari data.
- **The log-archive query.** `log show` is mocked in the replay (we check the search terms and our reading of
  its output); the query itself only runs on real sysdiagnose archives.

## Known gaps

1. Directory indicators are matched in the process list, restart diary and crash reports, but not in the
   system-log search: `/private/var/logs/keybagd/` (Predator) appears in healthy logs, so directories stay out
   of that search on purpose. `/private/var/tmp/icloud_dump` is covered there by the DarkSword log markers.

## Closed gaps

- **Live sweep in CI (2026-09-30).** The loader now finds MVT's folder on Linux too; see "How to run".
- **Directory indicators (2026-09-30).** Paths ending in `/` now match anything inside them, on a path-component
  boundary (`/a/dir/` matches `/a/dir/x`, never `/a/dir2/x`), deepest directory first so the right family is
  named. Only folders at least four levels deep are prefix-matched; a broad one like `/private/var/tmp/` would
  flag everything iOS keeps there, so it still matches only exactly. Before, a process running from
  `…/fud.appex/` (QuaDream KingSpawn) raised a generic "implant folder" alert without the family.

## Real-device runs

The same checks run on real captures every time the app runs on a real iPhone. Full checks on real devices
(iOS 18, 26 and 27) confirm the path from a phone to the checks, and their gradings agree with the replay's.
None of this needs anything harmful on a phone, and raw captures from real devices never enter the repository
(see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## Per-iOS-release fixtures

Apple moves forensic artifacts between iOS versions, so a check that reads iOS 27's layout can quietly read
nothing on the next release and return a clean result because it looked at nothing. `tests/ios_fixtures.py`
pins the layout we expect per release; `tests/test_ios_fixtures.py` plants a known implant in each artifact
and confirms the real check still catches it, per release.

Covered so far (each profile records whether it was `observed` on a real device or `reported` from published
research and Apple's notes; nothing about a future iOS is invented):

| Release line | Restart diary | Notes |
|---|---|---|
| iOS 26.1 | `shutdown.log`, overwritten on reboot (one boot cycle) | reported |
| iOS 26.5 | `shutdown.log`, appended (many cycles); pathless daemons resolved via taskinfo→spindump | observed |
| iOS 27.0 | `Extra/shutdown.0.log`; same pathless-daemon resolution | observed (full run) |

The tests check three things per release: the restart diary is found and an implant client in it is flagged
(right file name, right boot-cycle count); daemons ps.txt lists without a path resolve through the UUID chain,
so an implant hiding the same way is still caught; and no sysdiagnose-based check skips for a "layout not
found" reason on a complete capture. A meta-test asserts every difference listed under *iOS artifact notes*
below is encoded in at least one profile.

### iOS artifact notes

- `shutdown.log` is overwritten on reboot in iOS 26.0–26.1 and appended again from 26.2. On iOS 27 it is
  `Extra/shutdown.0.log`.
- `ps.txt` lists some daemons without a path (`assetsd`, `cloudphotod`, `rtadvd`). They are resolved through the
  `taskinfo` executable UUID to the path in `spindump-nosymbols.txt`.
- About 30 Apple apps (Safari, Mail, Messages, Camera and others) live in `/var/containers/Bundle/Application` on
  iOS 27. That is normal and not flagged.
- Safari's `History.db` is not in iOS 27 backups (0 rows). Firefox history is in `places.db`, which MVT doesn't
  read, so `check_browser_history` covers it.
- The latest iOS for a model comes from Apple's catalogue at `gdmf.apple.com/v2/pmv`. The whole catalogue is
  fetched and filtered locally, so the model is never sent. It chains to Apple Root CA, which is not in the
  certificate list an embedded Python uses, so `app/scan/apple_roots.pem` is trusted for that request.

## Extending it

- **New iOS release:** add a `Profile` to `tests/ios_fixtures.py` for the artifacts whose format changed (set
  its `source` to `observed` or `reported`); the meta-test and the per-profile tests then cover it. Add a new
  builder there only if the release introduces an artifact shape the current ones can't express.
- **New kind of indicator:** add the table to `KIND_CHECKS` and a replay; the coverage test fails until you do.
- **Recording a gap:** add a test for the wanted behaviour marked `xfail(strict=True)`; when the gap is fixed the
  test starts passing, strict mode fails the run, and you remove the marker.

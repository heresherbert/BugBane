# Changelog

## 0.68 (2026-10-02)

First public release.

### Added

- **Self-contained app.** `BugBane.app` carries its own Python 3.12 (python-build-standalone, SHA-256 pinned in
  `requirements/runtime.txt`) with pymobiledevice3 and MVT, so running it needs no Homebrew, setup or Terminal.
  The bundle is never written to; data lives in `~/Library/Application Support/Bugbane`. Apple silicon for now.
- **Clean installs.** `install.sh` builds in a temporary folder, finds every other copy of the app by bundle ID
  and name, moves strays to the Trash and leaves exactly one in `~/Applications`. History is kept.
- **Crash-safe backup encryption.** The temporary backup password is saved in the macOS Keychain before the
  phone is changed. After an interrupted check, a card offers to switch encryption back off, including before
  the consent step (the phone is matched by its USB identifier; nothing is read from it). A timeout is reported
  separately from other failures, with retry guidance.
- **Known-answer detection tests.** Every public indicator is planted in hand-made artifacts and replayed
  through the checks (`tests/replay.py`, `scripts/detection_report.py`, [docs/VALIDATION.md](docs/VALIDATION.md)):
  7,362 of 7,362 caught, with negative controls for everyday software and look-alike domains. CI replays the
  live indicator lists on every push and daily.
- **Per-iOS-release fixtures** pin the forensic-artifact layout per iOS line (restart-diary name and behaviour,
  pathless-daemon resolution), so an iOS format change breaks a test before it can produce an empty result.
- **Support log**, shown in plain text before it is saved, with names, identifiers, paths, email addresses and
  the launch token removed.
- Time estimate for the full check based on the phone's used storage, and a "before you start" checklist.
- The Mac stays awake during a check; an unplugged iPhone ends the backup with a clear message.

### Changed

- **New interface.** A calm, dark examination record: a step rail and a fixed action bar; results read as one
  record (verdict, the findings behind it, a summary label, next steps, every check). Each finding level has one
  name, colour and shape everywhere (Needs an expert, Worth a look, Good to know, No matches, Not checked), and
  a clean result is never shown in green. English and Hungarian copy rewritten to be plain and conclusion-first.
- **Safer advice.** Monitoring-app findings no longer suggest removing the app without warning that removal can
  alert whoever installed it. The consent screen now discloses the temporary backup encryption.
- **Name and identity.** The app is spelled **BugBane**, with a new logo (a fine-tooth comb) and app icon.
  Colours, spacing and radii come from `app/ui/tokens.css`.
- **Printable report** matches the results screen: dark on screen, ink on white when printed, level shapes,
  model name and method. It embeds Latin and Hungarian subsets of Newsreader and IBM Plex (the Plex subsets
  renamed as their licence requires), so a saved report loads nothing from the network.
- Directory indicators match files inside the folder on a path-component boundary.
- Monitoring-app makers with everyday products are named in browsing-hit explanations, and the same maker is
  reported once across checks.
- Before consent, the app no longer opens a session with a connected iPhone.

### Fixed

- A prompt can no longer be hidden by opening How it works or History.
- Stop, Erase and Delete confirm in the page instead of `window.confirm()`, which returns false in a WKWebView.
- Screen readers get a status region and an alert region instead of hearing the whole screen every second;
  focus moves to each new screen's heading; contrast of buttons and labels.
- The iOS-update check works in the bundled app: Apple's catalogue chains to Apple Root CA, now shipped in
  `app/scan/apple_roots.pem`.
- A check with nothing to examine (for example no Firefox or Chrome history) no longer makes a result
  "partial", and partial results explain the actual reason.
- A phone with only Apple's apps says so instead of "0 apps checked".

## 0.2.0 (pre-release, not published)

The first internal pre-release.

- Local web UI (HU/EN) with language picker, plain-language walkthrough, privacy screen with explicit
  consent, guided connect / Trust / passcode steps, live progress, results, and History
- Checks: apps (sideloaded, TestFlight, Screen Time, remote-access, known stalkerware), profiles and MDM,
  VPN/DNS/filters, running processes, Jetsam snapshots, shutdown.log, crash patterns, unified-log
  markers (DarkSword/Coruna), MVT backup analysis, Firefox history, iOS version
- Exact-match indicator engine over MVT's STIX2 feeds; explains shared-analytics-domain false positives
  instead of alarming
- Database-only encrypted backup that works when the Mac has far less free space than iOS asks for;
  passcode-prompt handling with automatic retries
- Privacy: local-only server with token and CSP, raw data erased after analysis, on stop and on quit
  (plus a sweep at the next start), results-only History, anonymous consent log, "forget this iPhone"
  on finish, temporary backup encryption switched back off
- Installer: runtime in `~/Library/Application Support/Bugbane`, app in `~/Applications`

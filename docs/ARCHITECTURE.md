# Architecture

```
 Browser (UI, HU/EN)  ──HTTP 127.0.0.1 + token──▶  app/server.py  ──▶  scan/pipeline.py (ScanSession)
   app/ui/*                                            │                  │
                                                       │                  ├─▶ helpers/device_helper.py ──▶ pymobiledevice3 ──USB──▶ iPhone
                                                       │                  ├─▶ helpers/filtered_backup.py (database-only backup)
                                                       │                  ├─▶ helpers/partial_decrypt.py (iphone_backup_decrypt)
                                                       │                  ├─▶ mvt-ios check-backup (separate process)
                                                       │                  └─▶ scan/checks.py + scan/iocs.py (own checks)
                                                       └─▶ scan/report.py (HTML rendered on demand)
```

## Processes and environments

- **Server** (`app/server.py`) runs in the pymobiledevice3 environment (`<tools>/pmd3`) and uses only the
  standard library itself. It binds to `127.0.0.1` and prefers port 17651.
- **Device helper** (`app/helpers/device_helper.py`) is a short-lived subprocess per call. It speaks
  JSON on stdout: `usb`, `devices`, `status`, `pair`, `encryption on|off` (password from
  `BUGBANE_PW`, never argv), `sysdiag-ls`, `pull`, `forget`.
- **MVT** runs from its own environment (`<tools>/mvt`) as a separate program, with update checks disabled.
- **Where things live** (`app/scan/paths.py`): `<tools>` is `.tools/` (setup.sh virtualenvs) in a checkout
  and `runtime/` inside the app bundle; both have the shape `<env>/bin/python` + console scripts. Data
  (`run/`, `history/`, `evidence/`) is in the checkout, or in `~/Library/Application Support/Bugbane` when
  running from the bundle (`BUGBANE_DATA` overrides).

## App bundle

`scripts/build_app.sh` builds `BugBane.app` (`install.sh` builds it and copies it to `~/Applications`):

```
BugBane.app/Contents/
  MacOS/launcher            starts runtime/pmd3/bin/python app/server.py, or reopens the running one
  Resources/app/            the app code (precompiled)
  Resources/runtime/python/ embedded CPython 3.12 (python-build-standalone, SHA-256 pinned in
                            requirements/runtime.txt), relocatable, own OpenSSL and SQLite
  Resources/runtime/pmd3|mvt/site/   the two tool environments (pip --target, pinned requirements)
  Resources/runtime/pmd3|mvt/bin/    small sh launchers: python, pymobiledevice3, mvt, mvt-ios
```

- **Read-only once signed.** The launchers set `PYTHONDONTWRITEBYTECODE=1` (everything is precompiled at
  build time) and ignore the user's Python settings; data goes to Application Support. The build ends by
  smoke-testing the bundle and re-verifying the signature, which fails if anything wrote into it.
- **No absolute paths.** Launchers find the interpreter relative to themselves, so the app works wherever it
  is copied; bytecode stores relative source paths, so tracebacks never show the build machine's folders.
- **Architecture:** built for the building Mac's CPU, so an Intel build needs an Intel Mac or CI runner.
- **Signing:** ad-hoc; the app is not yet signed with a Developer ID or notarized. The launcher is a shell
  script that starts the local server and opens the UI in the browser.

## Scan lifecycle

`connect → trust → ready → running → done`, driven by `ScanSession`:

1. **Consent** (`act: consent`) is required before the app asks any phone to trust the Mac. It
   writes an anonymous line to `run/consent-log.csv`.
2. **Device watch:** a cheap USB list (`usb`) every 1.5 s. Before consent that's all: no lockdown
   session, so nothing is read from any phone. The full lockdown query (`devices`, `status`) runs
   only after consent and when something changes, and it takes two empty polls in a row to count as
   "unplugged".
3. **Steps:** `prepare` (indicators ≤ 24 h old, space check) → `apps` (app list and profiles) →
   `crashes` → `sysdiagnose` (the user presses three buttons; the app polls `DiagnosticLogs/sysdiagnose`
   for `IN_PROGRESS_*` and the new archive) → `backup` (starts as soon as the snapshot is detected, in
   parallel) → `decrypt` → `analyze` → `report`. The unified-log search (several minutes of
   `log show`) starts as soon as the snapshot is unpacked, so it overlaps the backup.
4. **Backup:** if the phone's backups aren't encrypted, the app turns encryption on with a throwaway
   password and turns it back off after analysis. The password is saved first (`scan/recovery.py`, see
   "Temporary backup password" below), so a crash can't strand it. The Mac is kept awake with
   `caffeinate` for the whole check. If a backup attempt fails and the iPhone is no longer on USB,
   the step ends with "reconnect and start again" instead of retrying. `filtered_backup.py` keeps only
   `*.db|sqlite|plist|storedata|kvstore` files, and tells iOS there's ample space: iOS otherwise
   demands room for a *full* backup, counting clones at full size (150 GB for a phone using 47 GB).
   The pipeline itself stops the backup if real free space drops below 3 GB. A passcode prompt shows
   a card in the UI, and a dropped connection is retried up to 3 times.
5. **Results** are stored as translation keys plus parameters, so they can be shown or re-rendered in
   either language later (History, reports).

## Data lifecycle

| Data | Location | Lifetime |
|---|---|---|
| Raw phone data (apps list, crash logs, sysdiagnose, backup, decrypted DBs, MVT output) | `<data>/evidence/<case>/` (0700) | erased after analysis (encrypted backup right after decryption); on Stop, Quit or Finish; swept at next start. Kept only if the user chooses "keep for an expert" (`.keep`), and then erasable from History |
| Backup password (the user's own) | process memory; env var for the decrypt subprocess | forgotten at the end of the check |
| Temporary backup password (ours) | login Keychain, service "BugBane temporary backup password", account = hashed UDID; `run/restore-pending.json` lists hashed id, model and date | deleted as soon as the phone confirms encryption is off, or when the user dismisses the reminder |
| Results | memory; `<data>/history/<id>.json` (0600) only if the user opts in | until deleted in History |
| Report | rendered per request, streamed to the browser | never written by the app |
| Consent log | `<data>/run/consent-log.csv` | anonymous, no device data |
| Pairing | macOS usbmuxd and `~/.pymobiledevice3` | removed on Finish ("forget this iPhone") |

## Temporary backup password

`scan/recovery.py` keeps the one piece of state that must survive a crash: the password BugBane set
on a phone whose backups weren't encrypted.
- It's written to the Keychain (secret on stdin to `/usr/bin/security`, never argv) **before**
  `encryption on`. If that write fails, the backup part is skipped and the phone is left untouched.
- It's dropped only when `encryption off` reports `encrypted: false`, or when the phone already
  reports encryption off on connect (fixed in Finder or by Reset All Settings).
- While a record exists, the UI shows a restore card (welcome, connect, ready and results screens):
  *Switch it back now* when that iPhone is connected, instructions otherwise, plus manual fixes
  (Keychain Access + Finder, or Reset All Settings) and *I've already fixed this*.
- A new check on that phone reuses the saved password (no password prompt) and switches encryption
  off at its end, in quick mode too.

## Local server hardening

- Every API call requires the per-launch token (in the `X-Token` header, or `?t=` for report links).
- The `Host` header must be `127.0.0.1` or `localhost` (DNS-rebinding protection).
- Security headers: CSP `default-src 'self'`, no external assets, `frame-ancestors 'none'`, `no-store`,
  and `Referrer-Policy: no-referrer`.
- Request logging is off.

## Internationalisation

`app/i18n/{en,hu}.json` is the single source for the UI, the checks and the report. Parameters can be
plain values, `{"t": key}` (a nested translation), `{"d": ts}` / `{"dt": ts}` (a localized date), or
lists. Hungarian uses `2026. szept. 23.` dates and groups numbers from five digits up.

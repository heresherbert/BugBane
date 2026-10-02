# Third-party software and data

BugBane is licensed under **GPL-3.0-or-later** (see [LICENSE](LICENSE)). The repository does not
vendor third-party code; it does carry subsets of three open-licensed fonts (next-but-one section). For development, `setup.sh` installs the packages below into local virtual
environments (`.tools/`). The app bundle (`scripts/build_app.sh`) **redistributes** them, together with
an embedded Python (next section), all pinned in `requirements/`.

| Component | Used for | How it's used | License |
|---|---|---|---|
| [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) 11.17.0 | USB pairing, backup, crash reports, sysdiagnose | imported in-process by `app/helpers/device_helper.py` and `app/helpers/filtered_backup.py` | GPL-3.0 |
| [Mobile Verification Toolkit (MVT)](https://github.com/mvt-project/mvt) 2026.9.28 | backup analysis, indicator download | run as a **separate program** (`mvt`, `mvt-ios`) | MVT License 1.1 (MPL-2.0-based, adds a consent requirement) |
| [iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt) 0.10.0 (installed with MVT) | decrypting backup files | imported by `app/helpers/partial_decrypt.py` | MIT |

## Embedded Python (app bundle only)

`BugBane.app` embeds CPython 3.12 from [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
(pinned with SHA-256 in `requirements/runtime.conf`). The build scripts are MPL-2.0; CPython is under the
PSF License (its `LICENSE.txt`, which also covers components CPython itself includes, ships inside the
bundle at `runtime/python/lib/python3.12/LICENSE.txt`). The runtime statically links third-party libraries
such as OpenSSL (Apache-2.0), SQLite (public domain), libffi (MIT), XZ, bzip2, expat and mpdecimal (permissive
licences). It is built against libedit instead of GNU readline, and without GDBM, so it carries no GPL
components of its own. Tkinter/Tcl/Tk and pip are removed from the bundle.

**Before public distribution:** copy the full licence texts from the matching python-build-standalone
*full* archive into the bundle.

## Fonts (bundled in `app/fonts/`)

The printable report embeds subsets (Latin and Hungarian) of three typefaces from
[google/fonts](https://github.com/google/fonts), at pinned commits with SHA-256 checks
(`scripts/brand_assets.py`). Each licence ships next to the font files.

| Typeface | Copyright | License |
|---|---|---|
| Newsreader | The Newsreader Project Authors (Production Type) | SIL Open Font License 1.1 (`app/fonts/OFL-Newsreader.txt`) |
| IBM Plex Sans | IBM Corp. | SIL Open Font License 1.1 (`app/fonts/OFL-IBMPlexSans.txt`) |
| IBM Plex Mono | IBM Corp. | SIL Open Font License 1.1 (`app/fonts/OFL-IBMPlexMono.txt`) |

The subsets are Modified Versions under the OFL. IBM declares "Plex" a Reserved Font Name, so the Plex
subsets are renamed **BugBane Sans** (`BugBaneSans.woff2`) and **BugBane Mono** (`BugBaneMono-Regular.woff2`);
their copyright and licence notices are unchanged. Newsreader declares no reserved name and keeps its own.
The logo's wordmark is outlined from Newsreader, which the OFL permits for artwork.

## MVT License 1.1 consent condition

MVT may only be used with the **explicit, informed, uncoerced consent of the data owner**.
BugBane enforces a consent step before any data is read (`privacy.c.own` / `privacy.c.process`
in the UI). Keep it that way in any fork.

## Indicator data (downloaded at runtime, not redistributed)

`mvt download-iocs` fetches STIX2 indicator bundles into `~/Library/Application Support/mvt/indicators`.
Their sources and terms differ:

| Source | Terms |
|---|---|
| [mvt-project/mvt-indicators](https://github.com/mvt-project/mvt-indicators) | MIT (index) |
| [AmnestyTech/investigations](https://github.com/AmnestyTech/investigations) | no license file: don't bundle or redistribute without permission |
| [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | CC-BY (attribution) |

## Online services

`gdmf.apple.com/v2/pmv` (Apple's public iOS version catalogue) is downloaded whole and filtered
locally, so no device information is sent.

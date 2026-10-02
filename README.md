<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/lockup-on-dark.svg">
    <img src="assets/brand/lockup.svg" alt="BugBane" height="56">
  </picture>
</h1>

**Find out whether known spyware is on your iPhone, without your data ever leaving your Mac.**

BugBane is a private, local spyware check for people who aren't security experts. It compares the
phone's own records against thousands of public spyware indicators: Pegasus, Predator, Operation
Triangulation, the 2026 DarkSword and Coruna kits, and commercial stalkerware. Then it explains the
result in plain English or Hungarian.

**Connect, check, explain.**

1. **Connect** your iPhone to your Mac with a cable, and tap *Trust*.
2. **Check:** BugBane reads the phone's own records and compares them with known spyware
   fingerprints.
3. **Explain:** you get a plain-language result, what it means, and what to do next.

## Why you can trust it

- **Open source.** Every line is in this repository. You can read it, and you can build it yourself.
- **Nothing leaves your Mac.** No accounts, no cloud, no analytics. The raw copy of the phone is
  erased after the check, and the Mac "forgets" the iPhone at the end.
- **Exact matching against public indicators.** Findings come from published indicator lists
  (see [docs/DETECTION.md](docs/DETECTION.md)), never from guesswork. The report shows why each
  finding was raised.
- **Honest limits.** A clean result means *no known spyware was found*. We never call a phone "safe".
- **Built on researchers' tools.** It uses the open-source
  [Mobile Verification Toolkit](https://github.com/mvt-project/mvt), developed by Amnesty
  International's Security Lab, and [pymobiledevice3](https://github.com/doronz88/pymobiledevice3).
  Neither project endorses BugBane.

> **Status: pre-1.0 (0.70).** Full checks have run end to end in the installed app on an iPhone 13
> (iOS 27.0, encrypted backups) and an iPhone XS (iOS 18.7, unencrypted backups), and every capture step
> was exercised on real devices (iOS 18, 26.5 and 27.0). The app isn't signed or notarized yet. See
> [CHANGELOG.md](CHANGELOG.md).

## What it checks

| Check | Source on the phone |
|---|---|
| Installed apps: sideloaded, TestFlight, Screen Time and remote-access apps, known stalkerware | app list (lockdown) |
| Configuration profiles and MDM | profile list |
| VPNs, DNS proxies, content filters | sysdiagnose network configuration |
| Running programs vs. spyware names and implant folders | sysdiagnose `ps`, stackshots |
| Programs seen in the last days | Jetsam memory reports |
| Restart diary (the "shutdown.log" Pegasus method) | sysdiagnose |
| Exploit-kit crash patterns | crash reports |
| DarkSword/Coruna markers and indicator files | unified system log |
| Links in messages, websites, per-app network use, permissions | encrypted, **database-only** backup → [MVT](https://github.com/mvt-project/mvt) |
| Firefox history (MVT doesn't read the current format) | backup |
| iOS up to date | Apple's public catalogue |

**Limits.** A clean result means *no known spyware was found*, not that the phone is guaranteed
safe. Brand-new spyware without published indicators can be missed, and memory-only implants
vanish when the phone restarts. The app says this plainly to the user. See
[docs/DETECTION.md](docs/DETECTION.md).

## Requirements

- macOS 13+ (the app bundle is currently built for Apple silicon; Intel builds need an Intel Mac)
- An iPhone with a data-capable cable, its passcode, and its backup password if one was ever set

The app carries its own Python: no Homebrew, no Terminal and no setup are needed to run it.

## Install (build from source)

```bash
git clone https://github.com/heresherbert/BugBane.git && cd BugBane
./install.sh
```

This builds a self-contained `BugBane.app` (about 1–2 minutes, needs an internet connection and the Xcode
command-line tools for the icon) and installs it to `~/Applications`, replacing the previous version. Any other
copy of BugBane it finds on the Mac (older builds, older names) goes to the Trash, so exactly one is left. Your
data (History, run state) lives in `~/Library/Application Support/Bugbane` and is kept across updates. To only build it:
`scripts/build_app.sh` → `build/BugBane.app`.

For development, you can run straight from the checkout:

```bash
./setup.sh                                          # creates .tools/ venvs (Homebrew Python 3.12)
.tools/pmd3/bin/python app/server.py                # opens the UI in your browser
```

## Using it

1. Choose a language, then read and accept the privacy terms (both consents are required; History is optional).
2. Connect the iPhone, tap **Trust** and enter the passcode.
3. Choose a **Full** check or a **Quick** check (10–15 min). The full check took 17 minutes on an iPhone 13
   with 40 GB in use; the app shows an estimate for the connected phone.
4. When asked, press **Volume Up + Volume Down + Side** together for about 1 second (diagnostic
   snapshot), and enter the **passcode on the iPhone** when it asks for the backup.
5. Read the results, save or print the report, then **Finish**. If anything collected from the phone is still
   on the Mac, the button says **Finish and erase**.

## Privacy model

- Local only: the UI is served on `127.0.0.1` with a per-launch token, a strict CSP and no external assets.
- The only network calls download public indicator lists (MVT) and Apple's public iOS catalogue, and ask GitHub
  whether a newer BugBane is released. Nothing about you, the Mac or the phone is sent.
- Each time the app opens it refreshes indicator lists older than a day, so new spyware fingerprints arrive
  without an app update.
- Raw data is erased after the analysis, on Stop and on Quit, and swept at the next launch if the app crashed.
- History stores **results only**, only on opt-in, and every entry can be deleted.
- The consent log is anonymous (time, versions, language).
- Backups are **database-only**: photos and videos never reach the disk.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Brand

The logo is **Fine-tooth**, a comb: BugBane goes over a phone's records with a fine-tooth comb. The logo,
lockups and app icon in `assets/brand/`, and the report's font subsets in `app/fonts/`, are generated by
`scripts/brand_assets.py`; change them there rather than by hand. Colours, spacing and radii are in
`app/ui/tokens.css`. Please don't use the BugBane name or logo for modified versions in a way that suggests
they are the official app.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please **never** attach reports, logs or anything from a
real phone to an issue. Security problems: [SECURITY.md](SECURITY.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
(MVT's consent condition applies).

Only check a phone that is yours, or with its owner's explicit consent.

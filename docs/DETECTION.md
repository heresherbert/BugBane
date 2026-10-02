# Detection methods and limits

## Indicators

`app/helpers/fetch_indicators.py` downloads MVT's STIX2 feeds and verifies them before use (see
[SUPPLY-CHAIN.md](SUPPLY-CHAIN.md#threat-data)): Pegasus, Predator, RCS Lab, Quadream, Operation
Triangulation, Candiru, Cellebrite, NoviSpy, Coruna, DarkSword and more, plus ECHAP's
stalkerware/watchware list). `scan/iocs.py` indexes them with **exact** matching:

- process and file names: whole basename only
- file paths: the whole path; a directory indicator (ending in `/`) also matches anything inside it, on a
  path-component boundary (`/private/var/tmp/icloud_dump/` matches `/private/var/tmp/icloud_dump/x`, never
  `/private/var/tmp/icloud_dump2/x`)
- domains: the host or any parent domain on a label boundary (`evil.com` matches `cdn.evil.com`, never
  `notevil.com`)
- values shorter than 3 characters are ignored

Hits are graded by *category* and *where they were seen*:

| Hit | Level |
|---|---|
| Mercenary spyware indicator, anywhere | alert (with a message-specific text if seen in SMS/iMessage) |
| Stalkerware or watchware domain seen only in **browsing data**, and the vendor's app isn't installed | warn ("a website of a company that makes monitoring apps loaded") |
| Stalkerware indicator elsewhere, or the vendor's app is installed | alert |

**Example.** The FamiSafe (Wondershare) entry lists Wondershare's analytics domain `300624.com`, which
Wondershare's other web tools also load. Anyone who used one of those websites gets a hit without
having FamiSafe. Shared corporate analytics domains are the most common false positive in stalkerware
feeds, so the report says so instead of raising an alarm.

## Checks

| Check | Data | Flags |
|---|---|---|
| Apps | lockdown app list | App Store signer ≠ Apple; TestFlight; Screen Time (FamilyControls); VPN or network extension; remote-access apps; bundle IDs in stalkerware feeds |
| Profiles | profile list | any configuration profile or MDM |
| Network | sysdiagnose `com.apple.networkextension.plist` (NSKeyedArchiver) | always-on VPN, content filter, DNS proxy, URL filter, relay, profile-installed configs |
| Processes | sysdiagnose `ps.txt` + `taskinfo`/`spindump` UUID → path | indicator names; binaries in implant folders (`/private/var/db`, `/private/var/tmp`, …); non-standard paths |
| Jetsam | `JetsamEvent*.ips` | indicator process names over the past days |
| shutdown.log | sysdiagnose `Extra/shutdown*.log` | indicator names or non-standard paths among processes that delayed a restart |
| Crashes | `.ips` reports | WebKit `EXC_ARM_DA_ALIGN` and `mediaplaybackd` `CPU_RESOURCE` (DarkSword); ≥3 messaging/web/media crashes within an hour; crashes from implant paths |
| Unified logs | `system_logs.logarchive` via `/usr/bin/log show --predicate` | published DarkSword/Coruna strings; indicator file paths under `/tmp` and `/private/var/tmp` |
| MVT | database-only backup | all MVT backup modules |
| Firefox | `places.db` from the backup | indicator domains (MVT only reads the legacy `browser.db`) |
| iOS | `gdmf.apple.com` catalogue | newer iOS available for this model |

## Known limits

- **Unknown spyware:** new implants without published indicators can only show up through the
  heuristics (odd paths, crash bursts, log markers).
- **Restarts** remove memory-only implants and most of their traces. On iOS 26.0–26.1 a restart also
  overwrote `shutdown.log` (fixed in 26.2).
- **Safari history** isn't in iOS 27 backups; WebKit resource statistics are still checked.
- **Accounts:** someone with the Apple Account password can read iCloud data without touching the
  phone. The results screen points users to Safety Check and a password change.
- **Backups need the owner:** iOS asks for the passcode on the phone before a backup, and it drops the
  connection if nobody answers.
- On iOS 27 about 30 Apple apps (Safari, Mail, Messages, Camera…) live in
  `/var/containers/Bundle/Application`. That's normal, not a sign of tampering.

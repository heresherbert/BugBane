# Contributing

Thanks for helping make iPhone spyware checks accessible to everyone.

## Ground rules

1. **No real phone data, anywhere.** Not in issues, PRs, tests or screenshots. Build fixtures by hand
   (see `tests/`). Redact device names, UDIDs, app lists and domains from any log you share.
2. **Privacy promises are features.** A change that uploads data, keeps it longer, or weakens the
   consent step will not be merged. If a change affects what the UI promises, update both
   translations of the promise in the same PR.
3. **Honest results.** Never phrase a clean result as "safe". Every new finding needs a plain-language
   explanation (what we saw, why it matters, what to do) in **both** `app/i18n/en.json` and
   `app/i18n/hu.json`.
4. **Exact indicator matching.** Match whole process names and whole domain labels; substring matches
   caused a false Pegasus hit (`updaterd` inside Apple's `accessoryupdaterd`).

## Development setup

```bash
./setup.sh                           # Python 3.12 venvs in .tools/, pinned deps, indicators
python3.12 -m venv .venv && .venv/bin/pip install -r requirements/dev.txt
.venv/bin/pytest                     # unit tests: no iPhone needed
.tools/pmd3/bin/python app/server.py # run the app from the checkout
```

## Translations

- Keys live in `app/i18n/{en,hu}.json` and must stay in sync (same keys, same `{placeholders}`);
  the tests enforce this.
- Hungarian: use formal address (magázás), as iOS does, and Apple's official Hungarian UI names
  („Megbízható”, *Beállítások > Általános > …*, *Zárt mód*, *Biztonsági ellenőrzés*, *jelkód*,
  *Apple-fiók*). Check them against Apple's Hungarian support pages.
- To add a language, copy `en.json`, translate it, add the code to `LANGS` in `app/scan/i18n.py`,
  and add a button to the language picker.

## Pull requests

- Keep PRs focused; describe how you tested (unit tests, and the devices and iOS versions if relevant).
- CI must pass: `pytest`, translation parity, and a JS syntax check.
- By contributing you agree that your contribution is licensed under GPL-3.0-or-later.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

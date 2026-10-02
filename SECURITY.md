# Security policy

BugBane handles highly sensitive data, so we take reports seriously.

## Reporting a vulnerability

**Don't open a public issue.** Use GitHub's private vulnerability reporting (the
*Security → Report a vulnerability* tab), or contact the maintainers privately.

Please include the affected version or commit, steps to reproduce, and the impact. **Never include
data from a real phone**: use synthetic examples.

We aim to acknowledge reports within 3 working days and to ship a fix or mitigation for serious issues
within 30 days.

## In scope

- Anything that sends phone data off the Mac, or keeps it longer than documented
- Bypassing the local server's token or Host checks, XSS in the UI or report, path traversal
- Consent-flow bypasses (checking a phone without the owner's consent)
- Detection bypasses and false negatives caused by our code (for example, indicator matching bugs)

## Out of scope

- Vulnerabilities in iOS, pymobiledevice3 or MVT themselves (report upstream)
- Spyware that has no public indicators (a known limit, documented in docs/DETECTION.md)

## If you think *your* phone is compromised

This project can't give individual help. Contact the
[Access Now Digital Security Helpline](https://www.accessnow.org/help/) (free for civil society).
If a partner or family member may be involved, contact a domestic-violence helpline first.

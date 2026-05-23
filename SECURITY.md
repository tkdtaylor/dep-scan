# Security Policy

## Supported versions

| Version | Security fixes |
|---------|---------------|
| v1.2.x (latest) | ✅ Yes |
| older than v1.2.0 | ❌ No |

Only the latest minor release receives security fixes. Upgrade to the latest
release before reporting.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
A public report exposes the flaw to everyone before a fix is available.

### Option 1 — GitHub private vulnerability reporting (preferred)

Use GitHub's built-in private advisory flow:
<https://github.com/tkdtaylor/dep-scan/security/advisories/new>

GitHub keeps the report confidential and notifies only maintainers.

### Option 2 — Email

Send a report to <tools@taylorguard.me> with:

- A concise description of the vulnerability
- Reproduction steps (command line, config, package name/version)
- Affected dep-scan version(s)
- Your assessment of severity (CVSS or plain English is fine)
- Any suggested mitigations

Encrypt with PGP if you prefer — open an issue requesting a public key and
we will publish one.

## Response expectations

- **Acknowledgement:** within 7 days of receipt.
- **Status update:** within 30 days (triaged, confirmed, or declined with
  reasoning).
- **Fix shipped:** within 90 days for confirmed vulnerabilities. Critical
  issues (CVSS ≥ 9.0) target a 14-day patch window. If more time is needed
  we will coordinate a disclosure date with the reporter.

## Scope

**In scope:**

- The `dep-scan` binary itself (all platforms)
- Embedded trust roots (sigstore CA certificates, transparency log public keys)
- The `install.sh` installer script
- Security bypass in any dep-scan policy (age, typosquatting, maintainer
  change, provenance, vulnerability, obfuscation)

**Out of scope:**

- Bugs in upstream registries (npm, PyPI, crates.io, Go checksum DB)
- Bugs in sigstore / Rekor / Fulcio infrastructure
- Bugs in OSV.dev
- Vulnerabilities in transitive Rust dependencies that have no exploitable
  path through dep-scan (report those to the upstream crate's maintainers
  and the RustSec advisory database)
- False positives / false negatives that are not exploitable — file a
  regular GitHub issue instead

## Recognition

Reporters are credited in the changelog and release notes unless they
request anonymity. We do not currently offer a bug bounty.

## Maintainer note

After merging this file, enable **Settings → Code security and analysis →
Private vulnerability reporting** in the GitHub repository settings so the
"Report a vulnerability" button is visible on the repo page.

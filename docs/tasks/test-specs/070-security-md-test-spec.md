# Test Spec — Task 070: Add SECURITY.md

## Context

dep-scan is a security tool without a documented vulnerability disclosure
policy. This task adds `SECURITY.md` at the GitHub-conventional location.

---

## Validation

### T-070-01: File exists
- `SECURITY.md` is at repo root.

### T-070-02: Contains a "Reporting" section
- A heading like "Reporting a vulnerability" exists.

### T-070-03: Contains a contact channel
- The contact email `tools@taylorguard.me` appears at least once.

### T-070-04: References private GitHub vulnerability reporting
- The file mentions GitHub's private vulnerability reporting (e.g. "Use
  GitHub's private vulnerability reporting flow" or a link to
  `/security/advisories/new` for the repo).

### T-070-05: Lists supported versions
- A heading like "Supported versions" exists with a table or list naming the
  current minor (v1.2.x) as the version that receives security fixes.

### T-070-06: States response SLAs
- A statement of acknowledgment and fix-window expectations exists. Suggested
  language: "We aim to acknowledge reports within 7 days and ship a fix
  within 90 days." Specific numbers are open; presence of the statement is the
  required signal.

### T-070-07: Scope is documented
- A section names what's in scope (the dep-scan binary, embedded trust roots,
  install.sh) and what's out (bugs in OSV.dev / npm / PyPI / sigstore
  themselves — those go to their projects).

### T-070-08: README links to SECURITY.md
- README.md contains a link to `SECURITY.md` (e.g. in a "Security" subsection
  or as a top-level link near the install instructions).

### T-070-09: No accidental secrets
- The file does not contain any private keys, internal hostnames, or staging
  URLs that shouldn't be public.

### T-070-10: Manual verification — private vulnerability reporting enabled
- (Not a file check.) The task file documents a checkbox that the maintainer
  enabled `Settings → Code security and analysis → Private vulnerability
  reporting` in the GitHub UI before closing the task.

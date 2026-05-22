# Test Spec — Task 077: Add CODE_OF_CONDUCT.md

## Context

This task adds Contributor Covenant 2.1 as the project's code of conduct.

---

## Validation

### T-077-01: File exists
- `CODE_OF_CONDUCT.md` is at repo root.

### T-077-02: Version 2.1
- The file contains a version indicator (e.g. "Contributor Covenant" with
  a 2.1 reference, or the canonical "## Attribution" footer naming v2.1).

### T-077-03: Project name substituted
- Any `[INSERT CONTACT METHOD]` / `[homepage]` placeholders from the
  upstream template are replaced. No literal placeholder strings remain.

### T-077-04: Contact email is tools@taylorguard.me
- The enforcement-contact email is `tools@taylorguard.me`.

### T-077-05: README links to it
- README.md has a link to `CODE_OF_CONDUCT.md`.

### T-077-06: CONTRIBUTING.md links to it (if 076 has landed)
- If `CONTRIBUTING.md` exists, it links to `CODE_OF_CONDUCT.md`.

### T-077-07: GitHub community profile detection
- After commit, the repo's `/community` page shows the code of conduct as
  present. (Manual verification step.)

### T-077-08: Text matches upstream
- The bulk of the document matches the Contributor Covenant 2.1 text from
  https://www.contributor-covenant.org/version/2/1/code_of_conduct/
  (allow for line-wrapping and contact-placeholder differences).

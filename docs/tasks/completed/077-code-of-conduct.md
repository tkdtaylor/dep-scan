# Task 077 — Add `CODE_OF_CONDUCT.md`

**Status:** backlog
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier C / Community)
**Touches:** `CODE_OF_CONDUCT.md` (new), `README.md` (link), `CONTRIBUTING.md`
(cross-link if 076 has landed)

## Objective

Adopt Contributor Covenant 2.1 as the project's code of conduct. Standard
boilerplate for OSS projects; demonstrates inclusivity expectations.

## Background

Contributor Covenant 2.1 is the de facto OSS standard. GitHub auto-detects
it and surfaces in the community profile.

The file is intentionally not customized beyond:
- The enforcement contact (use `tools@taylorguard.me`, matching SECURITY.md).
- The project name.

## Behavior

1. Download the Contributor Covenant 2.1 plain-text version from
   https://www.contributor-covenant.org/version/2/1/code_of_conduct.txt
   (verify version 2.1, not earlier).
2. Save as `CODE_OF_CONDUCT.md` at repo root.
3. Replace the enforcement-contact placeholder with `tools@taylorguard.me`.
4. Add the project name where the template expects it.
5. Link from README.md (footer or community section).
6. If task 076 has landed, link from CONTRIBUTING.md.

## Acceptance criteria

- [ ] `CODE_OF_CONDUCT.md` exists at repo root
- [ ] Contents match Contributor Covenant 2.1 (verifiable against the
      upstream text)
- [ ] Enforcement contact is `tools@taylorguard.me`
- [ ] README.md links to the file
- [ ] CONTRIBUTING.md links to the file (if 076 has landed)
- [ ] GitHub's community profile shows the code of conduct as present
      (manual verification)

## Out of scope

- Customizing the CoC text beyond the contact swap. The whole point of
  using the standard is to not reinvent it.
- Setting up a separate moderation team — single-maintainer projects use
  the contact email; if a team forms later, the file gets updated.

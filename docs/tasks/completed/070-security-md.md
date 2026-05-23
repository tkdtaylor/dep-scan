# Task 070 — Add `SECURITY.md`

**Status:** backlog
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier A #1)
**Touches:** `SECURITY.md` (new), `README.md` (link)

## Objective

Publish a security policy at the standard location (`SECURITY.md` at repo
root) so reporters know where and how to disclose vulnerabilities in
dep-scan itself.

## Background

GitHub auto-detects `SECURITY.md` and displays a "Report a vulnerability"
button on the repo page. The absence of one is awkward for a security tool —
a reporter would have to guess at email, GitHub issue, etc., and might
default to a public issue (the worst outcome for an unfixed vulnerability).

The file should cover:

1. **Where to report.** Both a private channel (private GitHub advisory) and
   a contact email.
2. **What to include.** Reproduction steps, affected versions, suggested
   severity.
3. **Supported versions.** Which release lines receive security fixes. At
   v1.2.0 the answer is "the latest minor"; if/when a v2.0 lands the policy
   may grow.
4. **Response expectations.** Realistic SLAs for ack + fix. For a
   single-maintainer project, 7-day ack / 90-day fix is honest.
5. **What's in scope.** dep-scan binary, included roots, install.sh. What's
   out: bugs in OSV.dev, npm, PyPI, sigstore — those report to their
   respective projects.
6. **Recognition.** Whether reporters are credited in the changelog (yes,
   unless they prefer anonymity).

## Behavior

1. Create `SECURITY.md` at repo root using the structure above.
2. Use the contact email tools@taylorguard.me.
3. Link from README.md — a one-line "Security policy" entry in the README or
   a footer link.
4. Enable "Private vulnerability reporting" in the repo settings (manual
   GitHub UI step — document in the task that this needs to happen, not
   automate).

## Acceptance criteria

- [ ] `SECURITY.md` exists at repo root
- [ ] File covers the six sections above
- [ ] README.md links to SECURITY.md
- [ ] Private vulnerability reporting is enabled in repo settings (manual
      verification step documented)
- [ ] Markdown renders correctly on GitHub (no broken links, valid headings)

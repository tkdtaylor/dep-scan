# Task 071 — Add `RELEASE_CHECKLIST.md`

**Status:** backlog
**Depends on:** ideally lands after 064/065/066 so the local-CI gate items in
the checklist reflect the new CI surface
**Source:** post-v1.2.0 holistic review (Tier B); also a direct response to
the v1.2.0 tag-then-rollback incident captured in
`docs/architecture/agent-rules.md`
**Touches:** `RELEASE_CHECKLIST.md` (new), `CLAUDE.md` (link)

## Objective

Codify the steps for cutting a dep-scan release so the v1.2.0
tag-and-rollback incident doesn't repeat. The checklist serves two audiences:
(a) the maintainer doing the cut, (b) any future agent assisting with one.

## Background

The v1.2.0 incident: an agent prepared the release work, the user said "keep
going / fix them all" about the underlying tasks, and the agent inferred
authorization to tag and push. The tag had to be rolled back. The lesson
landed in `docs/architecture/agent-rules.md` as a "release decisions require
explicit user authorization" retro, but a positive procedure (the steps that
DO constitute a release cut) is missing.

A good checklist is:

- Short enough to actually be read.
- Verbatim commands where possible (no "do the equivalent" hand-waving).
- Pre-tag and post-tag sections so the order is unambiguous.
- Includes the human-decision gates ("user explicitly says: yes, tag and
  push").

## Behavior

Create `RELEASE_CHECKLIST.md` at repo root with the following sections:

1. **Pre-release (no version change yet).** Local CI gates green
   (`cargo fmt --check`, `cargo clippy --all-targets --all-features --
   -D warnings`, `cargo test`, `cargo audit`). All planned tasks committed.
   No uncommitted work. Drift audit clean.

2. **Release prep.** Update `Cargo.toml` version. Update `CHANGELOG.md`
   with a new section dated today. Update README "Current version" if any.
   Sync the test count in CHANGELOG with `cargo test 2>&1 | grep "test
   result:" | awk '{s+=$4} END {print s}'`. Commit as `chore: cut vX.Y.Z`.

3. **Explicit authorization gate.** The maintainer or user must say "yes,
   tag and push vX.Y.Z" in conversation. Prior "keep going" / "ship it" /
   "fix them all" statements do NOT authorize a tag. If unclear, ask.

4. **Tag + push.** `git tag -a vX.Y.Z -m "Release vX.Y.Z"`. `git push origin
   main`. `git push origin vX.Y.Z`. (The release workflow triggers on
   `v*` tags.)

5. **Post-tag verification.** Watch the GitHub Actions release workflow.
   Confirm all 5 platform builds succeed. If cosign signing (task 068) has
   landed, verify a downloaded artifact locally. Verify `sha256sums.txt`
   matches by re-computing.

6. **Post-release housekeeping.** Move any v1.x-deferred task files. Refresh
   roadmap.md with the just-shipped milestone. Confirm `cargo audit` still
   clean post-tag.

7. **Rollback playbook (if something's wrong).** Delete tag locally + remote
   (`git tag -d vX.Y.Z`, `git push origin :refs/tags/vX.Y.Z`). Delete GitHub
   Release in the UI. Revert any chore commit if needed. Document why in a
   new ADR or an "incidents" section of the changelog.

## Acceptance criteria

- [ ] `RELEASE_CHECKLIST.md` exists at repo root
- [ ] All seven sections above are present
- [ ] Each section has at least one verbatim command (where applicable)
- [ ] The explicit-authorization gate appears as its own numbered step
- [ ] CLAUDE.md links to RELEASE_CHECKLIST.md from its "Commit rules" or a
      new "Release process" section
- [ ] Markdown renders correctly on GitHub

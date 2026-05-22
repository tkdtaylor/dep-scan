# Test Spec — Task 071: Add RELEASE_CHECKLIST.md

## Context

The v1.2.0 rollback exposed a gap: no codified release procedure existed.
Lessons landed in `docs/architecture/agent-rules.md` as retros, but a
positive checklist was missing. This task adds it.

---

## Validation

### T-071-01: File exists
- `RELEASE_CHECKLIST.md` is at repo root.

### T-071-02: Pre-release CI gate section
- A section names the four local CI gates: `cargo fmt --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test`, `cargo audit`.

### T-071-03: Release prep section
- A section instructs updating `Cargo.toml` version + `CHANGELOG.md` + test
  count. The test-count line includes the exact command:
  `cargo test 2>&1 | grep "test result:" | awk '{s+=$4} END {print s}'`.

### T-071-04: Authorization gate section
- A numbered step requires explicit user authorization ("yes, tag and push
  vX.Y.Z") and explicitly states that prior "keep going" / "ship it"
  statements do not count.

### T-071-05: Tag + push commands
- A section lists the exact commands:
  ```
  git tag -a vX.Y.Z -m "Release vX.Y.Z"
  git push origin main
  git push origin vX.Y.Z
  ```

### T-071-06: Post-tag verification section
- A section instructs watching the GitHub Actions release workflow and
  validating sha256sums (and, if 068 has landed, cosign verify).

### T-071-07: Post-release housekeeping
- A section instructs updating roadmap.md and moving any deferred task files.

### T-071-08: Rollback playbook
- A section lists the exact commands for tag deletion local + remote.

### T-071-09: CLAUDE.md links to the checklist
- CLAUDE.md "Commit rules" or a new "Release process" section links to
  `RELEASE_CHECKLIST.md`.

### T-071-10: Cross-reference to agent-rules retro
- The release-checklist file links back to `docs/architecture/agent-rules.md`
  for the "why" behind the explicit-authorization gate.

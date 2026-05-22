# Test Spec — Task 076: Add CONTRIBUTING.md

## Context

External contributors have no documented workflow today. This task adds
`CONTRIBUTING.md`.

---

## Validation

### T-076-01: File exists
- `CONTRIBUTING.md` is at repo root.

### T-076-02: Quick-start section present
- A heading like "Quick start" or "Getting started" exists with clone +
  cargo test instructions.

### T-076-03: Lists all four local CI gates
- The exact commands appear:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test`
  - `cargo audit`

### T-076-04: States MSRV
- Mentions Rust 1.88+ (matching `Cargo.toml`).

### T-076-05: Documents test-spec-first rule
- A section names the rule and points at `docs/tasks/test-specs/`.

### T-076-06: Documents commit-message conventions
- Mentions the `feat:` / `test:` / `docs:` / `fix:` prefix pattern and the
  "one task, one commit" rule.

### T-076-07: Links to SECURITY.md
- A section directs security reports to `SECURITY.md` (not public issues).

### T-076-08: Process for new features
- A section explains opening an issue first / waiting for acceptance.

### T-076-09: README links to CONTRIBUTING.md
- README.md has a link to `CONTRIBUTING.md`.

### T-076-10: GitHub-detected
- After commit, the repo's PR creation flow shows the "Contributing
  guidelines" link. (Manual verification step; document in the task.)

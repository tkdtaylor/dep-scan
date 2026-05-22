# Test Spec — Task 073: Remove scaffold leftovers

## Context

`requirements.txt` (Python deps) and `.env.example` (Anthropic + Git tokens)
at the repo root are vestigial from the Docker dev-container scaffold and
have no role in the dep-scan binary. Task removes or relocates them.

---

## Validation

The task offers two approaches (delete vs relocate). Validation supports
either outcome.

### T-073-01: Root no longer has the stale files
- `ls requirements.txt .env.example 2>/dev/null` returns nothing.

### T-073-02 (if Approach A): Files are truly removed
- `git status` after the change shows the files as deleted (or already
  committed deleted).

### T-073-03 (if Approach B): Files moved under .devcontainer/
- `.devcontainer/requirements.txt` and `.devcontainer/.env.example` exist
  with the same content as the originals.

### T-073-04: CLAUDE.md updated
- Either:
  - The "Docker (run from host…)" block has been removed entirely, OR
  - The block carries a "Note: this workflow is currently aspirational"
    preamble, OR
  - The block references the new `.devcontainer/` paths (if Approach B).

### T-073-05: No stale references remain
- `grep -rn "requirements.txt\|\\.env\\.example" docs/ README.md
  CLAUDE.md .github/ 2>/dev/null` returns either zero matches OR only
  matches that point to the new `.devcontainer/` location.

### T-073-06: `.gitignore` still protects `.env`
- The line `^\.env$` (or `.env`) still appears in `.gitignore`.

### T-073-07: cargo build still succeeds
- After the changes, `cargo build --release` exits 0. (Sanity check that the
  removed files weren't actually referenced by anything that matters.)

### T-073-08: cargo test still passes
- `cargo test` still reports 788+ tests passing.

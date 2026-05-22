# Test Spec — Task 064: Add `cargo audit` step to CI

## Context

`.github/workflows/ci.yml` currently runs three jobs: `test`, `clippy`, `fmt`.
None of them audit Rust dependencies for known advisories. This task adds an
`audit` job using `rustsec/audit-check@v2`.

Acceptance is verified by static inspection of the YAML file (T-064-01 through
T-064-06) and one runtime check (T-064-07).

---

## Validation

### T-064-01: Valid YAML
- `.github/workflows/ci.yml` parses without errors (verify via `yq . .github/workflows/ci.yml` or `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`).

### T-064-02: `audit` job exists
- `jobs.audit` is defined in the workflow.

### T-064-03: `audit` job uses `rustsec/audit-check@v2`
- One of `jobs.audit.steps[*].uses` equals `rustsec/audit-check@v2`.

### T-064-04: `audit` job passes `GITHUB_TOKEN`
- The `rustsec/audit-check@v2` step has `with.token` set to `${{ secrets.GITHUB_TOKEN }}`.

### T-064-05: `audit` job triggers match the existing jobs
- `on.push.branches` includes `main` and `on.pull_request` exists at the workflow level (jobs inherit).

### T-064-06: `audit` job runs on `ubuntu-latest`
- `jobs.audit.runs-on` equals `ubuntu-latest`.

### T-064-07: `cargo audit` on current `main` passes
- `cargo install cargo-audit --locked` (or use a pre-installed copy) followed by
  `cargo audit` exits 0 against the current `Cargo.lock`.
- This is the same gate CI will enforce; running it locally before merge
  confirms the new CI job will be green on first run.

### T-064-08: CLAUDE.md documents suppression policy
- A new bullet or sentence in the "Commands" section of `CLAUDE.md` states that
  advisory suppression requires a `.cargo/audit.toml` ignore entry with a
  justification comment, not `--ignore` at the command line.

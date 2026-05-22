# Test Spec — Task 065: Multi-OS test matrix in CI

## Context

The `test` job in `.github/workflows/ci.yml` currently runs only on
`ubuntu-latest`. Release builds target five platforms. This task expands the
test job to a matrix over Ubuntu / macOS / Windows so platform-specific
behavior is exercised on every push.

Verification is static YAML inspection (T-065-01 to T-065-06) plus an
observable check that the matrix actually runs on first CI invocation
(T-065-07).

---

## Validation

### T-065-01: Valid YAML
- `.github/workflows/ci.yml` parses without errors.

### T-065-02: `test` job uses a strategy matrix
- `jobs.test.strategy.matrix` is defined.

### T-065-03: Matrix covers three OSes
- The matrix axis (whatever key is used — e.g. `os`) includes exactly the
  values `ubuntu-latest`, `macos-latest`, `windows-latest`.

### T-065-04: `runs-on` references the matrix axis
- `jobs.test.runs-on` is `${{ matrix.os }}` (or equivalent).

### T-065-05: `fail-fast` is disabled
- `jobs.test.strategy.fail-fast` equals `false`.

### T-065-06: `clippy`, `fmt`, and `audit` jobs stay Linux-only
- `jobs.clippy.runs-on`, `jobs.fmt.runs-on`, `jobs.audit.runs-on` (if 064 has
  landed) each equal `ubuntu-latest` and do NOT use a matrix. We don't want
  redundant clippy runs.

### T-065-07: All three matrix legs pass against current `main`
- After the workflow is updated, push to a branch and confirm all three matrix
  legs go green in GitHub Actions. If any platform fails, document the failure
  in the task file and either gate the failing test with `#[cfg_attr]` or open
  a follow-up task.

### T-065-08: No silent test skips introduced
- `grep -r "ignore" tests/ src/ | grep -v test-spec | grep -v ".md"` after the
  change should produce no new `#[ignore]` attributes beyond what was already
  in place pre-task.

# Test Spec — Task 067: Dog-food dep-scan on its own `Cargo.lock` in CI

## Context

dep-scan is a supply-chain security tool. Running it against its own
`Cargo.lock` in CI demonstrates self-trust and catches new dependency risks on
every PR. This task adds a `dogfood` job that does exactly that.

Verification mixes static YAML inspection with one runtime self-check.

---

## Validation

### T-067-01: Valid YAML
- `.github/workflows/ci.yml` parses without errors.

### T-067-02: `dogfood` job exists
- `jobs.dogfood` is defined.

### T-067-03: `dogfood` depends on `test`
- `jobs.dogfood.needs` contains `test`.

### T-067-04: `dogfood` job builds dep-scan
- Steps include `cargo build --release` (or equivalent that produces
  `target/release/dep-scan`).

### T-067-05: `dogfood` job runs the lockfile scan
- Steps include an invocation of `target/release/dep-scan check --lockfile
  Cargo.lock --lockfile-type crates --json` (or equivalent that emits JSON).

### T-067-06: Block verdicts fail the job
- A subsequent step parses the JSON output and exits non-zero if any package's
  `result` field is `"block"`. Implementation can be inline `jq` or a small
  shell script; mechanism is open as long as the behavior is correct.

### T-067-07: Warn verdicts emit annotations but do not fail
- A `warn` verdict produces a `::warning::` GitHub Actions annotation on
  stdout (so it shows in the run summary) and the step's exit code stays 0.

### T-067-08: Running dep-scan against current `main` produces no block verdicts
- Locally (or in a test push) verify: `cargo run --release -- check --lockfile
  Cargo.lock --lockfile-type crates --json | jq '.packages[] | select(.result
  == "block")'` returns empty. (Warns are acceptable; blocks are not.)

### T-067-09: Job runs on `ubuntu-latest`
- `jobs.dogfood.runs-on` is `ubuntu-latest`.

### T-067-10: Documentation references dog-food
- README's "What it detects" section (or a new "Eating our own dog food"
  callout) mentions that dep-scan scans its own `Cargo.lock` on every CI run.
  Single sentence is sufficient.

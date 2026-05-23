# Test Spec — Task 080: Fix typosquat false-positive on `version_check`

## Context

`POPULAR_CRATES` in `src/typosquat.rs:568` lists `"version-check"` (hyphen)
but the real crate is `version_check` (underscore). The typosquat policy
therefore blocks the *correct* popular crate as suspiciously-similar to a
non-existent hyphenated name. This task corrects the list entry.

---

## Unit tests

### T-080-01: `POPULAR_CRATES` contains `version_check`
- `POPULAR_CRATES.contains(&"version_check")` returns `true`.

### T-080-02: `POPULAR_CRATES` does NOT contain `version-check`
- `POPULAR_CRATES.contains(&"version-check")` returns `false`.

### T-080-03: Scanning `version_check` does NOT block on typosquat
- A new unit test in `src/typosquat.rs` (or `src/policy/typosquatting.rs`)
  calls the typosquatting check with package name `"version_check"`
  against the crates.io popular list and expects no warn/block verdict.

### T-080-04: Scanning a real typosquat (e.g. `version_chk`) STILL blocks
- A unit test verifies that an actual typosquat candidate like
  `"version_chk"` or `"versioncheck"` still produces a warn or block
  against `version_check`. Confirms that fixing the data did not blunt
  the policy.

---

## Integration / regression

### T-080-05: Dogfood scan no longer blocks on `version_check`
- After the fix, run:
  ```
  cargo build --release
  ./target/release/dep-scan check --lockfile Cargo.lock --lockfile-type crates --json 2>/dev/null \
    | jq '.[] | select(.package == "version_check" and .result == "block")'
  ```
- Expected: empty output.

### T-080-06: Other typosquat assertions in the suite still pass
- `cargo test typosquat` runs all existing typosquat tests; none regress.

### T-080-07: `cargo test` total ≥ 802
- After the fix and new tests, the total test count is at least 802 (the
  number after task 078).

### T-080-08: Full CI gate clean
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo audit` all exit 0.

---

## Optional audit findings

### T-080-09: List of other suspect entries documented
- If a sweep of `POPULAR_CRATES` finds other hyphen-vs-underscore
  mismatches, they are either fixed in this commit or recorded in the
  task file's "Findings" section for a follow-up task. Empty findings
  section is acceptable.

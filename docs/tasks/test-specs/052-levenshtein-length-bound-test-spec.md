# Test Spec — Task 052: Bound Levenshtein matrix on package-name length (L-5)

## Context

`levenshtein(a, b)` in `src/typosquat.rs` allocates a row of `O(|b|)` cells and
loops `O(|a| × |b|)` times.  npm allows package names up to 214 characters; with
a popular-package list of ~150 entries the worst case is ~214 × 214 × 150 ≈ 6.9M
comparisons per scan call.  The code has no guard, so a contrived 214-char input
scanned against all popular lists runs the full matrix unconditionally.

The fix adds an early return in `levenshtein` (or `normalized_levenshtein`) that
returns a sentinel distance of `1.0` (maximum — "not similar") when either input
exceeds 256 Unicode scalar values, and bounds the matrix allocation to at most 257
elements per row.  The typosquatting threshold used in production is `0.3`; a
sentinel of `1.0` is safely above the threshold and never produces a false match.

---

## Unit tests — early-return guard

### T-052-01: `levenshtein` with one input longer than 256 chars returns without computing the matrix
- Input: `a = "a".repeat(257)`, `b = "lodash"`
- Expected: the function returns quickly (no matrix allocation); the returned value
  is any value that will cause `normalized_levenshtein` to return >= `1.0` OR the
  function signals "not similar" to the caller.
- Implementer note: the simplest approach is to return `usize::MAX` from
  `levenshtein` for overlong inputs, letting `normalized_levenshtein` clamp to `1.0`.
  Alternatively, add the guard only in `normalized_levenshtein`. Either is acceptable;
  document the choice.

### T-052-02: `normalized_levenshtein` with one input longer than 256 chars returns `1.0`
- Input: `a = "x".repeat(300)`, `b = "react"`
- Expected: return value is exactly `1.0` (or `>= 1.0` if the sentinel is `usize::MAX`
  divided by max_len — the important thing is `>= threshold` for all practical thresholds).

### T-052-03: `normalized_levenshtein` with both inputs longer than 256 chars returns `1.0`
- Input: `a = "a".repeat(300)`, `b = "b".repeat(300)`
- Expected: `1.0` — both overlong.

### T-052-04: `find_closest_match` with an overlong name returns `None`
- Input: `name = "x".repeat(300)`, `popular = POPULAR_NPM`, `threshold = 0.3`
- Expected: `None` — no match because the sentinel distance exceeds the threshold.

### T-052-05: `find_closest_match` with an overlong popular-list entry returns `None`
- Construct a synthetic popular list containing a single 300-char entry.
- Input: `name = "react"`, `popular = [<300-char entry>]`, `threshold = 0.3`
- Expected: `None` — the overlong popular entry is skipped safely.

---

## Unit tests — correct behavior is preserved for normal-length inputs

### T-052-06: `levenshtein("kitten", "sitting")` still returns `3`
- Expected: `3` — the classic Levenshtein sanity check is unchanged.

### T-052-07: `normalized_levenshtein("lodash", "lodash")` still returns `0.0`
- Expected: `0.0`.

### T-052-08: `normalized_levenshtein("loadsh", "lodash")` still returns a value < `0.5`
- Expected: value is in `(0.0, 0.5)` — typo is detectable.

### T-052-09: `find_closest_match("loadsh", POPULAR_NPM, 0.3)` still returns `Some(("lodash", _))`
- Expected: closest match is `"lodash"` with distance < 0.3 — real typosquatting
  detection is unaffected.

### T-052-10: Exactly-256-char inputs are processed normally (boundary — not early-returned)
- Input: `a = "a".repeat(256)`, `b = "a".repeat(256)` (identical)
- Expected: distance is `0` (or `normalized_levenshtein` returns `0.0`).
- Rationale: the guard fires for `> 256`, not `>= 256`.

---

## Regression tests

### T-052-11: All task 013 typosquatting tests pass without modification
- Run `cargo test typosquat`
- Expected: 0 failures — the guard only adds an early return for overlong inputs
  that never appear in normal package names.

### T-052-12: All task 020 popular-list tests pass
- Run `cargo test popular_` (or equivalent)
- Expected: 0 failures.

### T-052-13: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

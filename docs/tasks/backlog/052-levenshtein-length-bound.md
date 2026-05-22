# Task 052 — Bound Levenshtein matrix on package-name length (L-5)

**Status:** backlog
**Depends on:** 013 (typosquatting detection)
**Security finding:** L-5 (LOW — algorithmic complexity, not exploitable remotely)
**Touches:** `src/typosquat.rs` only

## Objective

Add an early-return guard in `levenshtein` or `normalized_levenshtein` so that
inputs longer than 256 Unicode scalar values immediately return "not similar"
without allocating or filling the dynamic-programming matrix.

## Background

npm allows package names up to 214 characters; dep-scan applies `levenshtein` to
every scanned package name against every entry in the popular-package lists
(`POPULAR_NPM`, `POPULAR_PYPI`, `POPULAR_CRATES`, `POPULAR_GO`).  Each comparison
is O(N×M) in time and O(min(N,M)) in space.  With 150 popular packages and a
214-char name: ~150 × 214 × 214 ≈ 6.9M cell updates per scan call.

In practice, 214-char package names are never real typosquats — legitimate popular
packages have short names, and a 214-char name cannot be "close" to "react" or
"lodash" at any plausible threshold.  The guard can safely return `1.0` for any
input exceeding 256 chars without reducing real detection capability.

## Behavior

- **Guard location:** either `levenshtein` or `normalized_levenshtein`; document
  the choice in source code.
- **Threshold:** `> 256` Unicode scalar values (not bytes — the existing code
  already uses `chars().collect()`).
- **Return value for overlong inputs:**
  - `levenshtein` → `usize::MAX` (or any value that causes `normalized_levenshtein`
    to return `>= 1.0`), OR
  - `normalized_levenshtein` → `1.0` directly.
- **Matrix allocation cap:** after the guard, the matrix row allocation
  (`vec![0usize; b_len + 1]`) is implicitly capped to ≤ 257 elements because any
  name exceeding 256 chars is already rejected before reaching that line.

## Requirements

- **REQ-052-01:** `normalized_levenshtein(a, b)` returns `1.0` (not similar)
  when either `a` or `b` has more than 256 Unicode scalar values.
- **REQ-052-02:** Inputs with exactly 256 scalar values are processed normally
  (the guard fires for `> 256`, not `>= 256`).
- **REQ-052-03:** `find_closest_match` returns `None` for any input name exceeding
  256 chars, regardless of threshold.
- **REQ-052-04:** All existing task 013 and task 020 tests continue to pass.

## Acceptance criteria

- [ ] `normalized_levenshtein("x".repeat(300), "react")` returns `1.0`
  (REQ-052-01); verified by T-052-02.
- [ ] `find_closest_match("x".repeat(300), POPULAR_NPM, 0.3)` returns `None`
  (REQ-052-03); verified by T-052-04.
- [ ] `normalized_levenshtein("a".repeat(256), "a".repeat(256))` returns `0.0`
  (REQ-052-02); verified by T-052-10.
- [ ] Guard location documented in source code; matrix allocation comment updated.
- [ ] Task 013 regression suite passes (REQ-052-04); verified by T-052-11.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Parallelising the popular-list scan (a future optimisation task).
- Switching to a different distance metric (e.g. Damerau-Levenshtein) — a
  separate decision that requires an ADR.
- Capping the popular-list size.

## Risk notes

- The guard has no effect on scans of packages with names ≤ 50 chars (the
  overwhelming majority of real packages); there is no change to the hot path.
- `usize::MAX` as a sentinel from `levenshtein` is safe: `normalized_levenshtein`
  computes `raw as f64 / max_len as f64`; `usize::MAX as f64` for any reasonable
  `max_len` is a very large number, and the caller's threshold check (`dist <=
  threshold`) will correctly return `None`.

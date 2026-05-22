# Task 046 — verify_hash algorithm-prefix case normalization

**Status:** backlog
**Depends on:** 030 (content hash verify), 040 (sha1 cache bypass)
**Security finding:** M-2 (MEDIUM)
**Touches:** `src/main.rs` (`verify_hash`)

## Objective

Normalize the algorithm prefix (the part before the first `:`) to lowercase on
both the cached and registry sides before comparing content hashes in
`verify_hash`.  This prevents spurious re-scans when a registry changes the
case of the algorithm prefix between requests (`SHA512-…` vs `sha512-…`).

## Background

The current comparison in `verify_hash`:

```rust
(Some(c), Some(r)) if c == r => HashVerifyDecision::HonorCache,
```

is an exact-string comparison.  If the cached hash has prefix `sha512:` and the
registry returns `SHA512:` (or vice versa), the hashes compare unequal even
though they represent the same bytes and algorithm.  The result is a spurious
`Reverify` — a full re-scan that is not necessary.

This is a correctness defect, not a security defect: the re-scan itself is safe
(dep-scan verifies the package again), but it wastes time and makes cache
effectiveness unpredictable.

## Behavior

Normalize the algorithm prefix before comparison:

```rust
fn normalize_hash_prefix(hash: &str) -> String {
    match hash.split_once(':') {
        Some((algo, rest)) => format!("{}:{}", algo.to_lowercase(), rest),
        None => hash.to_string(),
    }
}
```

Apply `normalize_hash_prefix` to both `cached` and `registry` before the
equality test.  The sha1 rejection guard (task 040) must also fire on the
normalized string so that `"SHA1:…"` is correctly rejected:

```rust
fn verify_hash(cached: Option<&str>, registry: Option<&str>) -> HashVerifyDecision {
    let cached_norm = cached.map(normalize_hash_prefix);
    // sha1 guard on the normalized prefix
    if let Some(ref c) = cached_norm {
        if c.starts_with("sha1:") {
            return HashVerifyDecision::Reverify;
        }
    }
    match (cached_norm.as_deref(), registry.map(normalize_hash_prefix).as_deref()) {
        (Some(c), Some(r)) if c == r => HashVerifyDecision::HonorCache,
        _ => HashVerifyDecision::Reverify,
    }
}
```

Only the algorithm prefix (before `:`) is lowercased; the hex portion is left
unchanged because hex content hashes from all supported registries are already
lowercase in practice.

## Requirements

- **REQ-046-01:** The algorithm prefix is normalized to lowercase on both sides
  before comparison.
- **REQ-046-02:** Two hash strings that differ only in the case of the algorithm
  prefix and are otherwise identical return `HonorCache`.
- **REQ-046-03:** The sha1 rejection guard from task 040 continues to fire for
  both `"sha1:…"` and `"SHA1:…"` cached values.
- **REQ-046-04:** Hashes with genuinely different algorithms (`sha256` vs
  `sha512`) continue to return `Reverify`.
- **REQ-046-05:** All task 030 and task 040 test vectors continue to pass.

## Acceptance criteria

- [ ] Uppercase-prefix cached hash matches lowercase-prefix registry hash (REQ-046-02); verified by T-046-02.
- [ ] Lowercase-prefix cached hash matches uppercase-prefix registry hash (REQ-046-02); verified by T-046-03.
- [ ] `SHA1:…` cached hash still returns `Reverify` (REQ-046-03); verified by T-046-09.
- [ ] Different algorithms still return `Reverify` (REQ-046-04); verified by T-046-06, T-046-07.
- [ ] Task 030 regression suite passes (REQ-046-05); verified by T-046-14.
- [ ] Task 040 regression suite passes (REQ-046-05); verified by T-046-15.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Normalizing the hex portion (it is already lowercase from all known registries).
- Normalizing hashes stored in SQLite — the cache stores whatever the registry
  returned at scan time; the normalization is applied only at comparison time.
- Registry-specific hash format validation — that belongs in the registry client.

## Risk notes

- The change is entirely inside `verify_hash`; no network calls, no SQLite
  writes, no policy logic changes.
- The `normalize_hash_prefix` helper is pure and has no side effects; the risk
  of regression is very low.

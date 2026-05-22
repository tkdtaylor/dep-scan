# Test Spec — Task 045: Obfuscation policy — compile regexes once and cap script size

## Context

`ObfuscationPolicy::evaluate` currently calls `Self::patterns()` on every
invocation, which re-constructs a `Vec<ObfuscationPattern>` and re-compiles
every `Regex` from scratch each time.  For large install scripts (npm allows up
to ~10 MB) and the `chr\(\d+\).*chr\(\d+\).*chr\(\d+\)` pattern, this produces
non-trivial work per package.

Two fixes:
1. Compile regex patterns once using `std::sync::OnceLock` (or `lazy_static!`)
   so subsequent calls reuse the compiled objects.
2. Cap the portion of each script that is scanned to the first 1 MB (1,048,576
   bytes).  Patterns are searched against `&content[..content.len().min(CAP)]`.

The cap does not change the verdict for any real-world malicious package: a
10 MB postinstall with an obfuscation payload in the final megabyte is already
extremely suspicious by other heuristics; and practically all malicious scripts
front-load their payload.

---

## Unit tests — regex-cache correctness

### T-045-01: Compiled-once regex still detects long base64 strings
- Input: script with an 80-character base64 payload.
- Call `policy.evaluate(&ctx)` twice on the same context.
- Expected: both calls return `PolicyResult::Block` with reason containing
  `"long_base64"`.
- This verifies the `OnceLock` path is used on the second call without error.

### T-045-02: Compiled-once regex still detects hex escape chains
- Input: script with `\x68\x74\x74\x70\x3a\x2f\x2f` (7 hex escapes).
- Expected: `PolicyResult::Block` with `"hex_escape_chain"`.

### T-045-03: Compiled-once regex still detects chr() chains
- Input: script with `chr(104).chr(116).chr(116)`.
- Expected: `PolicyResult::Block` with `"chr_chain"`.

### T-045-04: Compiled-once regex still detects string-concat URL
- Input: script with `"ht" + "tp"`.
- Expected: `PolicyResult::Warn` with `"string_concat_url"`.

### T-045-05: Concurrent calls to `evaluate` from multiple threads do not panic or deadlock
- Spawn 8 threads, each calling `policy.evaluate(&ctx)` with a clean script 10 times.
- Expected: all calls return `PolicyResult::Pass`; no thread panics.
- This is the critical `OnceLock` thread-safety assertion.

---

## Unit tests — 1 MB script cap

### T-045-06: Script content shorter than 1 MB is scanned in full
- Build a script of 512 KB containing a `chr()` chain at the very end.
- Expected: `PolicyResult::Block` — the payload is within the scanned window.

### T-045-07: Script content exactly at the cap boundary (1,048,576 bytes) is scanned up to the cap
- Build a 1 MB script where the first byte is `\` and the next 6 bytes form part
  of a hex escape chain, followed by clean padding to exactly 1 MB.
- Expected: `PolicyResult::Block` — the pattern is within the cap.

### T-045-08: Payload placed beyond 1 MB is not detected (cap is enforced)
- Build a script whose first 1 MB is clean padding bytes (e.g. `'a'` repeated),
  followed immediately by a `chr()` chain pattern.
- Expected: `PolicyResult::Pass` — the payload is outside the cap and must not
  influence the verdict.
- This test explicitly asserts the cap behavior; the implementer must ensure the
  slice is `&content[..1_048_576.min(content.len())]` or equivalent.

### T-045-09: Script of exactly 1 byte is not panicked on
- Input: a single-character script `"a"`.
- Expected: `PolicyResult::Pass` — no index-out-of-bounds.

### T-045-10: Empty script (no install scripts in context) still returns Pass
- `ctx.install_scripts` is empty.
- Expected: `PolicyResult::Pass` — early exit path is unchanged.

---

## Performance / static checks

### T-045-11: `ObfuscationPolicy::evaluate` does not call `Regex::new` directly
- Code review assertion: after the fix, `Regex::new(...)` (or any equivalent
  on-the-fly compilation) is not called inside `evaluate` or inside any function
  called per-evaluation that is not the `OnceLock` initializer.
- The `OnceLock` initializer runs at most once per process lifetime.

### T-045-12: The script-cap constant is named `SCRIPT_SCAN_CAP_BYTES` (or similar) and equals 1,048,576
- Code review assertion: the literal `1_048_576` (or `1024 * 1024`) appears as
  a named constant, not an inline magic number inside `evaluate`.

### T-045-13: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass

---

## Regression tests

### T-045-14: All existing T-021-01 through T-021-11 obfuscation policy tests pass unchanged
- Run `cargo test obfuscation`.
- Expected: 0 failures — the compile-once change must not alter detection behavior
  for scripts shorter than 1 MB.

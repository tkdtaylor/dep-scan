# Test Spec — Task 053: Scrub user-visible error output (L-6)

## Context

`src/main.rs:142` contains:

```rust
Err(e) => {
    eprintln!("Error: {e:#}");
    2
}
```

`{e:#}` prints the full `anyhow` error chain, which can include file-system paths
(the cache DB path, lockfile path, temp file path) in multi-user environments where
those paths contain usernames or other PII.  The fix gates the full chain behind
`--verbose` / `RUST_LOG=debug`; the default error output is a single concise line.

---

## Unit tests — error formatting helpers

### T-053-01: A top-level `anyhow` error without a cause chain formats to a single line in non-verbose mode
- Construct `anyhow::anyhow!("registry fetch failed")`.
- Format with the non-verbose formatter (the helper the implementation introduces).
- Expected: output is exactly `"dep-scan: registry fetch failed\n"` (or equivalent
  single-line form) — no additional context frames.

### T-053-02: An `anyhow` error with a cause chain formats to a single line in non-verbose mode
- Construct a chained error:
  `anyhow::anyhow!("cache open failed").context("cannot initialize cache")`
- Format with the non-verbose formatter.
- Expected: output contains only the outermost message (`"cannot initialize cache"`)
  — inner cause (`"cache open failed"`) is suppressed.
- The output must not contain any file-system path that was embedded in the inner
  cause (e.g. `/home/alice/.cache/dep-scan/cache.db`).

### T-053-03: In verbose mode, the full chain is printed
- Same chained error as T-053-02.
- Format with the verbose formatter (or pass `--verbose`).
- Expected: output contains both `"cannot initialize cache"` and
  `"cache open failed"` — full chain is visible.

### T-053-04: A path-bearing error does not leak the path in non-verbose mode
- Construct an error whose inner cause contains a file-system path:
  `anyhow::anyhow!("failed to open /home/alice/.cache/dep-scan/cache.db")`
  wrapped in `anyhow!("cache error").context(inner)`.
- Format with the non-verbose formatter.
- Expected: the string `/home/alice` does NOT appear in the output.
- This is the primary privacy assertion for L-6.

---

## Integration tests (assert_cmd)

### T-053-05: A fatal scan error in non-verbose mode prints a single-line message to stderr
- Arrange: corrupt the config file so that `run` returns `Err(…)` immediately.
- Run `dep-scan check pkg --registry npm` (no `--verbose`).
- Expected: stderr is a single line beginning with `"dep-scan:"` or `"Error:"`;
  the line does not contain a file-system separator (`/` or `\`) originating from
  an inner cause path.
- Exit code: `2`.

### T-053-06: A fatal scan error with `--verbose` prints the full anyhow chain
- Same setup as T-053-05 but run with `--verbose`.
- Expected: stderr contains multiple lines (outer message + at least one inner
  cause); exit code is `2`.

### T-053-07: A non-fatal per-package warning (`eprintln!` calls inside `run_check`)
  is unaffected — those messages are already single-line
- Run `dep-scan check pkg --registry npm` with wiremock serving clean metadata.
- Expected: no spurious path information in stdout or stderr.

---

## Regression tests

### T-053-08: Exit code `2` is still produced for top-level errors after the format change
- Arrange any condition that causes `run` to return `Err(…)`.
- Expected: exit code is `2` — unchanged from current behavior.

### T-053-09: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

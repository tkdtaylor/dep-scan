# Test Spec — Task 048: Maintainer policy trust-on-first-use warning

## Context

`MaintainerChangePolicy::evaluate` passes silently on first observation
(`ctx.previous_maintainers == None`) — the initial maintainer set is accepted
as the trusted baseline with no signal to the user.  A package that is malicious
from day one (typosquat published under an attacker account) passes this check
forever once the first observation is recorded.

The fix: add a `first_seen_warning` configuration toggle.  When enabled (off by
default), a first observation for a package with zero download count (or
explicitly `popularity == 0`) produces a `Warn` verdict rather than a `Pass`.
This provides a defense-in-depth signal without breaking the common case of
first-time scans for established packages.

---

## Unit tests — first_seen_warning disabled (default behavior preserved)

### T-048-01: First scan with no history returns Pass when first_seen_warning is false
- `ctx.previous_maintainers = None`, `ctx.metadata.downloads = Some(1_000_000)`.
- `policy.first_seen_warning = false` (or the field is absent, defaulting to false).
- Expected: `PolicyResult::Pass`.

### T-048-02: First scan with zero downloads returns Pass when first_seen_warning is false
- `ctx.previous_maintainers = None`, `ctx.metadata.downloads = Some(0)`.
- `policy.first_seen_warning = false`.
- Expected: `PolicyResult::Pass` — the toggle is off, so no warning is emitted.

### T-048-03: First scan with None downloads returns Pass when first_seen_warning is false
- `ctx.previous_maintainers = None`, `ctx.metadata.downloads = None`.
- `policy.first_seen_warning = false`.
- Expected: `PolicyResult::Pass`.

---

## Unit tests — first_seen_warning enabled

### T-048-04: First scan with zero downloads warns when first_seen_warning is true
- `ctx.previous_maintainers = None`, `ctx.metadata.downloads = Some(0)`.
- `policy.first_seen_warning = true`.
- Expected: `PolicyResult::Warn` with a message mentioning "first observation" and
  "zero downloads" or "unestablished package" — some wording that conveys both facts.

### T-048-05: First scan with None downloads warns when first_seen_warning is true
- `ctx.previous_maintainers = None`, `ctx.metadata.downloads = None`.
- `policy.first_seen_warning = true`.
- Expected: `PolicyResult::Warn` — unknown download count is treated as potentially zero.

### T-048-06: First scan with non-zero downloads passes even when first_seen_warning is true
- `ctx.previous_maintainers = None`, `ctx.metadata.downloads = Some(5_000)`.
- `policy.first_seen_warning = true`.
- Expected: `PolicyResult::Pass` — an established package is not warned on first scan.
- This is the key design decision: the warning is gated on zero/unknown popularity,
  not on first-observation alone.

### T-048-07: First scan with exactly 1 download passes when first_seen_warning is true
- `ctx.previous_maintainers = None`, `ctx.metadata.downloads = Some(1)`.
- `policy.first_seen_warning = true`.
- Expected: `PolicyResult::Pass` — the threshold for "established" is `> 0` downloads.
  Implementer may choose a higher threshold (e.g. 100); document the chosen value
  here and adjust this test accordingly.

### T-048-08: Second scan (previous maintainers present) is unaffected by first_seen_warning
- `ctx.previous_maintainers = Some(vec!["alice".to_string()])`.
- `ctx.metadata.maintainers = vec!["alice".to_string()]`.
- `policy.first_seen_warning = true`.
- `ctx.metadata.downloads = Some(0)`.
- Expected: `PolicyResult::Pass` — the flag only applies to first observations.

### T-048-09: Complete changeover still blocks regardless of first_seen_warning
- `ctx.previous_maintainers = Some(vec!["alice".to_string()])`.
- `ctx.metadata.maintainers = vec!["mallory".to_string()]`.
- `policy.first_seen_warning = true`.
- `ctx.metadata.downloads = Some(0)`.
- Expected: `PolicyResult::Block` — the changeover detection supersedes the
  first_seen_warning logic.

---

## Configuration tests

### T-048-10: `first_seen_warning` defaults to `false` in default config
- Deserialize an empty `[policies]` TOML section.
- Expected: `config.policies.maintainer_first_seen_warning == false`.

### T-048-11: `first_seen_warning = true` is accepted in `.dep-scan.toml`
- Parse a TOML string containing `[policies]\nmaintainer_first_seen_warning = true`.
- Expected: `config.policies.maintainer_first_seen_warning == true`.

### T-048-12: `MaintainerChangePolicy` is constructed with the `first_seen_warning` value from config
- Build the policy pipeline with `first_seen_warning = true` from config.
- Verify the `MaintainerChangePolicy` instance carries the flag.
- This is a wiring test — not a detection test.

---

## Regression tests

### T-048-13: All existing T-014-04 through T-014-09 maintainer change tests pass unchanged
- Run `cargo test maintainer`.
- Expected: 0 failures — the default `first_seen_warning = false` preserves the
  existing behavior exactly.

### T-048-14: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

# Task 048 — Maintainer policy trust-on-first-use warning

**Status:** backlog
**Depends on:** 014 (maintainer change detection), 003 (configuration system)
**Security finding:** M-4 (MEDIUM)
**Touches:** `src/policy/maintainer.rs`, `src/config.rs`, `src/main.rs` (policy construction)

## Objective

Add an opt-in `maintainer_first_seen_warning` configuration toggle that emits a
`Warn` verdict on first observation of a package when its download count is zero
or unknown.  This provides a defense-in-depth signal against day-one malicious
publishes without changing the default behavior.

## Background

The current `MaintainerChangePolicy` passes silently when
`ctx.previous_maintainers == None` (first scan).  The audit finding notes that
this is the trust-on-first-use (TOFU) assumption: the first maintainer set is
recorded as the baseline and never re-examined.  A package that is malicious
from initial publication (typosquat + attacker account) passes the maintainer
check on every subsequent scan.

The exploit is defended elsewhere (typosquatting, popularity, age checks), but
an explicit first-observation signal at zero downloads adds another layer.
Keeping the feature opt-in avoids false positives for users who regularly scan
new packages.

## Behavior

### Config field

Add to `PolicyConfig` in `src/config.rs`:

```toml
[policies]
maintainer_first_seen_warning = false  # default: off
```

### Policy change

`MaintainerChangePolicy` gains a `first_seen_warning: bool` field:

```rust
pub struct MaintainerChangePolicy {
    pub first_seen_warning: bool,
}
```

Inside `evaluate`, in the `None` (first observation) arm:

```rust
None => {
    if self.first_seen_warning {
        let downloads = ctx.metadata.downloads.unwrap_or(0);
        if downloads == 0 {
            return PolicyResult::Warn(format!(
                "First observation of '{}': maintainer set recorded as baseline; \
                 package has zero known downloads — verify publisher identity",
                ctx.metadata.name
            ));
        }
    }
    PolicyResult::Pass
}
```

The threshold `downloads == 0` (any positive download count passes) is
deliberately low to avoid false positives on new-but-legitimate packages.
If a higher threshold is preferred (e.g. 100), document it here.

### Construction

In `src/main.rs`, pass the config value when constructing the policy:

```rust
Box::new(MaintainerChangePolicy {
    first_seen_warning: config.policies.maintainer_first_seen_warning,
})
```

## Requirements

- **REQ-048-01:** When `maintainer_first_seen_warning = false` (default), the
  policy behaves identically to the pre-task behavior (first observation → Pass).
- **REQ-048-02:** When `maintainer_first_seen_warning = true` and
  `ctx.metadata.downloads` is `Some(0)` or `None`, a first observation returns
  `PolicyResult::Warn` with a message that mentions first observation and zero
  downloads.
- **REQ-048-03:** When `maintainer_first_seen_warning = true` and downloads
  are `> 0`, a first observation returns `PolicyResult::Pass`.
- **REQ-048-04:** The `first_seen_warning` check applies only to first
  observations (`previous_maintainers == None`); subsequent scans with previous
  history are unaffected.
- **REQ-048-05:** Existing changeover / partial-change / no-change detection
  is unaffected.
- **REQ-048-06:** The config field is `false` by default (backward-compatible).

## Acceptance criteria

- [ ] Default `false` produces `Pass` on first scan (REQ-048-01); verified by T-048-01, T-048-02, T-048-03.
- [ ] `true` + zero downloads produces `Warn` on first scan (REQ-048-02); verified by T-048-04, T-048-05.
- [ ] `true` + non-zero downloads produces `Pass` (REQ-048-03); verified by T-048-06.
- [ ] Second scan (previous_maintainers present) unaffected (REQ-048-04); verified by T-048-08.
- [ ] Complete changeover still blocks (REQ-048-05); verified by T-048-09.
- [ ] Config defaults to `false` (REQ-048-06); verified by T-048-10.
- [ ] Config `true` is parsed correctly (REQ-048-06); verified by T-048-11.
- [ ] Policy receives the config value at construction (wiring); verified by T-048-12.
- [ ] Task 014 regression suite passes (REQ-048-01); verified by T-048-13.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- A stricter mode that warns on all first observations regardless of popularity
  — this would cause too many false positives for regular workflows.
- Recording the warning in the cache — the first-seen warning is advisory only;
  subsequent scans with history use the normal change-detection path.
- Download-count thresholds above 0 — the lowest reasonable threshold avoids
  false positives while still flagging truly unknown packages.

## Risk notes

- The feature is opt-in (`false` by default), so no change in behavior for
  existing users who do not set the flag.
- Adding `first_seen_warning: bool` to `MaintainerChangePolicy` requires
  updating all construction sites.  Check `src/main.rs` for the single
  construction point.

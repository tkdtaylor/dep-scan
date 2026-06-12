# Task 107 — [transitive] config block + CLI enable/disable flag

**Status:** backlog
**Depends on:** 103 (walker integration — config values are passed into the
               walker; this task can be developed in parallel with 104/105/106
               since it only adds a config struct)
**ADR:** 009 (piece 7 — Decisions 2a, 3b; config shape)
**Scope:** small
**Touches:** `src/config.rs` (add `TransitiveConfig` struct), `src/main.rs`
            (CLI flag wiring — `--transitive` / `--no-transitive`)

## Objective

Add the `[transitive]` configuration block and a CLI enable/disable flag.
Reuses the `[vcs]` config patterns from tasks 095 and 096. Config load
performs zero network I/O.

When `enabled = false` (the default), the output must be **byte-for-byte
identical** to today's flat scan — no regressions.

## Background

ADR 009 Decisions 2a and 3b: `max_depth`, `on_depth_limit`, and the
performance-budget fields are config-driven, not hardcoded. `enabled = false`
is the non-regressive default: operators opt in to transitive scanning rather
than having it forced on them.

## Requirements

### REQ-107-01: `TransitiveConfig` struct with validated fields
Fields:
- `enabled: bool` — default `false`
- `max_depth: u32` — default `5`; value `0` is either rejected or treated as
  depth-0 with DepthLimitReached for all children (documented)
- `on_depth_limit: DepthLimitAction` — `Warn` (default) | `Block`
- `fetch_concurrency: u32` — default `4`; value `0` is rejected
- `max_total_nodes: u32` — default `5000` (documented); value `0` is rejected
  or treated as "fail immediately"

### REQ-107-02: Config load is zero-network
Config parsing reads only the config file bytes. No network call during parse
or validation. Asserted by T-107-01.

### REQ-107-03: Invalid values are rejected, not silently defaulted
Unknown `on_depth_limit` string → error. `fetch_concurrency = 0` → error.
Validation is fail-closed: a misconfigured operator gets an error, not a
silently-wrong scan.

### REQ-107-04: enabled=false non-regression
With `enabled = false`, the scan output is byte-for-byte identical to the
pre-transitive flat scan. No transitive walker code paths are entered.

### REQ-107-05: CLI flag overrides config file
`--transitive` enables transitive scanning regardless of `enabled` in config.
`--no-transitive` disables transitive scanning regardless of `enabled` in config.
CLI flag takes precedence over config file value.

### REQ-107-06: Reuse [vcs] config patterns
The implementation follows the same deserialization approach as the `[vcs]`
config block introduced in task 095/096. No new config infrastructure is
invented.

## Acceptance criteria

- [ ] `enabled` defaults to false (T-107-02)
- [ ] `max_depth` defaults to 5 (T-107-03)
- [ ] `on_depth_limit` defaults to Warn (T-107-04)
- [ ] `fetch_concurrency` defaults to 4 (T-107-05)
- [ ] `max_total_nodes` defaults to documented value (T-107-06)
- [ ] All explicit values read back correctly (T-107-07)
- [ ] on_depth_limit "block" parsed correctly (T-107-08)
- [ ] on_depth_limit "warn" parsed correctly (T-107-09)
- [ ] Invalid on_depth_limit rejected (T-107-10)
- [ ] fetch_concurrency = 0 rejected (T-107-12)
- [ ] enabled=false output identical to flat scan (T-107-14)
- [ ] enabled=false suppresses DFS walker (T-107-15)
- [ ] --transitive CLI flag overrides config (T-107-16)
- [ ] --no-transitive CLI flag overrides config (T-107-17)
- [ ] CLI takes priority over config (T-107-18)
- [ ] Config load is zero-network (T-107-01)
- [ ] All T-107-01 through T-107-19 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/107-transitive-config-block-cli-flag-test-spec.md`

## Out of scope

- subtree_digest cache column (task 106)
- Main.rs scan-arm wiring (task 108)
- Fetch pool internals (task 105 reads the config values from this task's struct)

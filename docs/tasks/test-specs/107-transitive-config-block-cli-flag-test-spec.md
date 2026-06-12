# Test Spec — Task 107: [transitive] config block + CLI enable/disable flag

## Context

ADR 009 piece 7 (Decisions 2a/3b). Adds the `[transitive]` configuration block
with fields: `enabled` (default false), `max_depth` (default 5),
`on_depth_limit` ("warn" | "block", default "warn"), `fetch_concurrency`
(default 4), `max_total_nodes` (default 5000). Adds a CLI flag to enable or
disable transitive scanning at invocation time. Reuses the `[vcs]` config
patterns from tasks 095 and 096. Config load performs zero network I/O.

---

## Zero-network config load

### T-107-01: Config loading performs zero network I/O
- Load a config file containing a `[transitive]` block.
- No network call is made during config parse or validation.
- Assert: the load succeeds identically in a network-isolated environment.

---

## Default values

### T-107-02: enabled defaults to false
- Load a config with no `[transitive]` block.
- `config.transitive.enabled == false`.

### T-107-03: max_depth defaults to 5
- Load a config with no `[transitive]` block.
- `config.transitive.max_depth == 5`.

### T-107-04: on_depth_limit defaults to "warn"
- Load a config with no `[transitive]` block.
- `config.transitive.on_depth_limit == DepthLimitAction::Warn`.

### T-107-05: fetch_concurrency defaults to 4
- Load a config with no `[transitive]` block.
- `config.transitive.fetch_concurrency == 4`.

### T-107-06: max_total_nodes defaults to 5000 (or the project-chosen small default)
- Load a config with no `[transitive]` block.
- `config.transitive.max_total_nodes` equals the documented default (the exact
  value is chosen by the task implementor; it must be ≥ 1000 and documented in
  the task file).

---

## Explicit values override defaults

### T-107-07: All fields can be explicitly set and read back
- Config file:
  ```toml
  [transitive]
  enabled = true
  max_depth = 3
  on_depth_limit = "block"
  fetch_concurrency = 8
  max_total_nodes = 200
  ```
- Each field reads back the specified value.

### T-107-08: on_depth_limit = "block" is parsed to the Block variant
- Config with `on_depth_limit = "block"`.
- `config.transitive.on_depth_limit == DepthLimitAction::Block`.

### T-107-09: on_depth_limit = "warn" is parsed to the Warn variant
- Config with `on_depth_limit = "warn"`.
- `config.transitive.on_depth_limit == DepthLimitAction::Warn`.

---

## Invalid values are rejected fail-closed

### T-107-10: Invalid on_depth_limit value is rejected
- Config with `on_depth_limit = "ignore"` (not a valid variant).
- Config load returns an error (not a silent default).

### T-107-11: max_depth = 0 is rejected or treated as fail-closed depth-0
- Config with `max_depth = 0`.
- Either rejected with an error, or accepted and treated as "scan only direct
  deps, cut everything else with DepthLimitReached."
- The chosen behaviour is documented in the task; either is acceptable provided
  it does not silently pass transitive nodes.

### T-107-12: fetch_concurrency = 0 is rejected
- Config with `fetch_concurrency = 0`.
- Config load returns an error (zero concurrency would deadlock the pool).

### T-107-13: max_total_nodes = 0 is rejected or treated as "fail immediately"
- Config with `max_total_nodes = 0`.
- Either rejected or treated as "the scan fails closed for any non-empty graph."

---

## enabled=false non-regression

### T-107-14: enabled=false produces output identical to today's flat scan
- Run the real dep-scan binary (via `assert_cmd`/`Command::cargo_bin`) twice against
  a small offline Cargo.lock fixture (a single git-sourced dep; no registry needed).
  - Scan A: config with NO `[transitive]` block (flat-scan baseline).
  - Scan B: identical config but with `[transitive] enabled = false` appended.
- Assert: stdout AND exit code are byte-for-byte identical between A and B.
- Zero network: all registry URLs point at 127.0.0.1:1 and the git dep's host is
  denied before any socket is opened (REQ-096-03).
- (Non-regression: the transitive feature, when disabled, must not alter any
  observable behaviour.)

### T-107-15: enabled=false suppresses all transitive walker code paths
- Assert the GATE PRECONDITION the scan arm consults before invoking the DFS walker:
  `resolve_transitive(cli_transitive, cli_no_transitive).unwrap_or(config.transitive.enabled)`
  yields `false` in the following cases:
  - (a) config `enabled=false`, no CLI flags → effective enabled = false.
  - (b) config `enabled=true`, `--no-transitive` → effective enabled = false.
- Use real `assert_eq` / `assert!` on the resolved boolean in both cases.
- Note: the "dfs_walk is not invoked when disabled" spy/mock assertion is verified
  end-to-end in task 108 (T-108-14 --no-transitive suppression), because the walker
  call site is introduced there. T-107-15 covers the gate precondition that task 108 wires to the walker.

---

## CLI flag

### T-107-16: --transitive CLI flag enables transitive scanning (overrides config)
- Config has `enabled = false`; CLI invocation uses `--transitive`.
- Transitive scanning runs (DFS walker is entered).

### T-107-17: --no-transitive CLI flag disables transitive scanning (overrides config)
- Config has `enabled = true`; CLI invocation uses `--no-transitive`.
- Transitive scanning does not run.

### T-107-18: CLI flag priority: CLI > config file
- Confirmed by T-107-16 and T-107-17: CLI flags override the config-file value.

---

## Tooling gate

### T-107-19: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

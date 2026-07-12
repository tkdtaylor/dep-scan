# Test Spec: Task 111: apache-relicense-followup

## Context

Task 111 is a pre-existing backlog task with no paired test spec (house rule: write one before closing). Investigation while writing this spec found both remaining items already done in prior commits, ahead of this task file being closed out:

- **SPDX headers**: `d603d74` ("chore: add SPDX-License-Identifier headers (Apache-2.0)") added `// SPDX-License-Identifier: Apache-2.0` as line 1 of every first-party `src/**/*.rs` file. `d0c778d` ("fix: repair docstring static-audit tests broken by SPDX header") fixed two static-audit tests (`t_035_18`, `t_036_24`) whose docstring scanners assumed line 1 was `//!` and broke when the SPDX line was prepended.
- **Push**: the relicense commit `085d020` is reachable from `origin/main` (`git merge-base --is-ancestor 085d020 origin/main` succeeds). The repo's origin remote is `https://github.com/tkdtaylor/dep-scan.git`, i.e. already public and pushed.

This spec adds a durable regression test (no prior test enforced the header) and closes the task out. No `src/` behavior changes; this is a verification + tooling-gate task.

---

## T-111-01: Every first-party `.rs` file under `src/` starts with the SPDX header

- New `tests/spdx_header_integration.rs`, `#[test] fn all_first_party_rs_files_have_spdx_header()`.
- Walk `src/` (relative to `CARGO_MANIFEST_DIR`) recursively, collect every `*.rs` path.
- For each file, read the first line and assert it equals exactly `// SPDX-License-Identifier: Apache-2.0`.
- Assert the collected file count is > 0 (guards against a walk bug silently passing on zero files).
- This is a **verifies**, not a smoke test: mutate any single header (or delete it) and the assertion fails with the offending path in the message.

## T-111-02: New first-party source files are covered without an allowlist

- Same test as T-111-01: the walk is directory-based (`src/` recursively), not a hardcoded file list, so a file added after this task lands is checked automatically. No separate test case; this is a property of T-111-01's implementation, asserted by inspection during spec-verifier review (grep the test body confirms `walkdir`/manual recursion over `src/`, not a fixed `Vec<&str>` of filenames).

## T-111-03: Relicense commit is on the public remote

- Documented, not re-encoded as a `cargo test` (this is git/repo state, not binary behavior): `git merge-base --is-ancestor 085d020 origin/main` exits 0, and `git remote get-url origin` resolves to a public `github.com` HTTPS URL.
- Acceptance criterion "Relicense pushed" is satisfied; recorded as a runtime/operator-observation check in the task's Verification plan, not a `cargo test` assertion (there is no in-repo way to assert remote-repo visibility from a unit test).

## Tooling gate

### T-111-04: No regressions from the header addition or this task's closeout

- `cargo test` exits 0 (includes the new `spdx_header_integration` test and the two previously-repaired static-audit tests `t_035_18`, `t_036_24`).
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

# Task 111 — Apache-2.0 relicense follow-up — SPDX headers + push

**Status:** backlog
**Depends on:** 085d020 (relicense commit)

## Context

Relicensed MIT -> Apache-2.0 in commit `085d020`.

Done in that commit: LICENSE, NOTICE, `Cargo.toml` license field, README adoption
sections, CONTRIBUTING (DCO), `.github/FUNDING.yml` + `dco.yml`.

## Remaining

### a. SPDX headers (own commit)

- Add `// SPDX-License-Identifier: Apache-2.0` as the **first line** of every
  first-party Rust source file under `src/` (and any other first-party `.rs`).
- Skip `target/`, generated, and vendored files.
- Land as its own commit.

### b. Push

- Push the relicense once public/private visibility is confirmed.

## Acceptance criteria

- [x] SPDX header (`// SPDX-License-Identifier: Apache-2.0`) on every first-party `.rs`
- [x] Relicense pushed: `085d020` confirmed reachable from `origin/main` (`git merge-base --is-ancestor 085d020 origin/main`); repo is public on GitHub

## Closeout note

Both items were already done ahead of this task file being closed: SPDX headers landed in `d603d74` (repaired in `d0c778d`), and the relicense commit is confirmed on the public `origin/main`. This closeout adds `tests/spdx_header_integration.rs` as a durable regression guard (no prior test enforced the header) and a paired test spec, since the task predates the paired-spec convention. See `docs/tasks/test-specs/111-apache-relicense-followup-test-spec.md`.

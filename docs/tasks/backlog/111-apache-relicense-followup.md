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

- [ ] SPDX header (`// SPDX-License-Identifier: Apache-2.0`) on every first-party `.rs`
- [ ] Relicense pushed

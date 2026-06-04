# Task 088 — Statement freshness: OSV-snapshot marker + `valid_until` backstop

**Status:** backlog
**Depends on:** 086 (DSSE envelope — freshness fields go inside `payload`)
**ADR:** 006 (Q7 — freshness decision)
**Touches:** `src/osv.rs` (query context), `src/main.rs` (pass context to render),
            `src/config.rs` (`[freshness]` section), render functions from
            083–085

## Objective

Embed two freshness signals into every signed interchange payload:
1. `osv_queried_at` — the exact timestamp the OSV advisory data was fetched
   (precise freshness signal for strict consumers).
2. `valid_until` — `osv_queried_at + valid_until_hours` (coarse backstop,
   default 24 h, configurable in `.dep-scan.toml`).

Both fields live inside the `payload` bytes (before base64-encoding into the
DSSE envelope). A consumer can decode the payload and check staleness without
verifying the signature. Online revocation lists are explicitly not used.

## Background

ADR 006 Q7 resolves the freshness model. A daily re-scan is the standard CI
cadence; 24 hours aligns with that and provides a sensible default for both
connected and air-gapped environments. The configurable window exists for
teams that scan on a different cadence or need a longer validity window
between air-gapped refreshes.

## Requirements

### REQ-088-01: `OsvQueryContext`
Add `pub struct OsvQueryContext { pub queried_at: DateTime<Utc> }` in
`src/osv.rs`. `OsvClient::query_batch` (or equivalent) populates this
struct with `Utc::now()` at the time the query is issued. When OSV is not
queried (cache-only hit), the context is `None`.

### REQ-088-02: Freshness injection in render functions
Each render function (`render_osv`, `render_cyclonedx`, `render_spdx`,
`render_vex`) accepts an `Option<&OsvQueryContext>`. When `Some`:
- Sets `osv_snapshot.queried_at` (RFC 3339)
- Sets `valid_until` = `queried_at + Duration::hours(config.freshness.valid_until_hours)`

When `None`, these fields are omitted (or set to `null`).

### REQ-088-03: `[freshness]` config section
Add to `src/config.rs`:
```toml
[freshness]
valid_until_hours = 24   # must be > 0
```
Validate at load time: `valid_until_hours == 0` → `Err`.

### REQ-088-04: `config init` includes `[freshness]` with a descriptive comment
The config-init output includes the `[freshness]` section.

### REQ-088-05: Freshness fields are inside `payload`, not the envelope wrapper
The DSSE envelope produced by task 086 contains `payload` (base64 of the
rendered JSON). `valid_until` and `osv_snapshot` are in that JSON, not in
the outer envelope object.

### REQ-088-06: No revocation-list calls
The freshness implementation introduces no OCSP, CRL, or online revocation
calls of any kind.

## Acceptance criteria

- [ ] `OsvQueryContext` exists and is populated by the OSV client
- [ ] All four interchange formats embed `osv_snapshot.queried_at` and `valid_until`
- [ ] When OSV not queried (cache hit), freshness fields are absent/null
- [ ] `valid_until` respects `freshness.valid_until_hours` config
- [ ] `valid_until_hours = 0` is rejected at config load
- [ ] Freshness fields are inside `payload`, readable without signature verification
- [ ] `--format native` and `--format json` carry no freshness fields
- [ ] No OCSP/CRL calls (offline guarantee preserved)
- [ ] All T-088-01 through T-088-19 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/088-statement-freshness-test-spec.md`

## Out of scope

- Revocation (online or offline) — explicitly rejected per ADR 006 Q7
- Freshness enforcement on the consume side (verifying a received statement's
  `valid_until` before acting on it) — that is a consumer concern
- Freshness on `--format native` / `--format json` (unsigned paths, no need)

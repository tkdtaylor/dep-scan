# Test Spec — Task 088: Statement freshness — OSV snapshot marker + `valid_until`

## Context

ADR 006 Q7 resolves: each signed interchange statement records the OSV
advisory-data snapshot (timestamp/version) it was computed against as the
precise freshness signal, plus a `valid_until` field defaulting to 24 hours
as a coarse backstop. The window is configurable in `.dep-scan.toml`. Online
revocation lists are explicitly rejected because they break the offline
guarantee.

This task embeds freshness metadata in the interchange payload (before
signing by task 086/087). It depends on 083 for the format enum and on 086
for the DSSE envelope shape (freshness fields go inside `payload`, not in the
envelope wrapper).

---

## OSV snapshot marker

### T-088-01: `OsvQueryContext` records the query timestamp
- After `OsvClient::query_batch` completes, the returned context includes
  `osv_queried_at: DateTime<Utc>` capturing when the query was made.
- The timestamp is within 1 second of `Utc::now()` at call time.

### T-088-02: Snapshot timestamp is embedded in OSV output
- Call `render_osv` with a `Vec<CheckResult>` that carries an
  `OsvQueryContext`.
- The rendered JSON root object has a `"osv_snapshot"` object containing
  `"queried_at"` (RFC 3339 string) matching the context timestamp.

### T-088-03: Snapshot timestamp is embedded in CycloneDX output
- Call `render_cyclonedx` with results that carry `OsvQueryContext`.
- The CycloneDX `metadata.properties` array contains an entry
  `{ "name": "dep-scan:osv_queried_at", "value": "<rfc3339>" }`.

### T-088-04: Snapshot timestamp is embedded in SPDX output
- Call `render_spdx` with results that carry `OsvQueryContext`.
- The SPDX document contains the OSV snapshot timestamp in a
  `documentDescribes` annotation or a top-level comment field.

### T-088-05: Snapshot timestamp is embedded in VEX output
- Call `render_vex` with results that carry `OsvQueryContext`.
- The OpenVEX root object has `"metadata"` (or equivalent field) containing
  `"osv_queried_at"`.

### T-088-06: When OSV was not queried (e.g. cache-only hit), snapshot is absent
- Build a `Vec<CheckResult>` with no `OsvQueryContext` (all results came
  from cache without a fresh OSV call).
- Rendered output does NOT have a `"osv_snapshot"` key (or the field is
  `null`) — no false freshness claim.

---

## `valid_until` field

### T-088-07: Default `valid_until` is 24 hours after `osv_queried_at`
- Given `osv_queried_at = 2026-06-04T12:00:00Z` and default config
  (`freshness.valid_until_hours = 24`).
- Rendered output contains `"valid_until": "2026-06-05T12:00:00Z"`.

### T-088-08: `valid_until` is present in all four interchange formats
- Render OSV, CycloneDX, SPDX, and VEX with the same `OsvQueryContext`.
- Each rendered string contains a `valid_until` value.

### T-088-09: `freshness.valid_until_hours` config key changes the window
- Set `[freshness] valid_until_hours = 1` in `.dep-scan.toml`.
- Given `osv_queried_at = 2026-06-04T12:00:00Z`.
- Rendered `valid_until` is `"2026-06-04T13:00:00Z"`.

### T-088-10: `freshness.valid_until_hours = 168` (one week) is accepted
- Config with `valid_until_hours = 168` (max reasonable for air-gapped
  environments) loads without error.
- Rendered `valid_until` is 168 hours after `osv_queried_at`.

### T-088-11: Zero `valid_until_hours` is rejected at config parse
- Config with `valid_until_hours = 0` returns `Err` at `Config::load` time.
- Error message mentions `valid_until_hours` must be > 0.

---

## Freshness in the signed payload

### T-088-12: `valid_until` and `osv_queried_at` are inside `payload`, not the envelope
- Sign a rendered OSV JSON payload.
- Decode `base64(envelope.payload)` and confirm the resulting JSON contains
  `"osv_snapshot"` and `"valid_until"`.
- The envelope-level keys (`payload`, `payloadType`, `signatures`) do NOT
  contain freshness fields directly.

### T-088-13: A consumer can extract `valid_until` without verifying the signature
- The freshness fields are in the unencrypted `payload` (base64-decoded JSON),
  readable before signature verification. A consumer can quickly check
  staleness and skip verification of an expired statement.
- Confirmed: `base64::decode(envelope["payload"])` → parse JSON → read
  `valid_until` without calling any verify function.

---

## No online revocation

### T-088-14: No OCSP / CRL / revocation-list calls are made
- Run a full `run_check` with `--format osv` against a wiremock stub.
- The wiremock server captures ALL outbound HTTP requests.
- None of the recorded request URLs contain `ocsp`, `crl`, or `revocation`.
- This confirms the offline guarantee is intact (ADR 006 Q7 rejection of
  online revocation).

---

## `native` and `json` paths unaffected

### T-088-15: `--format native` output contains no freshness fields
- `run_check` with `OutputFormat::Native` writes the human table.
- Stdout does not contain `"valid_until"` or `"osv_snapshot"`.

### T-088-16: `--format json` output contains no freshness fields
- `run_check` with `OutputFormat::Json` writes the raw `CheckResult` array.
- None of the array elements has a `"valid_until"` or `"osv_snapshot"` key.

---

## Config defaults and documentation

### T-088-17: Default `Config` has `freshness.valid_until_hours = 24`
- `Config::default().freshness.valid_until_hours == 24`.

### T-088-18: `config init` emits the `[freshness]` section with default and comment
- Running `dep-scan config init` writes a `.dep-scan.toml` that includes a
  `[freshness]` section with `valid_until_hours = 24` and a comment
  explaining the purpose (e.g. "# How long a signed interchange statement
  is considered fresh; 24h matches the standard CI daily scan cadence.").

---

## Tooling gate

### T-088-19: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

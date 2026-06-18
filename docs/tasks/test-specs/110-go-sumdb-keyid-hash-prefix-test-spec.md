# Test spec — Task 110: go_sumdb key-id derivation `hash:1:` prefix bug

## Context

The Ed25519 signed-note verifier (`src/signed_note.rs`) derives the expected key-id as
`SHA256("hash:1:" + name + "\n" + key)[:4]`. Go's `note.keyHash` has no `"hash:1:"` prefix —
it is `SHA256(name + "\n" + key)[:4]`. The spurious prefix makes the computed key-id
(`9f6cb724`) differ from the real `sum.golang.org` key-id (`033de0ae`, embedded in the pinned
key string), so the verifier never matches a signature line and BLOCKs every real Go module with
`no signature line found for key 'sum.golang.org'`. Existing tests pass only because their
synthetic notes recompute the key-id with the same wrong prefix. See task 110.

## Test cases

### TC-110-01 — key-id derivation matches Go `note.keyHash` (independent ground truth)
- **Assertion:** the key-id derived from `SUMDB_PUBLIC_KEY_STR`
  (`sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8`) equals the bytes
  `[0x03, 0x3d, 0xe0, 0xae]` — i.e. the `033de0ae` hex literally present in the pinned key string.
- **Must be independent:** the expected value is the hard-coded literal `033de0ae`, NOT a value
  recomputed via the production hashing path. This is what makes the test catch a re-introduced
  prefix.

### TC-110-02 — real sum.golang.org note verifies as Valid (recorded fixture)
- **Assertion:** feeding a **real, recorded** signed-note response from
  `sum.golang.org/lookup/github.com/google/uuid@v1.6.0` to the Ed25519 verifier with the pinned
  key returns `NoteVerifyOutcome::Valid`. The fixture is the genuine response captured once and
  stored in-tree so the test is offline/deterministic.
- **Pre-fix behavior (regression guard):** before the fix this returns
  `Invalid { "no signature line found for key 'sum.golang.org'" }`.

### TC-110-03 — end-to-end go_sumdb policy passes a legitimate module
- **Assertion:** `GoSumDbPolicy::evaluate` (or the equivalent policy entry) on
  `github.com/google/uuid@v1.6.0` with the recorded lookup response returns a pass/non-block
  result when `check_go_sumdb = true`.

### TC-110-04 — CLI scan of a real go.sum is green
- **Assertion:** `dep-scan check --registry go --lockfile <go.sum-with-uuid> --lockfile-type go`
  (default config, `check_go_sumdb = true`) reports `github.com/google/uuid v1.6.0  pass` and exits 0.

### TC-110-05 — synthetic-note tests use the corrected derivation
- **Assertion:** the test helpers in `src/policy/go_sumdb.rs` that build synthetic notes compute
  the key-id without the `"hash:1:"` prefix, and the positive/negative sumdb tests still pass under
  the corrected derivation (they no longer encode the bug). The negative test that legitimately
  expects `no signature line found` must keep failing for the right reason (genuinely-absent
  signature), not because of a key-id mismatch.

### TC-110-06 — full gate green
- **Assertion:** `cargo test`, `cargo clippy`, `cargo fmt --check` all pass.

## Verification plan

- **Highest in-repo level:** unit + integration tests (TC-110-01..03, 05) + CLI test (TC-110-04),
  all offline via the recorded fixture.
- **Manual confirmation:** the reproduction in the task file returns `pass` after the fix.

## Out of scope

- The P-256/Rekor key-id path — audited per task AC, fixed only if found wrong (separate concern).
- The sumdb fetch client (`src/registry/go_sumdb.rs`) — unchanged.

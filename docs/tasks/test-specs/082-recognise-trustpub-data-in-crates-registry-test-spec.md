# Test Spec — Task 082: Recognise crates.io `trustpub_data`

## Context

Task 081 surfaced that dep-scan's `maintainer_change` policy fires a false
positive (Block) on `getrandom@0.4.2` because the 0.4.x line is published
via crates.io Trusted Publishing (OIDC). The per-version `published_by`
field is intentionally `null` in that flow; dep-scan today reads only
`published_by` and so sees the maintainer set as empty.

This task adds `trustpub_data` awareness to the crates.io registry client
so the policy sees a stable identity for OIDC-published versions and stops
producing false positives on legitimate Trusted-Publishing transitions.

---

## Parsing

### T-082-01: `CrateVersion` struct gains `trustpub_data`
- The serde struct in `src/registry/crates.rs` deserialises the
  `trustpub_data` field on each version into an optional struct with at
  least `{ provider, repository }`.
- Missing field defaults to `None` (must not break older crates that
  predate Trusted Publishing).

### T-082-02: Unknown / extra fields ignored
- The serde struct must tolerate forward-compatible additions to
  `trustpub_data` (e.g. `run_id`, `sha`) without breaking deserialisation.

---

## Maintainer extraction

### T-082-03: Traditional publish still extracts `published_by`
- When `published_by` is `Some` and `trustpub_data` is `None`, the
  resulting `maintainers` Vec contains exactly `[published_by.login]`
  (regression check against existing behaviour from task 018).

### T-082-04: Trustpub-only publish synthesises a stable label
- When `published_by` is `None` and `trustpub_data` is `Some`, the
  resulting `maintainers` Vec contains exactly one synthetic identity in
  the form `trustpub:<provider>:<repository>`
  (e.g. `trustpub:github:rust-random/getrandom`).

### T-082-05: Both fields present prefers `published_by`
- When both are present (unlikely but possible), `published_by` wins.
  This preserves backwards-compatible behaviour and avoids identity
  churn if crates.io ever populates both for legacy reasons.

### T-082-06: Neither field present → empty Vec
- When both are `None` (very old versions like `getrandom@0.0.0`), the
  `maintainers` Vec is empty. This matches today's behaviour and the
  existing `no_published_by_returns_empty_maintainers` regression test.

---

## Policy integration

### T-082-07: Stable identity across consecutive trustpub versions
- Scanning `getrandom@0.4.0` and then `getrandom@0.4.2` (both trustpub
  from the same repo) results in the same synthetic identity both times,
  so the maintainer-change policy sees Pass, not Warn or Block.

### T-082-08: trustpub repo binding change is detectable
- Scanning a version published via trustpub from `repoA` followed by a
  version published via trustpub from `repoB` (same provider) results
  in a maintainer-change Warn (or Block, on complete changeover) —
  ensuring this task doesn't silently disable the policy when the
  repository binding moves.

### T-082-09: Dogfood gate passes without the 0.4.2 entry
- After 082 lands, removing the
  `getrandom@0.4.2 maintainer_change` entry from
  `.dep-scan-dogfood-allowlist.toml` still results in
  `scripts/dogfood-gate.py` exit 0 on the current `Cargo.lock`.

---

## Tooling gate

### T-082-10: `cargo test`, `cargo clippy --all-targets -- -D warnings`,
and `cargo fmt --check` all pass after the change.

---

## Out of scope

- Cross-checking that the trustpub publish actually originated from the
  bound repo (would require querying GitHub Actions API). The synthetic
  identity treats `trustpub_data.repository` as authoritative.
- Generalising to PyPI / npm trusted publishing — both already have
  dedicated provenance policies.

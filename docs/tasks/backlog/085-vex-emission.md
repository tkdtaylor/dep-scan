# Task 085 — Presence-only VEX emission

**Status:** backlog
**Depends on:** 083 (`OutputFormat` enum), 084 (PURL helper)
**ADR:** 005 (Q3 — VEX depth decision)
**Touches:** `src/main.rs` (render path), new `src/vex.rs` module

## Objective

Wire `--format vex` to emit OpenVEX statements with per-vulnerability status
(`affected` / `fixed` / `under_investigation`) derived from existing OSV data.
Replaces the "not yet implemented" stub from task 083.

## Background

ADR 005 Q3 resolves that dep-scan ships presence-only VEX first. dep-scan
has no reachability analysis today, so it cannot honestly emit `not_affected`
with a reachability justification. That capability is explicitly deferred to
a future ADR and is out of scope here.

Status derivation rule (from OSV `VulnerabilityInfo`):
- `fixed_versions` non-empty → `"fixed"`
- `fixed_versions` empty AND advisory has substantive data (non-empty
  summary or severity) → `"affected"`
- `fixed_versions` empty AND advisory is thin (no summary, no severity) →
  `"under_investigation"`

Packages with no vulnerability findings produce no VEX statements.

## Requirements

### REQ-085-01: Status mapper
Implement `osv_to_vex_status(info: &VulnerabilityInfo) -> &'static str`
returning `"affected"` / `"fixed"` / `"under_investigation"` per the rule
above. Never returns `"not_affected"`.

### REQ-085-02: OpenVEX JSON renderer
Implement `render_vex(results: &[CheckResult]) -> Result<String>` that emits
an OpenVEX JSON document:
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "<urn>",
  "author": "dep-scan",
  "timestamp": "<rfc3339>",
  "statements": [
    {
      "vulnerability": { "id": "<osv-id>" },
      "products": [ { "id": "<purl>" } ],
      "status": "<status>"
    }
  ]
}
```
One statement per `(package, vulnerability)` pair. Reuses `to_purl` from
task 084's shared helper.

### REQ-085-03: Stub replaced
`OutputFormat::Vex` no longer returns "not yet implemented".

## Acceptance criteria

- [ ] `--format vex` exits 0 and writes valid OpenVEX JSON
- [ ] Status derivation covers all three values; `not_affected` is never emitted
- [ ] Packages with no findings contribute no statements
- [ ] All T-085-01 through T-085-16 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/085-vex-emission-test-spec.md`

## Out of scope

- `not_affected` with reachability justification (deferred per ADR 005 Q3)
- Signing the VEX output (task 086)
- Freshness / `valid_until` fields (task 088)

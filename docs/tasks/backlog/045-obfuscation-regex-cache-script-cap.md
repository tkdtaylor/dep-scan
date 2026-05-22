# Task 045 — Obfuscation policy — compile regexes once and cap script size

**Status:** backlog
**Depends on:** 021 (obfuscation detection policy)
**Security finding:** M-1 (MEDIUM)
**Touches:** `src/policy/obfuscation.rs`

## Objective

Eliminate per-call regex compilation in `ObfuscationPolicy::evaluate` by using
`std::sync::OnceLock` and cap each install script's scanned content to 1 MB to
bound worst-case scan time against adversarially large postinstall scripts.

## Background

`ObfuscationPolicy::patterns()` is called on every `evaluate()` invocation and
builds a fresh `Vec<ObfuscationPattern>` that includes calling `Regex::new` for
each pattern.  The `regex` crate is linear-time (no ReDoS risk), but regex
compilation itself is not free.  The `chr\(\d+\).*chr\(\d+\).*chr\(\d+\)`
pattern applied to a multi-MB script on every scan invocation produces
measurable overhead.

npm allows postinstall scripts up to approximately 10 MB.  A package author can
ship a 10 MB postinstall with a clean first megabyte and a payload in the tail.
The 1 MB cap means such a package passes the obfuscation check while failing
more targeted checks (install-script size itself, or the age/popularity
heuristics).  This is an acceptable trade-off documented explicitly here.

## Behavior

### Compile patterns once via `OnceLock`

Replace `fn patterns() -> Vec<ObfuscationPattern>` with a static:

```rust
use std::sync::OnceLock;

static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

fn compiled_patterns() -> &'static [CompiledPattern] {
    PATTERNS.get_or_init(|| {
        vec![
            // same patterns as before, with Regex compiled here once
        ]
    })
}
```

`CompiledPattern` replaces `ObfuscationPattern` with a concrete `Option<Regex>`
field instead of a `&'static str` that is compiled on demand.

### Cap script content to 1 MB

Before pattern matching, truncate each script's content to the scan cap:

```rust
const SCRIPT_SCAN_CAP_BYTES: usize = 1_048_576; // 1 MB

let content_to_scan = &script.content.as_bytes()[..SCRIPT_SCAN_CAP_BYTES.min(script.content.len())];
// Convert back to &str at a valid UTF-8 boundary.
let content_to_scan = match std::str::from_utf8(content_to_scan) {
    Ok(s) => s,
    Err(e) => &script.content[..e.valid_up_to()],
};
```

Matching against `content_to_scan` rather than `script.content` bounds the
worst-case work per script.

## Requirements

- **REQ-045-01:** Regex patterns are compiled at most once per process lifetime,
  not once per `evaluate()` call.
- **REQ-045-02:** Multiple concurrent calls to `evaluate()` from different
  threads are safe — `OnceLock` ensures exactly-once initialization.
- **REQ-045-03:** The portion of each script content that is scanned is capped
  at `SCRIPT_SCAN_CAP_BYTES` (1,048,576 bytes).
- **REQ-045-04:** Content shorter than the cap is scanned in full (the cap does
  not pad or truncate shorter scripts).
- **REQ-045-05:** Existing detection behavior for scripts under 1 MB is
  unchanged; all T-021-* tests continue to pass.

## Acceptance criteria

- [ ] `Regex::new` (or equivalent) is not called inside `evaluate` (REQ-045-01); verified by T-045-11.
- [ ] Concurrent calls do not panic (REQ-045-02); verified by T-045-05.
- [ ] Payload beyond 1 MB is not detected (REQ-045-03); verified by T-045-08.
- [ ] Payload within 512 KB is detected (REQ-045-04); verified by T-045-06.
- [ ] Cap constant is named (REQ-045-03); verified by T-045-12.
- [ ] All T-021-01 – T-021-11 tests pass (REQ-045-05); verified by T-045-14.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Parallelizing the pattern-matching loop across scripts.
- Streaming large scripts — content is already in memory from the registry fetch.
- Changing the cap value based on configuration — the 1 MB cap is hardcoded.
  If per-policy configuration is needed, that is a separate task.

## Risk notes

- A malicious npm package could front-load clean content and place a payload
  exactly at byte 1,048,577.  This would evade the obfuscation check.  The cap
  is documented here so that future maintainers can adjust it.  The age,
  popularity, and install-script-presence checks provide defense-in-depth.
- `str::from_utf8` truncation at a valid UTF-8 boundary may crop 1–3 bytes from
  the cap for multi-byte characters straddling the limit.  This is negligible;
  a 3-byte crop does not matter for pattern matching.

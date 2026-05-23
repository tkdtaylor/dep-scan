# Test Spec — Task 081: Investigate getrandom maintainer changes

## Context

The post-078 dogfood run flagged two `getrandom` maintainer-change
verdicts. They may be legitimate rust-random org rotations or may be a
real security signal. This task is the investigation; its output is a
memo, not a code change. Verification is therefore mostly structural
(the memo exists, has the right sections, the conclusion is honored).

---

## Memo content

### T-081-01: Memo file exists
- `docs/security/getrandom-maintainer-investigation.md` exists.

### T-081-02: Memo has date + investigator
- Memo opens with a `**Investigated:** YYYY-MM-DD by <name>` line.

### T-081-03: Dep-scan output captured
- Memo includes the verbose dep-scan output for at least one of the
  two flagged versions (sanitized of irrelevant noise; the maintainer-
  change line and surrounding context are present).

### T-081-04: crates.io snapshot captured
- Memo includes a paste of the current owners list from
  `crates.io/crates/getrandom`, with retrieval timestamp.

### T-081-05: GitHub repo cross-check captured
- Memo names the `rust-random/getrandom` org members or CODEOWNERS at
  investigation time, plus who tagged the 0.3.4 and 0.4.2 releases.

### T-081-06: Verdict line present
- Memo contains exactly one of:
  - `**Verdict:** BENIGN`
  - `**Verdict:** SUSPICIOUS`
  - `**Verdict:** NEED MORE INFO`

### T-081-07: Recommended action present
- Memo contains a "Recommended action:" line describing what should
  happen next (allowlist / escalate / investigate further).

---

## If verdict is BENIGN

### T-081-08: Allowlist populated with real justification
- `.dep-scan-dogfood-allowlist.toml` contains two `[[allow]]` entries
  for `getrandom` (0.3.4 and 0.4.2, policy `maintainer_change`).
- Each entry's `justification` field is **non-placeholder** — it
  references the investigation memo by path and summarizes the finding
  in one sentence.
- Each entry has `opened_at` set to the investigation date.

### T-081-09: Allowlist entries have no `expires`
- Maintainer-change verdicts don't auto-resolve. Allowlist entries
  for them MUST NOT carry an `expires` date — the next maintainer
  rotation re-fires the policy and forces a fresh investigation.

### T-081-10: Dogfood gate passes
- `cargo build --release && ./target/release/dep-scan check --lockfile
  Cargo.lock --lockfile-type crates --json 2>/dev/null |
  scripts/dogfood-gate.py` exits 0.

---

## If verdict is SUSPICIOUS or NEED MORE INFO

### T-081-11: No allowlist entries added
- `.dep-scan-dogfood-allowlist.toml` does NOT contain `getrandom`
  entries.

### T-081-12: GitHub issue referenced
- Memo links to a (public or private) GitHub issue containing the
  investigation findings.

### T-081-13: Dogfood gate continues to fail on these blocks
- The CI failure is the correct outcome. The task's purpose is the
  investigation, not the allowlist.

---

## Bug discovery

### T-081-14: If a dep-scan parser bug was found, it's filed
- If the investigation identifies a maintainer-list-parsing bug in
  dep-scan (e.g. the empty-array case in the maintainer-change diff
  format), a follow-up task file is created in
  `docs/tasks/backlog/` with the bug details.

---

## Closing T-067-08

### T-081-15: Coverage-tracker row 067 → 10/10 ✅
- Once 081 (BENIGN path) + 079 + 080 have all landed, the dogfood gate
  passes against current main. At that point, `coverage-tracker.md` row
  067 is updated:
  - From: `9/10 | ⏳ T-067-08 blocked by 079/080/081 …`
  - To:   `10/10 | ✅`
- This update can ride in 081's commit (if 081 is the last) or in
  whatever commit lands last.

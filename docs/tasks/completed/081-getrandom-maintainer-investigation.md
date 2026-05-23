# Task 081 — Investigate `getrandom` maintainer changes

**Status:** completed (2026-05-22)
**Verdict:** BENIGN — see `docs/security/getrandom-maintainer-investigation.md`
**Follow-up:** task 082 — recognise crates.io `trustpub_data` so the empty
`added []` diff stops mis-firing on Trusted-Publishing transitions.
**Depends on:** 079 (allowlist mechanism); investigation findings populate
the allowlist entries that 079 seeds with placeholders
**Source:** Surfaced by task 067 dogfood run; two of five remaining real
block verdicts
**Touches:** `docs/security/getrandom-maintainer-investigation.md` (new),
`.dep-scan-dogfood-allowlist.toml` (populate justifications)

## Severity: MEDIUM (security investigation, possibly HIGH)

Dep-scan's maintainer-change policy fired on `getrandom@0.3.4` and
`getrandom@0.4.2` with the messages:

```
getrandom@0.3.4: removed [newpavlov], added [josephlr]
getrandom@0.4.2: removed [josephlr], added []
```

Either of these COULD be a legitimate rust-random org maintainer rotation,
OR could be an indicator of a compromised or hostile takeover. We don't
know which yet. The fix is to **investigate**, document the findings, and
either allowlist (benign) or escalate (real signal).

`getrandom` is one of the most security-sensitive transitive dependencies
in the Rust ecosystem — it's the source of cryptographic randomness for
countless downstream consumers. Getting this wrong is bad.

## Objective

Produce a written investigation memo. Decide based on the memo whether
to allowlist or escalate.

## Investigation checklist

The agent / maintainer doing this task must work through ALL of these
before writing the verdict:

1. **Confirm the maintainer set dep-scan saw** for each version. Re-run
   the scan with `--verbose` and confirm the JSON output matches.
2. **Cross-check on crates.io** — view the actual maintainer list for
   `getrandom` on `https://crates.io/crates/getrandom`. Note the current
   set. Note when historic versions show different sets if visible.
3. **Cross-check the upstream repo** — `rust-random/getrandom` on
   GitHub. Look at the CODEOWNERS or maintainer list. Look at release
   PRs for 0.3.4 and 0.4.2 specifically. Who tagged the release? Who
   pushed to crates.io?
4. **Look at the broader rust-random org** — is `josephlr` a known
   contributor across the org's other crates (`rand`, `rand_chacha`,
   `rand_core`, etc.)? Is `newpavlov` (David Pavlov / `dhuseby` /
   similar) a known org member?
5. **Check the org's GitHub for any incident reports** — RustSec
   advisories, GitHub Security Advisories, or maintainer-team blog
   posts in the last year.
6. **Optionally confirm via sigstore** — if `getrandom` 0.3.4 or 0.4.2
   were published with sigstore attestations, verify the publisher
   identity matches the org's documented maintainers. (crates.io
   provenance is on the roadmap but not yet GA — this may not be
   possible today.)
7. **Compare to historic maintainer-change patterns in the rust-random
   org.** Other crates in the org are reviewed by the same team; if
   the same `josephlr` shows up as the publisher across multiple
   recent releases, that's strong evidence of legitimate org rotation.

## Background note on the dep-scan output

The "added []" on `getrandom@0.4.2` is suspicious-looking but may be a
data artifact: crates.io's API returns the **current** owner set when
queried, not the owner set as it was at publish time. If a maintainer
rotation happened between 0.3.4's publish and now, dep-scan's
maintainer-history table compares the cached set from when we last
scanned 0.3.4 (with josephlr) against the current set on 0.4.2 (which
might be empty or might be the new owner — the JSON parser may also
have stripped a single-member list incorrectly).

The investigation should determine whether "added []" is **(a)** a real
"no current maintainers" state on crates.io, **(b)** a parser bug in
dep-scan's crates.io owner-list handling, or **(c)** a quirk of how
maintainer-change diffs format the empty-set case.

If (b), file a follow-up code-fix task.

## Behavior

1. Create `docs/security/getrandom-maintainer-investigation.md` with:
   - Date and investigator
   - Output of `dep-scan check --verbose --lockfile Cargo.lock` for both
     versions
   - crates.io maintainer list snapshots (paste, with retrieval date)
   - GitHub repo maintainer / CODEOWNERS / release-tagger findings
   - Cross-reference to other rust-random org releases
   - **Verdict: BENIGN / SUSPICIOUS / NEED MORE INFO**
   - Recommended action

2. If verdict is BENIGN:
   - Update `.dep-scan-dogfood-allowlist.toml` (created by task 079)
     replacing the placeholder justifications with concrete findings.
     Reference the investigation memo by path.
   - No `expires` date — maintainer changes don't auto-resolve like ages.
3. If verdict is SUSPICIOUS or NEED MORE INFO:
   - DO NOT allowlist. The CI failure is the correct outcome.
   - Open a GitHub issue (private if hostile-takeover signal); link from
     the memo.
   - Consider whether to pin `getrandom` away from the suspicious
     versions in our own Cargo.lock.

4. After whichever action above:
   - Update task 081's task file with the verdict.
   - Re-run dogfood scan; if BENIGN and allowlist populated, expect
     gate to pass.

## Acceptance criteria

- [ ] `docs/security/getrandom-maintainer-investigation.md` exists with
      all 7 investigation-checklist items addressed
- [ ] A clear "Verdict: …" line is present in the memo
- [ ] If verdict is BENIGN: allowlist entries for both `getrandom@0.3.4`
      and `getrandom@0.4.2` carry the real justification (not placeholder)
      and reference the memo
- [ ] If verdict is SUSPICIOUS: a GitHub issue is filed and linked from
      the memo; allowlist is NOT populated for these entries
- [ ] If the investigation identified a dep-scan parser bug, a follow-up
      task is created
- [ ] Memo includes the date of investigation so future re-checks have
      a reference point

## Out of scope

- Fixing crates.io's maintainer-history surface (out of dep-scan's
  control)
- Building a "live owner-list-as-of-publish-time" feature into dep-scan
  (would require historical crates.io data we don't currently retrieve)
- Re-investigating after every release of `getrandom` — the memo's
  verdict is good until the maintainer set changes again

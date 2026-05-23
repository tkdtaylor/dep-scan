# Task 079 — Dogfood allowlist mechanism for justified block verdicts

**Status:** backlog
**Depends on:** none (but logically lands after 080 so the typosquat false positive isn't in the initial allowlist)
**Source:** Surfaced by task 067 dogfood run — 5 real block verdicts on dep-scan's own Cargo.lock, of which several need acknowledgment rather than code fixes (transient ages, investigated-and-benign maintainer changes)
**Touches:** `.github/workflows/ci.yml` (dogfood step), `.dep-scan-dogfood-allowlist.toml` (new, repo root), `README.md` (one-line callout)

## Severity: MEDIUM (CI plumbing)

Not a security fix per se — this is the structural plumbing needed for
task 067's dogfood CI job to be useful long-term. Without it the gate is
either too strict (CI flakes on transient age verdicts every time a dep
publishes a new version) or absent (we ignore real verdicts).

## Objective

Add a small allowlist mechanism, scoped to the dogfood CI step, that lets
the maintainer record "this block verdict is acknowledged" with a
justification and an optional expiry. The dogfood CI step reads the
allowlist, downgrades matched blocks to GitHub-Actions `::warning::`
annotations, and only fails the build on unmatched blocks.

The allowlist is **metadata for the CI step**, not a feature of dep-scan
itself. dep-scan continues to report what it sees; the dogfood gate
decides which blocks fail the build.

## Background — three classes of "real" blocks

From the post-078 dogfood run:

| Class | Example | Right response |
|-------|---------|----------------|
| **Transient age** | `serde_json@1.0.150` flagged at 20h old | Wait 28h, problem resolves itself. Allowlist with `expires` = +48h. |
| **Investigated-benign maintainer change** | `getrandom@0.3.4` rotation | Document the investigation, add allowlist entry pointing at the writeup. |
| **Real signal that should block** | (hypothetical) some package gets sold to a hostile new maintainer | Don't allowlist. The CI failure is the point. |

The mechanism MUST make the second case painless (so we don't lose CI signal
on the third).

## File format — `.dep-scan-dogfood-allowlist.toml`

```toml
# Each [[allow]] entry suppresses a specific (package, policy, version)
# block verdict in the dogfood CI step ONLY. dep-scan itself still reports
# the block; CI logs it as ::warning:: instead of ::error:: when matched.
#
# Required fields: package, policy, justification, opened_at
# Optional fields: version (exact match; omit for any version),
#                  expires (ISO date; entry inert after this date)

[[allow]]
package = "serde_json"
version = "1.0.150"
policy = "age"
justification = "Transient — serde_json publishes a new patch every few weeks; this one's only 20h old at audit time."
opened_at = "2026-05-22"
expires = "2026-05-24"
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `package` | yes | Crate name; must match `package` field in dep-scan JSON output |
| `version` | no | Exact-match string; omitted matches any version |
| `policy` | yes | Policy name from dep-scan output (`age`, `maintainer_change`, `typosquatting`, etc.) |
| `justification` | yes | Free text; the CI script surfaces this in the annotation |
| `opened_at` | yes | ISO date; helps the maintainer track stale entries |
| `expires` | no | ISO date; entry inert after this date (allows transient ages to auto-tighten) |

## Behavior

### 1. CI script change

Replace the inline Python verdict-counter in `.github/workflows/ci.yml`'s
`dogfood` job with a small standalone script `scripts/dogfood-gate.py` (or
keep inline if short) that:

1. Reads `dep-scan check --json` output from stdin (or a file).
2. Reads `.dep-scan-dogfood-allowlist.toml` from repo root (absent file =
   empty allowlist).
3. For each block verdict in the output:
   - Look up matching allowlist entries (`package == p`, `policy in
     reasons`, `(version omitted OR version == v)`, `expires >= today OR
     expires omitted`).
   - Match found ⇒ emit `::warning file=Cargo.lock::pkg=<p>@<v> policy=<pol>
     [allowlisted] <justification>`.
   - No match ⇒ emit `::error file=Cargo.lock::pkg=<p>@<v> policy=<pol>
     <reason>`. Build fails.
4. For each warn verdict: existing behavior (emit `::warning::`).
5. Exit code: 0 if all blocks were allowlisted (or none), 1 if any
   unmatched block remains.

### 2. New allowlist file

Seed `.dep-scan-dogfood-allowlist.toml` with the 4 currently-known
acknowledgments (`autocfg@1.5.1` age, `serde_json@1.0.150` age,
`getrandom@0.3.4` maintainer, `getrandom@0.4.2` maintainer). The maintainer
investigation findings (task 081) become the justification text for the
getrandom entries; for now use a placeholder like "blocked pending task
081 investigation" so the entries exist but the writeup is tracked.

Note: the `version_check` typosquat is addressed by **task 080** in code,
not by allowlist — that's the right shape for a wrong-data bug.

### 3. Documentation

- A `## Allowlist policy` subsection under `## Dogfood` in README.md (or
  wherever the dogfood feature is documented) explaining: what the file
  is, when to add an entry, how to write a good justification, why
  `expires` exists.
- The dogfood task file (`docs/tasks/completed/067-…`) gets a closing
  note pointing at the allowlist.

### 4. CI step integration

Update the `dogfood` job in `.github/workflows/ci.yml` to call the gate
script instead of the inline Python.

## Acceptance criteria

- [ ] `.dep-scan-dogfood-allowlist.toml` exists at repo root with a
      header comment explaining format
- [ ] `scripts/dogfood-gate.py` (or equivalent inline) reads the
      allowlist + dep-scan JSON and applies the matching rules above
- [ ] Current 4 known-acknowledged blocks (post-task-080) are
      allowlisted with `opened_at = 2026-05-22`
- [ ] Two of the four entries (the age blocks) carry `expires` dates
      ~48h after the publish dates
- [ ] `dogfood` CI job in `ci.yml` calls the gate script
- [ ] Local run of the CI script against current main exits 0
- [ ] If `version_check` typosquat still fires (task 080 not yet landed),
      it is NOT in the allowlist — it must be fixed in code
- [ ] README.md (or dedicated doc) explains the allowlist policy
- [ ] T-067-08 finally satisfied — coverage-tracker row 067 → `10/10 ✅`
      in the same commit as this task's completion

## Out of scope

- A `dep-scan`-level allowlist feature (would change the binary's
  contract). The allowlist here is CI-step metadata, intentionally narrow.
- An allowlist that exempts from age policy globally — only the dogfood
  CI step consults this file.
- Sigstore-signing the allowlist file — for now it's just version-
  controlled YAML/TOML in git; the maintainer's commit signature is the
  authorization gate.

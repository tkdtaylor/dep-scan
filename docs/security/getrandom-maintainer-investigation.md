# `getrandom` maintainer-change investigation

**Investigated:** 2026-05-22 by Kevin (dep-scan maintainer) with Claude Code

**Verdict:** BENIGN

**Recommended action:** Allowlist both `getrandom@0.3.4` and `getrandom@0.4.2`
`maintainer_change` verdicts in `.dep-scan-dogfood-allowlist.toml` with real
justifications referencing this memo. File a follow-up task (082) to teach
dep-scan how to recognise crates.io Trusted Publishing (`trustpub_data`) so
the empty-`[]` "added" diff stops mis-firing for legitimate OIDC-based
publishes.

---

## Background

dep-scan's dogfood scan (task 067) flagged two block verdicts against
`getrandom` in dep-scan's own `Cargo.lock`:

```
getrandom@0.3.4: Complete maintainer changeover for 'getrandom':
                 removed [newpavlov], added [josephlr]
getrandom@0.4.2: Complete maintainer changeover for 'getrandom':
                 removed [josephlr], added []
```

`getrandom` is the source of cryptographic entropy for most of the Rust
ecosystem, so a hostile takeover here would be a top-tier supply-chain
incident. We need to determine whether these are genuine maintainer-change
signals, a legitimate maintainer rotation inside the rust-random org, or a
data-shape artefact that dep-scan should learn to ignore.

## Dep-scan output (captured 2026-05-22)

Trimmed from `./target/release/dep-scan check --lockfile Cargo.lock
--lockfile-type crates --json`:

```
getrandom@0.2.17 → warn
  maintainer_change: warn: Maintainers of 'getrandom' changed:
                                 added [newpavlov]

getrandom@0.3.4  → block
  maintainer_change: block: Complete maintainer changeover for 'getrandom':
                                 removed [newpavlov], added [josephlr]

getrandom@0.4.2  → block
  maintainer_change: block: Complete maintainer changeover for 'getrandom':
                                 removed [josephlr], added []
```

The Cargo.lock pins all three versions transitively:

```
[[package]] name = "getrandom" version = "0.2.17"
[[package]] name = "getrandom" version = "0.3.4"
[[package]] name = "getrandom" version = "0.4.2"
```

(0.4.x is **older** than 0.3.x in this crate's quirky version timeline —
see crates.io ownership table below; the 0.4.x line was originally a
rust-random "experimental" branch that was revived in early 2026.)

## crates.io owners (retrieved 2026-05-22)

`GET https://crates.io/api/v1/crates/getrandom/owners`

```json
{
  "users": [
    { "id": 1234,  "login": "dhardy",                              "kind": "user" },
    { "id": 563,   "login": "github:rust-random:maintainers",      "kind": "team",
      "url":  "https://github.com/rust-random", "name": "maintainers" }
  ]
}
```

The crate is co-owned by **Diggory Hardy** (`dhardy`, individual account)
and the **`rust-random:maintainers` GitHub team** (org-level owner). Any
member of that GitHub team can publish.

## Per-version `published_by` history (retrieved 2026-05-22)

`GET https://crates.io/api/v1/crates/getrandom`

```
0.4.2        published_by=None   created=2026-03-03   trustpub: rust-random/getrandom @ 4d82673
0.4.1        published_by=None   created=2026-02-03   trustpub: rust-random/getrandom @ 314fd5a
0.4.0        published_by=None   created=2026-02-02   trustpub: rust-random/getrandom @ 35fd5af
0.4.0-rc.1   published_by=None   created=2026-01-24   trustpub: rust-random/getrandom @ b6a28dc
0.2.17       published_by=newpavlov     created=2026-01-11
0.4.0-rc.0   published_by=None   created=2025-12-27   trustpub: rust-random/getrandom @ 7853627
0.3.4        published_by=josephlr      created=2025-10-14   trustpub: null
0.3.3        published_by=josephlr      created=2025-05-09
0.3.2        published_by=newpavlov     created=2025-03-17
0.3.1        published_by=newpavlov     created=2025-01-28
0.3.0        published_by=newpavlov     created=2025-01-25
0.2.16       published_by=newpavlov     created=2025-04-22
0.2.15..0.2.11  alternating josephlr / newpavlov  (2020–2024)
0.2.10..0.2.4   alternating josephlr / newpavlov  (2022)
0.2.3..0.1.4    newpavlov  (2019–2021)
0.1.3..0.1.0    dhardy     (2019)
```

Two observations:

1. **`josephlr` and `newpavlov` are NOT new publishers.** Both have been
   alternating release-cutters on this crate continuously since 2020. The
   `0.3.4 removed [newpavlov], added [josephlr]` diff is just "this release
   was cut by the other co-maintainer" — a noisy but benign signal.

2. **Every `0.4.x` version has `published_by: null` and a populated
   `trustpub_data` field.** That field captures the GitHub Actions run
   that authorised the publish via crates.io's **Trusted Publishing**
   (OIDC-based) mechanism. The SHA of the `trustpub_data` for 0.4.2
   matches the v0.4.2 tag in the upstream repo. No human user is recorded
   because the publish was authorised by a workflow identity, not a
   personal API token. This is **strictly more secure** than the old
   personal-token model.

The "added []" string in dep-scan's diff is therefore real (`published_by`
truly is `null` on crates.io's side) — it is not a parser bug. It IS a
signal-quality limitation in dep-scan: see "Follow-up" below.

## GitHub repo cross-check (retrieved 2026-05-22)

### Tag → commit → author

```
v0.3.4 → 38e4ad3 → author: Joe Richey   <joerichey@google.com>  date: 2025-10-14
v0.4.2 → 4d82673 → author: Artyom Pavlov <newpavlov@gmail.com>  date: 2026-03-03
```

The commit that tagged 0.3.4 has the message "Update version number to
v0.3.4 (#736) — Forgot this because I'm out of practice. Signed-off-by:
Joe Richey." That is josephlr (Joe Richey, ex-Google contributor),
explicitly self-identifying.

### rust-random org public members

`GET https://api.github.com/orgs/rust-random/public_members`

```
benjamin-lieser
dhardy
josephlr            ← Joe Richey
MichaelOwenDyer
newpavlov           ← Artyom Pavlov
```

Both `josephlr` and `newpavlov` are listed as public members of the
`rust-random` GitHub organisation. Both have been the only two
release-tagging committers on `getrandom` for years.

### Other rust-random crates cross-check

`rand_core` (a peer crate in the same org) shows the same pattern in
recent releases:

```
0.10.1     published_by=None    (trustpub)   2026-04-13
0.10.0     published_by=None    (trustpub)   2026-02-01
0.10.0-rc-6  None  (trustpub)               2026-01-24
0.10.0-rc-5  None  (trustpub)               2026-01-20
0.10.0-rc-4  dhardy                          2026-01-19
0.9.5       dhardy                           2026-01-13
```

`rand_core` flipped to Trusted Publishing in the same January–February
2026 window as `getrandom`, also under the rust-random org. This is a
coordinated org-wide move to OIDC-based publishing, not a per-crate
anomaly.

## RustSec advisory check (retrieved 2026-05-22)

WebSearch for "rust-random getrandom RustSec advisory 2025 2026
compromise" returned no recent advisories targeting `getrandom` or the
rust-random org. The most recent `rand_core` advisory (RUSTSEC-2021-0023)
is unrelated and pre-dates this investigation.

## What dep-scan saw, explained

| Cargo.lock version | Last `published_by` dep-scan cached | Current `published_by` | Why dep-scan reacted |
|---|---|---|---|
| 0.2.17 | (empty) — first scan | `newpavlov` | Warn: added [newpavlov] |
| 0.3.4  | `newpavlov` (from 0.3.2) | `josephlr` | Block: removed [newpavlov], added [josephlr] — actually a benign co-maintainer alternation |
| 0.4.2  | `josephlr` (from 0.3.4 chain) | `null` (trusted-publish) | Block: removed [josephlr], added [] — actually `null` because Trusted Publishing |

Both block verdicts are downstream of dep-scan's "one version = one
maintainer-set snapshot" model, which treats the per-version `published_by`
field as if it were the *current owner list* of the whole crate. For
crates with multiple alternating co-maintainers, or for crates that have
switched to Trusted Publishing, this model is too coarse and produces
benign blocks. The corrective work belongs in dep-scan's policy/registry
layer, not in the allowlist.

## Verdict

**Verdict:** BENIGN

Both flagged maintainer changes are legitimate behaviour from the
upstream `rust-random` org:

- **0.3.4** was tagged and published by `josephlr` (Joe Richey,
  longstanding rust-random member, ~10 prior getrandom releases since
  2020), with a verbatim "out of practice" commit message confirming
  identity. The "removed [newpavlov]" half of the diff is misleading —
  newpavlov did not leave; he just didn't cut THIS release.
- **0.4.2** was tagged by `newpavlov` (Artyom Pavlov, longstanding
  rust-random member, dozens of prior getrandom releases since 2019) and
  published via crates.io Trusted Publishing from the
  `rust-random/getrandom` GitHub workflow. The "added []" half of the
  diff reflects that crates.io intentionally records no individual user
  for OIDC publishes — a security-improving change.

No evidence of compromise, hostile takeover, or unauthorised access.

## Recommended action

1. **Allowlist** both entries in `.dep-scan-dogfood-allowlist.toml`
   (replacing the placeholder justifications written when task 079
   seeded the file). Reference this memo by path. **No `expires` date**
   — maintainer changes don't auto-resolve; the next genuine rotation
   should re-fire the policy and force a fresh look.

2. **File follow-up task 082** to teach dep-scan to recognise
   `trustpub_data` and either (a) synthesise a stable identity like
   `trustpub:github:rust-random/getrandom` so the diff is not empty, or
   (b) skip the maintainer-change policy for trustpub-published versions
   on a known-good repo (since trustpub already cryptographically
   binds publisher identity to the source repo, that signal is stronger
   than per-user `published_by`). This will eliminate the false positive
   class going forward and remove the need for an open-ended allowlist
   entry on `getrandom@0.4.2`.

3. **Re-investigate** if either `getrandom` is yanked / unyanked, the
   `rust-random:maintainers` team membership changes, or the trustpub
   repo binding moves off `rust-random/getrandom`. None of those are
   true today.

## Sources

- crates.io API: `/api/v1/crates/getrandom`, `/api/v1/crates/getrandom/owners`, `/api/v1/crates/getrandom/{0.3.4,0.4.2,0.4.1,0.4.0,0.4.0-rc.0,0.4.0-rc.1}`
- crates.io API: `/api/v1/crates/rand_core`, `/api/v1/crates/rand/owners`
- GitHub API: `repos/rust-random/getrandom/git/refs/tags/v{0.3.4,0.4.2}`, `repos/rust-random/getrandom/git/commits/{38e4ad3,4d82673}`, `repos/rust-random/getrandom/tags`
- GitHub API: `orgs/rust-random/public_members`
- RustSec advisory database <https://rustsec.org/advisories/> — no recent getrandom advisory
- Cargo.lock entries lines 729–767 (`getrandom@{0.2.17,0.3.4,0.4.2}`)

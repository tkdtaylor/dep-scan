# Task 078 — Lockfile scanner uses pinned versions, not registry "latest"

**Status:** backlog
**Depends on:** none (independent fix; required to unblock T-067-08)
**Source:** Surfaced by task 067 (dogfood) local dry-run on 2026-05-22
**Touches:** `src/main.rs`

## Severity: HIGH

This is a security-correctness bug, not a polish item. `dep-scan check
--lockfile <path>` does NOT actually verify the bytes the lockfile pins — it
verifies whatever the registry currently serves as the latest version of
each named package. A real republish attack against an old pinned version
would slip through this scanner today.

## Objective

When packages come from a lockfile, propagate the pinned version through to
`Registry::get_metadata(name, Some(&version))` so the scan operates on the
lockfile-pinned bytes, not the registry's current "latest". CLI-supplied
package names (without a version) MUST continue to query latest.

## Background — exact code path

[`src/main.rs:269-282`](../../src/main.rs#L269-L282):

```rust
let mut all_packages = packages;            // packages: Vec<String> from CLI args
…
let deps = lockfile::parse(lf_path, format)?;   // Vec<LockfileDependency> with .name + .version
…
for dep in deps {
    all_packages.push(dep.name);            // ← BUG: .version is discarded
}
```

[`src/main.rs:380-408`](../../src/main.rs#L380-L408):

```rust
for pkg_name in &all_packages {
    …
    let fetch_result = match reg_type {
        RegistryType::Npm => client.get_metadata(pkg_name, None).await,    // ← BUG: None for version
        RegistryType::PyPI => client.get_metadata(pkg_name, None).await,
        RegistryType::Crates => client.get_metadata(pkg_name, None).await,
        RegistryType::Go => client.get_metadata(pkg_name, None).await,
    };
```

`Registry::get_metadata(name, version: Option<&str>)` — `None` means "use
latest"; `Some(v)` means "fetch this specific version". The lockfile branch
should produce `Some(v)`; the CLI-arg branch should produce `None`.

## Why this is a real security bug, not just a UX nit

Spec [behaviors.md B-004](../../docs/spec/behaviors.md#b-004-scan-a-package-via-the-policy-pipeline)
says: "Fetch metadata from registry R → resolved version is the version
string from the registry's metadata response". For lockfile-driven scans
that's the wrong contract — the resolved version should be the **pinned
version from the lockfile**. Otherwise:

1. **Republish attack misses the attack window.** A malicious actor
   republishes `pkg@1.0.0`. dep-scan, asked to verify a lockfile that pins
   `1.0.0`, instead queries the registry for "latest" — which is the
   attacker's new payload that the lockfile no longer reflects. The age
   policy says "this is brand new" because the republish IS recent — but
   the age policy block is misleading, since the user's actual bytes are
   the old pinned ones.

2. **Cache key drifts off the lockfile.** Cache rows get keyed by the
   registry's current resolved version, not by the lockfile-pinned version
   the user actually has on disk. A later CI run against the same lockfile
   gets a stale cache hit on the wrong bytes.

3. **Worst — silent skip of a real attack.** If the registry currently
   serves a non-malicious `1.0.1` and the lockfile pins a malicious-since-
   republished `1.0.0`, dep-scan reports "all green" because it never looked
   at `1.0.0`'s metadata. The user installs the malicious `1.0.0` from the
   lockfile while dep-scan said it was fine.

The dogfood CI job (task 067) exists precisely to surface this kind of
hole. It worked — the very first run flagged 13 false-positive blocks, all
of which trace back to this bug.

## Behavior

1. Change `all_packages: Vec<String>` to `Vec<PackageRef>` where:
   ```rust
   struct PackageRef {
       name: String,
       version: Option<String>,
   }
   ```
   - CLI-arg packages: `PackageRef { name, version: None }`.
   - Lockfile entries with a non-empty `version` field:
     `PackageRef { name: dep.name, version: Some(dep.version) }`.
   - Lockfile entries with an empty `version` field (bare names in
     `requirements.txt`): `PackageRef { name, version: None }` — these are
     genuinely "no version pinned" and SHOULD query latest.

2. In the scan loop, pass `pkg_ref.version.as_deref()` to `get_metadata`.

3. Cache keying is already on `metadata.version` (the resolved version
   returned by the registry client) — that continues to work correctly,
   since registries return the requested version when asked for one.

4. Spec sync — update [behaviors.md B-004](../../docs/spec/behaviors.md):
   add a sentence stating that for lockfile-driven scans, the resolved
   version is the **pinned** version from the lockfile (which the registry
   client returns when asked for that specific version), not registry
   latest.

5. Verbose output: the `Checking <pkg> on <reg>...` line should include
   the version when known: `Checking <pkg>@<version> on <reg>...`.

## Acceptance criteria

- [ ] CLI-arg scans still work (no regression): `dep-scan check lodash
      --registry npm` produces the same output as before.
- [ ] Lockfile scans use the pinned version: `dep-scan check --lockfile
      Cargo.lock --lockfile-type crates --verbose` shows
      `Checking serde@1.0.214 on crates...` (or similar — version matches
      Cargo.lock, not crates.io latest).
- [ ] Dog-food CI job (task 067) now produces zero block verdicts on
      current main. Re-verify locally with the exact CI command:
      ```
      cargo build --release
      ./target/release/dep-scan check --lockfile Cargo.lock \
          --lockfile-type crates --json > /tmp/dogfood.json
      jq '.packages[] | select(.result == "block")' /tmp/dogfood.json
      ```
      Returns empty.
- [ ] T-067-08 is satisfied — coverage-tracker row 067 goes back to
      `10/10 | ✅` in the same commit or immediately following.
- [ ] `behaviors.md` B-004 updated to reflect lockfile-pinned-version
      contract.
- [ ] All 788 existing tests still pass.
- [ ] New unit tests cover: (a) the CLI-arg path passes `None`, (b) the
      lockfile path passes `Some(version)`, (c) requirements.txt bare names
      pass `None`.

## Out of scope

- Refactoring the lockfile parsing layer itself (already works; the bug is
  at the consumer).
- Adding lockfile parsing for new ecosystems (npm package-lock.json, etc.
  are unchanged by this fix).
- Cache-key changes (cache already keys on resolved version, which now
  matches the pinned version — no change needed).

## Known limitations surfaced by dogfood self-check

After the fix, the dogfood self-check against the project's own `Cargo.lock`
produces 5 block verdicts. These are **legitimate policy verdicts** on the
correct pinned versions — they are not bugs introduced by this fix.

| Package | Verdict | Reason |
|---------|---------|--------|
| `autocfg@1.5.1` | block | Age policy: recently published (< 48h at time of scan) |
| `getrandom@0.3.4` | block | Maintainer change: removed [newpavlov], added [josephlr] |
| `getrandom@0.4.2` | block | Complete maintainer changeover: removed [josephlr], added [] |
| `serde_json@1.0.150` | block | Age policy: recently published (< 48h at time of scan) |
| `version_check@0.9.5` | block | Typosquatting: similar to popular package `version-check` (Levenshtein distance ≤ 1) |

The `version_check` crate is a well-known legitimate crate (used by the Rust
ecosystem) that happens to be named very similarly to a popular package. The
typosquatting policy correctly flags it as suspicious by design. Suppressing
this false positive would require adding `version_check` to a trusted-name
allowlist or adjusting the Levenshtein threshold — both are out of scope for
this fix. The age and maintainer-change verdicts are transient (they will
clear as the packages age past 48h or the maintainer baseline is established).

# Task 082 — Recognise crates.io Trusted Publishing (`trustpub_data`)

**Status:** backlog
**Depends on:** 081 (surfaced the limitation; this task fixes the root cause)
**Source:** Surfaced by task 081 — getrandom maintainer-change investigation
**Touches:** `src/registry/crates.rs`, `src/policy/maintainer.rs` (maybe),
`src/types.rs` (maybe — depends on chosen approach)

## Severity: MEDIUM (signal-quality / false-positive reduction)

## Problem

crates.io's modern publishing flow uses **Trusted Publishing** — packages
are published via GitHub Actions OIDC tokens, not personal API tokens. When
that happens, the per-version `published_by` field is intentionally `null`
and a new `trustpub_data` field is populated:

```json
{
  "version": {
    "num": "0.4.2",
    "published_by": null,
    "trustpub_data": {
      "provider": "github",
      "repository": "rust-random/getrandom",
      "run_id": "22617675559",
      "sha": "4d826731b20a09e69cca91c66aea57ab3cf00072"
    }
  }
}
```

dep-scan's `src/registry/crates.rs` only reads `published_by`. When a crate
switches from per-user tokens to Trusted Publishing (a security-positive
move), dep-scan sees the maintainer set "collapse" to `[]` and the
`maintainer_change` policy fires a Block:

```
getrandom@0.4.2: Complete maintainer changeover for 'getrandom':
                 removed [josephlr], added []
```

The investigation memo for getrandom
(`docs/security/getrandom-maintainer-investigation.md`) confirmed this is
benign behaviour and **not** a parser bug — but the resulting false positive
forces the user to either add an open-ended allowlist entry or chase the
signal manually. Both are bad UX, and the false positive will recur every
time a popular crate (cargo, serde, rand, tokio, …) switches to Trusted
Publishing.

## Objective

Teach dep-scan to recognise `trustpub_data` and incorporate it into the
maintainer-change signal so that legitimate Trusted-Publishing transitions
do not look like an empty maintainer set.

## Proposed approach (subject to ADR)

Two viable strategies, pick one (or both) in the test spec:

### A. Synthesise a stable trustpub identity string

Map `{ provider, repository }` to a synthetic maintainer label like
`trustpub:github:rust-random/getrandom`. Inject it into
`PackageMetadata.maintainers` whenever `published_by` is null but
`trustpub_data` is present. The maintainer-change policy then sees a
stable, non-empty identity that won't churn between releases and won't
look like "the maintainer left."

Pros: minimal policy change; signal still fires if the *repository*
binding changes (which would be the real attack surface — e.g. a malicious
actor convinces crates.io to bind a different repo).

Cons: introduces a new identity-space; the synthetic label might confuse
users reading raw verdict text.

### B. Skip maintainer_change for trustpub-published versions

When `trustpub_data` is present, emit a Pass (or Info) verdict for that
version regardless of `published_by`. Optionally, separately verify that
the trustpub `repository` matches the previously-observed binding.

Pros: simplest, removes the noise entirely.

Cons: loses signal if a hostile actor manages to bind a different repo to
the same crate via trustpub — needs at least a "repo binding changed"
sub-policy to compensate.

Recommendation: **do A**, with the optional repo-binding check as a future
add-on. A keeps the maintainer-change policy uniform; the trustpub label is
a stronger identity than per-user `published_by` because it is OIDC-bound.

## Out of scope

- Verifying the trustpub publish actually happened from the bound repo
  (requires cross-checking against GitHub Actions APIs — separate task).
- Generalising to other registries' trusted-publishing equivalents
  (PyPI has its own; npm has provenance). Those are already partially
  handled by `npm_provenance` and `pypi_provenance` policies.

## Acceptance criteria

- [ ] `src/registry/crates.rs` parses the `trustpub_data` field
- [ ] When `published_by` is null and `trustpub_data` is present, the
      synthetic maintainer label is emitted (e.g.
      `trustpub:github:rust-random/getrandom`)
- [ ] Unit tests cover: (a) traditional `published_by` only,
      (b) trustpub only, (c) both present (prefer `published_by` for
      backwards-compat, or document the chosen precedence)
- [ ] Re-running the dogfood scan against the current Cargo.lock no
      longer fires `maintainer_change` Block on `getrandom@0.4.2`
- [ ] Once 082 lands, the corresponding `getrandom@0.4.2` entry in
      `.dep-scan-dogfood-allowlist.toml` can be removed (the entry for
      `getrandom@0.3.4` may still be needed, since 0.3.4 is a
      traditional per-user publish)

# Task 068 — Sign release artifacts with cosign / sigstore

**Status:** backlog
**Depends on:** none (independent workflow file)
**Source:** post-v1.2.0 holistic review (Tier A #5 — "eat your own dog food")
**Touches:** `.github/workflows/release.yml`, `README.md` (verification snippet),
`install.sh` (optional verification path)

## Objective

Sign every release artifact (the per-platform tarballs/zip + `sha256sums.txt`)
with sigstore via cosign's keyless OIDC flow, publishing `.sig` + `.crt`
alongside each artifact in the GitHub Release. This is dep-scan applying its
own threat model to its own distribution.

## Background

dep-scan tells users to trust npm/PyPI provenance because it's sigstore-signed
against a publicly auditable Rekor log. The same argument applies to dep-scan
itself: a user downloading the binary should be able to verify it came from
the official GitHub Actions release workflow and that the signing event is
recorded in Rekor.

`cosign sign-blob` with `--yes` and the OIDC token GitHub Actions provides
(`id-token: write` permission) produces:

- `<artifact>.sig` — base64-encoded signature
- `<artifact>.crt` — Fulcio-issued code-signing certificate

Verification by an end user:

```
cosign verify-blob \
  --certificate dep-scan-v1.3.0-x86_64-unknown-linux-gnu.tar.gz.crt \
  --signature dep-scan-v1.3.0-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/tkdtaylor/dep-scan/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  dep-scan-v1.3.0-x86_64-unknown-linux-gnu.tar.gz
```

A user without cosign installed still gets the existing sha256 + manual
inspection path; signing is additive.

## Background — why this matters now

We just added the post-cut hardening tasks (059-063) on top of the v1.2.0
prep. Re-cutting v1.2.0 without provenance signatures means we ship a
security tool whose own distribution channel has weaker assurances than the
ones it asks users to enforce. The discrepancy is uncomfortable.

## Behavior

1. Add the `id-token: write` permission to the `release` workflow.
2. Add a `sigstore/cosign-installer@v3` step to the `release` job.
3. After the existing `Generate checksums` step, add a `Sign artifacts` step
   that runs `cosign sign-blob --yes --output-signature <file>.sig
   --output-certificate <file>.crt <file>` for each artifact and the
   `sha256sums.txt`.
4. The `softprops/action-gh-release@v2` step's `files:` list grows to include
   the `.sig` and `.crt` files.
5. Update README.md "Install" section with an "Optional: verify with cosign"
   subsection showing the command above.
6. Optionally add a `--verify` flag to `install.sh` that runs cosign verify
   before extracting. Out of scope to require it (cosign is not always
   installed) but documented.

## Acceptance criteria

- [ ] `.github/workflows/release.yml` requests `id-token: write` permission
- [ ] Workflow installs cosign via `sigstore/cosign-installer@v3`
- [ ] Every release artifact (5 binaries + sha256sums.txt) gets `.sig` and
      `.crt` companions
- [ ] GitHub Release page lists the signed companions
- [ ] README documents the verify command with the correct
      `--certificate-identity-regexp` for this repo
- [ ] Workflow YAML is valid
- [ ] Test-tagged release on a branch produces signatures that `cosign
      verify-blob` accepts locally

## Out of scope

- Mandatory verification in `install.sh` (additive only).
- Signing the source tarball — the binaries are what users run.
- Setting up a personal key / KMS — keyless OIDC is the whole point.

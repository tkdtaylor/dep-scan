# Test Spec — Task 068: Sign release artifacts with cosign / sigstore

## Context

The release workflow currently produces 5 binaries + `sha256sums.txt` with no
cryptographic provenance. dep-scan is a tool that asks users to trust
sigstore-signed npm/PyPI attestations; not signing its own releases is a
"physician heal thyself" gap. This task adds keyless OIDC signing via cosign.

Verification combines static YAML inspection with a test-tag dry run.

---

## Validation

### T-068-01: Valid YAML
- `.github/workflows/release.yml` parses without errors.

### T-068-02: `id-token: write` permission requested
- `permissions.id-token` is `write` at the workflow level or on the `release`
  job.

### T-068-03: cosign installed
- A step uses `sigstore/cosign-installer@v3` (or a fixed minor version pin
  inside v3).

### T-068-04: Each artifact gets a `.sig`
- A step runs `cosign sign-blob` over each `dep-scan-*` file and produces a
  `<file>.sig` companion. Equivalent inline loops or `find` invocations are
  acceptable.

### T-068-05: Each artifact gets a `.crt`
- The same step outputs `<file>.crt` via `--output-certificate`.

### T-068-06: `sha256sums.txt` is also signed
- The sums file gets both `.sig` and `.crt`.

### T-068-07: Signed companions are uploaded to the release
- `softprops/action-gh-release@v2`'s `files:` glob includes the `.sig` and
  `.crt` artifacts (e.g. `artifacts/*.sig`, `artifacts/*.crt`).

### T-068-08: cosign verification succeeds locally on a test tag
- After the workflow runs on a test tag (e.g. `v0.0.0-test1` on a branch),
  download an artifact and verify locally:
  ```
  cosign verify-blob \
    --certificate <artifact>.crt \
    --signature <artifact>.sig \
    --certificate-identity-regexp 'https://github.com/tkdtaylor/dep-scan/.github/workflows/release.yml@.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    <artifact>
  ```
  Exit code 0.

### T-068-09: README documents the verify command
- README.md "Install" (or "Install via install.sh") section gains an
  "Optional: verify with cosign" subsection with the exact command above,
  using the repo's actual workflow path in the `--certificate-identity-regexp`.

### T-068-10: Existing sha256sums verification still works
- The original sha256-based verification flow in `install.sh` continues to
  work — signing is additive, not a replacement.

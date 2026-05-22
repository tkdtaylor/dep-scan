# Rekor transparency-log signing key

Embedded Rekor public key used by `src/sigstore_verify.rs::verify_rekor_inclusion`
(task 036) to verify the signed tree heads ("checkpoints") attached to sigstore
bundles.

The PEM file is baked into the dep-scan binary at build time via
`include_str!`.  dep-scan does **not** download it at runtime — pinning at
build time mirrors the Fulcio trust-store approach (see
`fulcio-roots/README.md`) and is the practical compromise for a single static
binary.

## Contents

| File | Format | Purpose |
|------|--------|---------|
| `rekor.pub` | PEM `BEGIN PUBLIC KEY` — ECDSA P-256 SubjectPublicKeyInfo | The single Rekor signer used to sign tree-head notes attached to sigstore bundles. Key name in checkpoint lines: `rekor.sigstore.dev`. |

The associated key-id (first 4 bytes of `sha256(SPKI_DER)`) is `c0d23d6ah` —
embedded in each `— rekor.sigstore.dev <base64>` signature line.

## Provenance / rotation procedure

The Rekor key is distributed via sigstore's TUF repository at
<https://tuf-repo-cdn.sigstore.dev>.  The retrieval procedure:

1. Download the current targets metadata file.  The version number rolls
   forward as sigstore issues new TUF metadata; check
   <https://tuf-repo-cdn.sigstore.dev> for the latest.  As of 2026-05, the
   current targets snapshot was `12.targets.json`:

   ```sh
   curl -sSL https://tuf-repo-cdn.sigstore.dev/12.targets.json -o targets.json
   ```

2. Identify the Rekor target by name in the JSON (`signed.targets`).  The
   relevant entry is named `rekor.pub`:

   ```sh
   python3 -c "
   import json
   d = json.load(open('targets.json'))
   for n, i in d['signed']['targets'].items():
       if 'rekor' in n.lower():
           print(i['hashes']['sha256'], n, i.get('custom', {}).get('sigstore', {}).get('status', '?'))
   "
   ```

3. Download the target.  TUF paths are content-addressed by sha256 prefix:

   ```sh
   curl -sSL -o rekor.pub \
     https://tuf-repo-cdn.sigstore.dev/targets/<sha256>.rekor.pub
   ```

4. Verify the sha256 of the downloaded file matches the manifest:

   ```sh
   sha256sum rekor.pub
   ```

5. Replace the file in this directory and run `cargo test`.  The
   real-bundle tests (T-036-19) will exercise the new key against the
   embedded fixture bundles — if those bundles were signed under the old
   key, they will fail and you will need to update the fixtures too.

## Verification (last refresh 2026-05-22)

The PEM in this directory derives from this TUF manifest entry
(`12.targets.json`):

```
rekor.pub
  sha256: dce5ef715502ec9f3cdfd11f8cc384b31a6141023d3e7595e9908a81cb6241bd
  status: Active
```

## When to rotate

- Sigstore announces a new Rekor signing key (watch
  <https://github.com/sigstore/root-signing>).
- The TUF manifest flips the `Active` status to `Expired` (treat any
  newly-issued attestations signed under the expired key with suspicion;
  pre-rotation attestations remain verifiable against the previous key).
- An external advisory (e.g., a CVE) recommends rotation.

Each rotation requires a dep-scan release because the key is baked into
the binary.

## Why pinned and not dynamic

dep-scan ships as a single binary with no runtime trust-root negotiation.
TUF-based dynamic trust-root updates are out of scope (deferred — see task
035 documentation).  Pinning is the pragmatic compromise: it forces a
release cadence on rotations but eliminates a network dependency from the
verify path.

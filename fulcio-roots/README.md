# Fulcio trust store

Embedded Fulcio root and intermediate certificates used by
`src/sigstore_verify.rs::verify_fulcio_chain` (task 035).

These DER files are baked into the dep-scan binary at build time via
`include_bytes!`. dep-scan does **not** download them at runtime — pinning at
build time is the practical compromise for a single static binary (see ADR
section in task 035).

## Contents

| File | Subject | Issuer | Public key | Purpose |
|------|---------|--------|------------|---------|
| `fulcio.crt.der`              | `O=sigstore.dev, CN=sigstore`              | self-signed | P-384 (secp384r1) | Legacy Fulcio root (pre-rotation). TUF status: `Expired` for issuance but still a valid trust anchor for older attestations. |
| `fulcio_v1.crt.der`           | `O=sigstore.dev, CN=sigstore`              | self-signed | P-384 (secp384r1) | Current Fulcio root. |
| `fulcio_intermediate_v1.crt.der` | `O=sigstore.dev, CN=sigstore-intermediate` | `fulcio_v1.crt` | P-384 (secp384r1) | Current Fulcio intermediate that signs leaf cert. |

All signatures use `ecdsa-with-SHA384`. Leaf certs issued by the intermediate
are typically P-256 with `ecdsa-with-SHA384` signatures.

## Provenance / rotation procedure

These certs are distributed via sigstore's TUF repository at
<https://tuf-repo-cdn.sigstore.dev>. The retrieval procedure:

1. Download the current targets metadata file. The version number rolls
   forward as sigstore issues new TUF metadata; check
   <https://tuf-repo-cdn.sigstore.dev> for the latest. As of 2026-05, the
   current targets snapshot was `12.targets.json`:

   ```sh
   curl -sSL https://tuf-repo-cdn.sigstore.dev/12.targets.json -o targets.json
   ```

2. Identify the Fulcio targets by name in the JSON (`signed.targets`). Each
   target has a sha256 hash and length:

   ```sh
   python3 -c "
   import json
   d = json.load(open('targets.json'))
   for n, i in d['signed']['targets'].items():
       if 'fulcio' in n.lower():
           print(i['hashes']['sha256'], n, i.get('custom', {}).get('sigstore', {}).get('status', '?'))
   "
   ```

3. Download each target. TUF paths are content-addressed by sha256 prefix:

   ```sh
   curl -sSL -o fulcio.crt.pem \
     https://tuf-repo-cdn.sigstore.dev/targets/<sha256>.fulcio.crt.pem
   curl -sSL -o fulcio_v1.crt.pem \
     https://tuf-repo-cdn.sigstore.dev/targets/<sha256>.fulcio_v1.crt.pem
   curl -sSL -o fulcio_intermediate_v1.crt.pem \
     https://tuf-repo-cdn.sigstore.dev/targets/<sha256>.fulcio_intermediate_v1.crt.pem
   ```

4. Verify the sha256 of each downloaded file matches the manifest:

   ```sh
   sha256sum *.pem
   ```

5. Convert PEM → DER with openssl. dep-scan embeds DER:

   ```sh
   for f in fulcio.crt fulcio_v1.crt fulcio_intermediate_v1.crt; do
       openssl x509 -in "${f}.pem" -outform DER -out "${f}.der"
   done
   ```

6. Replace the files in this directory and run `cargo test`. The chain-walk
   smoke test (T-035-14, T-035-15) will exercise real Fulcio leaves against
   the new trust roots.

## Verification (last refresh 2026-05-22)

The DER files in this directory derive from these TUF manifest entries
(`12.targets.json`):

```
fulcio.crt.pem
  sha256: f360c53b2e13495a628b9b8096455badcb6d375b185c4816d95a5d746ff29908
  status: Expired (still a valid anchor for older attestations)

fulcio_intermediate_v1.crt.pem
  sha256: f8cbecf186db7714624a5f4e99da31a917cbef70a94dd6921f5c3ca969dfe30a
  status: Active

fulcio_v1.crt.pem
  sha256: f989aa23def87c549404eadba767768d2a3c8d6d30a8b793f9f518a8eafd2cf5
  status: Active
```

## When to rotate

- Sigstore announces a new Fulcio root (watch
  <https://github.com/sigstore/root-signing>).
- The `Expired` status on a root flips to `Revoked` in the TUF manifest
  (treat all attestations issued under that root as untrusted; remove the
  DER from this directory).
- An external advisory (e.g., a CVE) recommends rotation.

Each rotation requires a dep-scan release because the trust store is baked
into the binary.

## Why pinned and not dynamic

dep-scan ships as a single binary with no runtime trust-root negotiation.
TUF-based dynamic trust root updates are out of scope (deferred — see task
035 documentation). Pinning is the pragmatic compromise: it forces a release
cadence on rotations but eliminates a network dependency from the verify
path.

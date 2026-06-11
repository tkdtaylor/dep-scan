# Task 089 — Public-key export for consumers

**Status:** backlog
**Depends on:** 087 (`OperatorKeySigner`, `signing.key_path` config field,
               key-id derivation)
**ADR:** 007 (point 3 — operator tooling to export public key for distribution)
**Touches:** `src/cli.rs` (new `Signing` command + `SigningAction::ExportPubkey`
            subcommand), `src/signing_export.rs` (new — export logic)

## Objective

Add `dep-scan signing export-pubkey`: a CLI subcommand that reads the
operator's private signing key from `signing.key_path`, derives the public
half, and prints it to stdout as a PEM-encoded SubjectPublicKeyInfo (SPKI)
block preceded by a `# key-id:` comment line. Consumers (sibling blocks,
verifying agents) copy this output out of band and use it to verify
offline-signed statements.

No network access. No private key material in stdout. One responsibility.

## Background

ADR 007 (point 3) is explicit: there is no project-wide public key — the key
is per-deployment/operator. dep-scan is responsible for providing the
*tooling* to export the public key; the operator is responsible for
distributing it to consumers. Task 087 introduced `signing.key_path` and the
key-id derivation (hex-encoded SHA-256 of the raw public key bytes). This
task surfaces that public key in a copy-pastable, standard format so
consumers can pin it.

The output format is **PEM SPKI** because it is the standard representation
for Ed25519 public keys across cryptographic tooling (OpenSSL, Python
`cryptography`, Rust `ed25519-dalek`). A DSSE verifier holds the raw public
key bytes; those are trivially extracted from the SPKI DER by stripping the
12-byte Ed25519 algorithm identifier prefix. The `# key-id:` comment uses the
same derivation as task 087's `OperatorKeySigner` so consumers can match the
`keyid` field in a signed envelope to the key they hold.

## Requirements

### REQ-089-01: `Signing` subcommand in CLI
Add a `Signing` variant to `Command` in `src/cli.rs`, with a nested
`SigningAction` enum whose only variant for this task is `ExportPubkey`. The
CLI parses `dep-scan signing export-pubkey` without arguments. Help text must
mention `signing.key_path` as the key source and PEM/SPKI as the output
format.

### REQ-089-02: `export_pubkey` function
Implement `pub fn export_pubkey(config: &Config, out: &mut dyn Write) -> Result<()>`
in a new `src/signing_export.rs` module. This function:
1. Reads `config.signing.key_path`; returns `Err` if empty/unset.
2. Reads the file at that path; returns `Err` with the path in the message
   if unreadable.
3. Parses the file as a PEM-encoded PKCS#8 Ed25519 private key; returns `Err`
   with a clear message on any parse failure (wrong PEM type, wrong algorithm,
   truncated file, garbage bytes, etc.).
4. Derives the Ed25519 public key from the private key.
5. Computes the key-id: hex-encoded lowercase SHA-256 of the 32-byte raw
   public key bytes (same derivation as `OperatorKeySigner` in task 087).
6. Writes to `out`:
   - `# key-id: <hex>\n`
   - The PEM SPKI block for the public key (standard `-----BEGIN PUBLIC KEY-----` header).
7. Makes zero network calls.
8. Writes no private key bytes to `out` at any point.

### REQ-089-03: Key-id matches task 087 derivation
The key-id written by `export_pubkey` must be identical to the key-id that
`OperatorKeySigner::sign` embeds in DSSE envelopes for the same key. This is
the linkage consumers need to match a received envelope's `keyid` field to
the pinned public key.

### REQ-089-04: Output is pipe/redirect friendly
stdout output must consist only of printable ASCII, end with a newline, and
contain no ANSI escape sequences. This allows `dep-scan signing export-pubkey
> pubkey.pem` to produce a valid PEM file without post-processing.

### REQ-089-05: Robust error messages
Each failure mode names the concrete problem and, where a file path is
involved, includes the path. The message must not expose private key material.

## Acceptance criteria

- [ ] `dep-scan signing export-pubkey` parses via clap and dispatches to
      `export_pubkey`
- [ ] Given a valid `signing.key_path`, stdout contains a `# key-id:` comment
      followed by a `-----BEGIN PUBLIC KEY-----` PEM block
- [ ] The PEM block decodes to the correct Ed25519 public key for the given
      private key
- [ ] The key-id matches the derivation in task 087's `OperatorKeySigner`
- [ ] No private key bytes appear in stdout
- [ ] `signing.key_path` unset → non-zero exit, message names `signing.key_path`
- [ ] Non-existent path → non-zero exit, message includes the path
- [ ] Malformed / wrong-type key file → non-zero exit, clear error
- [ ] Zero network calls (confirmed in test)
- [ ] Path with spaces works on all platforms
- [ ] All T-089-01 through T-089-19 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/089-pubkey-export-test-spec.md`

## Out of scope

- Project-wide / built-in public key (ADR 007: there is none; the key is
  per-deployment)
- Keyless (Fulcio/sigstore) identity export — those are cert-based and
  distributed through Rekor/CT logs, not this command
- Automating consumer distribution (out-of-band is the operator's job)
- KMS / PKCS#11 key backends (future; ADR 007 point 2)
- Importing or validating a consumer's copy of the public key
- Key rotation tooling (generate new key, announce rotation) — future task

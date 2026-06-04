# Test Spec — Task 089: Public-key export for consumers

## Context

ADR 007 (point 3) requires that dep-scan provide operator tooling to export
the public half of the operator's signing key so consumers (sibling blocks,
verifying agents) can pin it and verify offline-signed statements. There is
no project-wide key; the key is per-deployment/operator. This task adds a
`dep-scan signing export-pubkey` subcommand that reads the private key from
`signing.key_path` (introduced in task 087), derives the corresponding public
key, and prints it to stdout in a format that DSSE/Ed25519 consumers can use.

The key format is **PEM-encoded SubjectPublicKeyInfo (SPKI)**, which is the
standard wire format for Ed25519 public keys in most cryptographic tooling
(OpenSSL, OpenSSH `--pk`, Python `cryptography`, Rust `ed25519-dalek`
`VerifyingKey::to_public_key_pem`). A key-id (hex-encoded, first 16 bytes of
SHA-256 over the raw 32-byte public key) is printed on a comment line above
the PEM block so operators can correlate it with the `keyid` field in signed
envelopes from task 087.

No network access is performed. No private key bytes appear in stdout.

---

## CLI shape

### T-089-01: `dep-scan signing export-pubkey` parses without arguments
- `Cli::parse_from(["dep-scan", "signing", "export-pubkey"])` succeeds and
  produces `Command::Signing { action: SigningAction::ExportPubkey }`.

### T-089-02: `dep-scan signing export-pubkey --help` exits 0 and includes a
description
- The help text references the key source (`signing.key_path`) and the output
  format (PEM / SPKI).

---

## Happy-path output

### T-089-03: Exports public key as PEM SPKI to stdout
- Generate a test Ed25519 key-pair; write the private key (PEM-encoded
  PKCS#8) to a temp file; set `signing.key_path` to that path in config.
- Run `export_pubkey(&config, &mut stdout_buf)`.
- `stdout_buf` contains a PEM block beginning with
  `-----BEGIN PUBLIC KEY-----` and ending with `-----END PUBLIC KEY-----`.

### T-089-04: Exported PEM decodes to the correct Ed25519 public key
- Starting from the same key-pair as T-089-03, decode the PEM output back to
  raw bytes (SPKI DER → strip 12-byte Ed25519 OID/algorithm prefix → 32-byte
  key material).
- The 32 bytes match the expected public key bytes derived from the test
  private key.

### T-089-05: Key-id comment line precedes the PEM block
- `stdout_buf` (from T-089-03) starts with a line matching the pattern:
  `# key-id: <64 lowercase hex chars>` (SHA-256 hex of the 32-byte public
  key).
- The comment line is immediately followed by the PEM block.

### T-089-06: Key-id matches the derivation used in task 087
- Given the same test private key, the key-id printed by `export-pubkey`
  equals the key-id that `OperatorKeySigner::sign` embeds in envelopes
  (T-087-03 pre-computed value).
- This cross-check ensures consumers can match the `keyid` field in a signed
  envelope to the exported public key.

### T-089-07: No private key bytes appear in stdout
- The raw private key material (32 secret scalar bytes) must not appear
  anywhere in `stdout_buf`.
- Confirmed: search `stdout_buf` for the private key's 32 raw bytes (hex and
  base64 encoded); confirm no match.

### T-089-08: Output is pipe/redirect friendly — no ANSI codes or extra decoration
- `stdout_buf` contains only printable ASCII.
- There are no ANSI escape sequences (`\x1b[`) in the output.
- Output ends with a newline.

---

## Error cases

### T-089-09: `signing.key_path` unset → non-zero exit, clear message
- Config has `signing.key_path = ""` (empty / None).
- `export_pubkey(&config, &mut buf)` returns `Err`.
- The error message mentions `signing.key_path` by name.

### T-089-10: Key file does not exist → non-zero exit, clear message
- `signing.key_path` points to a path that does not exist.
- `export_pubkey` returns `Err` with a message containing the missing path
  (so the operator knows which file to check).

### T-089-11: Key file is not a valid Ed25519 private key (garbage bytes) →
non-zero exit, clear message
- Write 64 random bytes to a temp file; set `signing.key_path` to it.
- `export_pubkey` returns `Err`; error message indicates the key is invalid
  or not in the expected format (PEM PKCS#8).

### T-089-12: Key file exists but is zero bytes → non-zero exit, clear message
- Write an empty file; set `signing.key_path` to it.
- `export_pubkey` returns `Err`.

### T-089-13: Key file has a wrong PEM type (e.g. contains a certificate PEM,
not a private key PEM) → non-zero exit, clear message
- Write a file containing a DER-base64 blob labeled
  `-----BEGIN CERTIFICATE-----`/`-----END CERTIFICATE-----`.
- `export_pubkey` returns `Err` mentioning an unexpected PEM type.

---

## No network access

### T-089-14: No network calls are made during export
- Run `export_pubkey` with a valid key configured and a stub HTTP server
  listening.
- Assert the stub server receives zero requests.
- This confirms the command is fully offline and safe for air-gapped use.

---

## Cross-platform path handling

### T-089-15: Absolute path with spaces works on all platforms
- Set `signing.key_path` to a temp-dir path that contains a space in the
  directory name.
- `export_pubkey` loads the key and succeeds (no path-parsing error).

### T-089-16: Relative path in `signing.key_path` is resolved from the process
  working directory
- Set `signing.key_path` to a relative path (e.g. `"my-signing-key.pem"`).
- Change the working directory to the parent directory of the key file before
  calling `export_pubkey`.
- Export succeeds and produces correct output.

---

## Integration: CLI wiring

### T-089-17: `dep-scan signing export-pubkey` end-to-end (process invocation)
- Spawn `cargo run -- --config <cfg> signing export-pubkey` with a test
  config pointing at a valid key.
- Process exits 0.
- stdout contains `# key-id: ` comment and PEM block.
- stderr is empty.

### T-089-18: `dep-scan signing export-pubkey` exits non-zero when key_path
  unset (process invocation)
- Spawn `cargo run -- signing export-pubkey` with no config (empty default).
- Process exits non-zero.
- stderr contains a message mentioning `signing.key_path`.

---

## Tooling gate

### T-089-19: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

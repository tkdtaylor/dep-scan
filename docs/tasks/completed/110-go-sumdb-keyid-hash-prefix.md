# Task 110 — go_sumdb key-id derivation has a spurious `hash:1:` prefix → false BLOCK on every real Go module

**Status:** backlog
**Type:** bug (correctness / false-positive; security-relevant — fails *closed* but unusably)
**Severity:** high — `check_go_sumdb` BLOCKs **every** real Go dependency it scans
**Component:** `src/signed_note.rs` (Ed25519 note verifier), surfaced via `src/policy/go_sumdb.rs`
**ADR:** none required (bug fix; no design decision changes)

## Symptom

Running a Go dependency scan against any real module returns a `go_sumdb` **BLOCK**, even
for unimpeachable modules:

```
$ dep-scan check --registry go --lockfile go.sum --lockfile-type go
github.com/google/uuid v1.6.0   BLOCK: go_sumdb: sumdb signature verification failed for
  'github.com/google/uuid': no signature line found for key 'sum.golang.org'
  age: pass
  install_scripts: pass
  obfuscation: pass
  maintainer_change: pass
  typosquatting: pass
  vulnerability: pass
  popularity: pass
  dependency_confusion: pass
  go_sumdb: BLOCK — no signature line found for key 'sum.golang.org'
```

Every other policy passes; only `go_sumdb` blocks. Because the scan exits non-zero, this makes
`check_go_sumdb = true` (the default) unusable for real Go projects — every dependency-bearing
scan fails closed on a false positive.

Discovered by the **agent-builder** project, whose in-box verification gate runs
`dep-scan check --registry go --lockfile go.sum --lockfile-type go`. A Claude-generated task
that added `github.com/google/uuid` built/tested/linted clean but the gate red-lined here. It is
**not** an egress/network issue (dep-scan reaches sum.golang.org fine — the lookup succeeds and
all other checks run) and **not** an agent-builder issue.

## Reproduction

```bash
T=$(mktemp -d); cd "$T"
cat > go.sum <<'EOF'
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
EOF
dep-scan check --registry go --lockfile go.sum --lockfile-type go   # → go_sumdb BLOCK
```

Confirmation it is specifically the sumdb check: with a config setting `check_go_sumdb = false`,
the same module returns `pass`. (That is only a workaround — the verifier itself is wrong.)

## Root cause (proven)

The Ed25519 signed-note verifier in [`src/signed_note.rs`](../../../src/signed_note.rs) derives
the expected key-id with a **spurious `"hash:1:"` prefix** that is not part of Go's
`golang.org/x/mod/sumdb/note` key-hash algorithm:

```rust
// src/signed_note.rs ~line 248-254  (current, WRONG)
// sumdb key-id: SHA256("hash:1:" || name || "\n" || key_bytes)[:4]
let mut hasher = Sha256::new();
hasher.update(b"hash:1:");           // <-- not part of Go's note.keyHash
hasher.update(key_name.as_bytes());
hasher.update(b"\n");
hasher.update(&key_bytes);           // key_bytes = 0x01 || 32-byte ed25519 pubkey
let expected_key_id = &hasher.finalize()[..4];
```

Go's actual algorithm (`note.keyHash`) is `SHA256(name + "\n" + key)[:4]` — **no prefix**.

The pinned key string already embeds the correct key-id:
`SUMDB_PUBLIC_KEY_STR = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"`
→ the real key-id is **`033de0ae`**.

Verified numerically against that pinned key:

| Derivation | key-id | matches real `033de0ae`? |
|---|---|---|
| Go `SHA256(name + "\n" + key)[:4]` | `033de0ae` | ✅ yes |
| dep-scan `SHA256("hash:1:" + name + "\n" + key)[:4]` | `9f6cb724` | ❌ no |

(Independently reproducible:)
```python
import hashlib, base64
key = base64.b64decode('Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8')   # 0x01 || ed25519 pubkey
name = b'sum.golang.org'
hashlib.sha256(name + b'\n' + key).digest()[:4].hex()             # '033de0ae'  ✅
hashlib.sha256(b'hash:1:' + name + b'\n' + key).digest()[:4].hex() # '9f6cb724' ✗
```

Because the computed `expected_key_id` (`9f6cb724`) never equals the key-id on the real
`sum.golang.org` signature line (`033de0ae`), the loop's `if sig.key_id != expected_key_id { continue; }`
guard skips every signature, and the function falls through to
`"no signature line found for key 'sum.golang.org'"` (signed_note.rs:291-293).

## Why the tests didn't catch it

The unit tests in `src/policy/go_sumdb.rs` (and the `signed_note.rs` tests) **build their synthetic
signed notes by computing the key-id with the same `"hash:1:"` prefix** (see the test helper around
`src/policy/go_sumdb.rs:575-607`). So the fixture's key-id matches the verifier's wrong derivation
and the tests pass — they are self-consistent with the bug and were never validated against the real
`sum.golang.org` key/note. This is the classic "verified only against fakes that encode the same
mistake" failure: the verifier must be pinned to an **independent** ground truth (the real key-id
`033de0ae`, or a recorded real `sum.golang.org` lookup response).

## Fix

1. In `src/signed_note.rs`, remove the `b"hash:1:"` write from the Ed25519 key-id hash so the
   derivation is exactly `SHA256(key_name + "\n" + key_bytes)[:4]`, matching `note.keyHash`. Update
   the accompanying comment.
2. Audit the P-256 / Rekor verifier path (signed_note.rs ~line 326-333, `SHA256(spki_der)[:4]`) for
   the analogous concern — confirm whether Rekor's key-id derivation is correct or also needs
   alignment. (Rekor and Go-note key-id schemes differ; do not blindly copy the fix. This is a
   verify-don't-assume note, not a claim that Rekor is broken.)
3. Fix the test fixtures that compute the synthetic key-id with the `"hash:1:"` prefix so they use
   the corrected derivation — but ALSO add the independent regression below so fixtures can never
   re-encode the same mistake.

## Acceptance criteria

- [AC-1] The Ed25519 key-id derivation matches Go's `note.keyHash` (`SHA256(name + "\n" + key)[:4]`);
  no `"hash:1:"` prefix.
- [AC-2] A regression test pins the derivation to the **independent** ground truth: feeding the real
  `SUMDB_PUBLIC_KEY_STR` yields key-id `033de0ae` (the hex in the pinned key string). This test must
  NOT recompute the expected value through the production code path.
- [AC-3] A verification test against a **real, recorded** `sum.golang.org/lookup/github.com/google/uuid@v1.6.0`
  signed-note response returns `Valid` (note text + signature verified). Record the real response as
  a fixture so the test is offline/deterministic.
- [AC-4] `dep-scan check --registry go --lockfile go.sum --lockfile-type go` on a `go.sum` containing
  `github.com/google/uuid v1.6.0` returns `pass` (go_sumdb green) with `check_go_sumdb = true`.
- [AC-5] `cargo test`, `cargo clippy`, `cargo fmt --check` green.

## Out of scope

- The `check_go_sumdb = false` config workaround (already exists; not a fix).
- Any change to the sumdb lookup/fetch client (`src/registry/go_sumdb.rs`) — the fetch is correct;
  only the signature verification key-id derivation is wrong.

## Downstream note

agent-builder is consuming `dep-scan` as a blocking gate step and is currently unblocked only by
disabling `check_go_sumdb`. Once this is fixed and released, agent-builder can re-enable the check
(its in-box gate calls `dep-scan check --registry go --lockfile go.sum --lockfile-type go`).

# ADR 009 — Driving the async sigstore network from the synchronous `InterchangeSigner` trait

**Status:** Accepted
**Date:** 2026-06-11
**Relates to:** ADR 006 (Q5 identity), ADR 007 (offline key custody), task 086
(the `InterchangeSigner` trait), task 087 (the two signer implementations)

## Context

Task 086 defined the signing abstraction as a **synchronous** trait:

```rust
pub trait InterchangeSigner {
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)>;
}
```

That signature is correct for the offline `OperatorKeySigner`: loading a PEM
PKCS#8 Ed25519 key and signing a byte slice is a pure, non-blocking CPU
operation with no I/O.

Task 087 must also provide `KeylessSigner`, which is the opposite: signing
*requires* network round-trips (Fulcio cert issuance, Rekor log upload). The
rest of the codebase is async-on-`reqwest` (see `src/osv.rs`,
`src/registry/go_sumdb.rs`), and `run_check` — the only live call site — is an
`async fn` already running inside a tokio runtime.

So we have a synchronous trait method that, for one implementation, needs to
perform async network I/O while a tokio runtime is already on the stack.

## Options considered

1. **Make the trait `async`.** Rejected. It would ripple through task 086's
   already-merged, already-tested `sign_interchange` / `produce_serialized_output`
   surface and the offline signer (which has no async work) would pay an
   `async` tax for nothing. The trait is the wrong place to encode "this one
   impl happens to do I/O."

2. **`reqwest::blocking` inside `sign()`.** Rejected. Constructing a blocking
   reqwest client inside a thread already owned by a tokio runtime panics
   ("Cannot start a runtime from within a runtime"), and it would pull in a new
   feature/transitive surface.

3. **Bridge with `tokio::task::block_in_place` + `Handle::current().block_on(..)`.**
   Chosen. `block_in_place` tells the multi-threaded scheduler the current
   worker is about to block so it can move other tasks elsewhere; the inner
   `block_on` then drives the async Fulcio/Rekor calls to completion. The sync
   trait stays sync, the offline signer is untouched, and the async HTTP code
   reuses the existing `reqwest::Client` pattern.

## Decision

`KeylessSigner::sign` keeps the synchronous trait signature and bridges to its
async HTTP work via `tokio::task::block_in_place(|| Handle::current().block_on(async { … }))`.

Consequences:

- The live call path (`run_check`) must run on a **multi-threaded** tokio
  runtime. `#[tokio::main]` already gives a multi-thread runtime by default, so
  production is unaffected.
- Tests that exercise `KeylessSigner::sign` against a wiremock server must use
  `#[tokio::test(flavor = "multi_thread")]` (current-thread runtime cannot host
  `block_in_place`). The offline-signer and `resolve_signer` tests need no such
  constraint.
- If `block_in_place` is ever called with no current runtime (e.g. a future
  non-async caller), `Handle::current()` panics; the only caller is the async
  `run_check`, and `KeylessSigner` is only ever produced by `resolve_signer`
  from inside it, so this is not reachable on the live path.

## Alternatives left open

A future refactor could introduce a parallel `async` signing trait if more
signer implementations need I/O; this ADR does not preclude that. For task 087
the bridge is the minimal, localized change that satisfies the 086 contract.

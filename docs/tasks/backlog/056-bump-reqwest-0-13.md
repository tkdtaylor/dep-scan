# Task 056 — Bump `reqwest` 0.12 → 0.13

**Status:** backlog (deferred — attempted and reverted during v1.2.0 prep)
**Depends on:** release-workflow fix for `cross-rs/cross` aarch64-linux build
  (see *Deferral note* below)
**Security finding:** dependency audit — minor version lag
**Touches:** `Cargo.toml`, `Cargo.lock`, and any call sites that use APIs that
changed in 0.13

## Deferral note (2026-05-22)

This task was implemented during v1.2.0 prep but reverted before the v1.2.0
cut. Local CI passed cleanly, but `reqwest` 0.13's only stable feature flag
that pulls in a crypto provider is `rustls`, which pulls
`aws-lc-rs` + `aws-lc-sys` (a BoringSSL fork; C library requiring `cmake` +
`clang` at build time).

The release workflow's `aarch64-unknown-linux-gnu` job runs under
`cross-rs/cross`, whose default docker image has `build-essential` but not
`cmake`. The cross-compile would very likely fail at the C build step.

**Three viable paths to re-attempt this task in a future release:**

1. Update `.github/workflows/release.yml` to install `cmake` (and any
   companion build-tools `aws-lc-sys` needs) in the aarch64-linux cross
   build before invoking `cross build`.
2. Use `reqwest = { ..., features = ["rustls-no-provider"] }` and wire
   `rustls`'s `CryptoProvider::install_default(ring::default_provider())`
   at process start so dep-scan keeps the pre-existing `ring` crypto stack.
   This adds a direct `rustls = "0.23"` dep and an init-time call.
3. Wait until a future `reqwest` release re-exposes a feature that picks
   `ring` (or until `ring` is restored as the default provider — both
   sigstore-rs and rustls upstream have ongoing discussions).

Reverted at the v1.2.0 cut to avoid a cross-compile failure on push;
deferred until one of the above paths is selected.

## Objective

Upgrade `reqwest` from `0.12` to `0.13` to stay on the supported release track
and pick up any security patches that ship in 0.13.x.

## Background

`reqwest` 0.13 introduced changes to the `rustls-tls` feature flag hierarchy:
- `rustls-tls-native-roots` — uses the system certificate store
- `rustls-tls-webpki-roots` — uses the bundled webpki certificate bundle
- `rustls-tls` may be retained as an alias for one of the above (verify in
  release notes)

dep-scan currently specifies:

```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```

The correct feature flag for 0.13 must be verified against the 0.13 release notes
and changelog before the bump.

dep-scan must remain statically linkable (no OpenSSL dependency); the TLS backend
must remain `rustls`.

## Behavior

This is a version bump with no behavior change.  All five registry clients and
the OSV client call `Client::new()` or straightforward builder patterns; no
advanced reqwest API features (streaming, middleware, interceptors) are used.

## Requirements

- **REQ-056-01:** `Cargo.toml` specifies `reqwest = { version = "0.13", … }` with
  the correct feature flags for rustls TLS on 0.13.
- **REQ-056-02:** `cargo build --release` exits 0.
- **REQ-056-03:** `openssl-sys` does NOT appear in `Cargo.lock` — dep-scan must
  remain OpenSSL-free.
- **REQ-056-04:** `cargo audit` exits 0 with no new advisories.
- **REQ-056-05:** All existing tests (635 minimum) continue to pass.

## Acceptance criteria

- [ ] `Cargo.toml` uses `reqwest = "0.13"` with rustls feature (REQ-056-01).
- [ ] Feature flag choice documented in `Cargo.toml` comment.
- [ ] `cargo build --release` exits 0 (REQ-056-02); verified by T-056-01.
- [ ] `openssl-sys` absent from `Cargo.lock` (REQ-056-03); verified by T-056-03.
- [ ] `cargo audit` clean (REQ-056-04); verified by T-056-02.
- [ ] All registry client integration tests pass (REQ-056-05); verified by
  T-056-04 through T-056-10.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` pass.

## Out of scope

- Upgrading other HTTP-layer dependencies alongside reqwest.
- Changing the HTTP client abstraction (e.g. introducing a trait for testability
  — a separate task).

## Risk notes

- The bump may update transitive dependencies (`hyper`, `h2`, `rustls`,
  `tokio-rustls`) — review `Cargo.lock` diff for any crate that is also listed
  in `cargo audit` advisories.
- If `rustls-tls` is no longer a valid feature name in 0.13, the build will fail
  at the feature-resolution step with a clear error message.  Consult the
  `reqwest` 0.13 changelog before attempting the bump.

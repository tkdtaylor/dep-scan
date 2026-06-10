# Test Spec — Task 092: Cargo lockfile git source parser

## Context

ADR 008 piece 1 — the Cargo lockfile parser in `src/lockfile.rs` currently
includes packages with `source` fields starting with `git+`, but classifies them
as `DependencySource::Registry { registry: RegistryType::Crates }`. That is a
mis-route: a `git+https://github.com/user/repo?branch=main#abc1234` source is
a git dependency, not a crates.io package. Additionally, the current parser skips
packages with no `source` field (local path deps), which is correct — but it must
now also distinguish `registry+` sources (crates.io/alternate registries) from
`git+` sources.

This task teaches `parse_cargo_lock` to emit `DependencySource::Git` for `git+`
source entries. It depends on task 090 for the `DependencySource::Git` variant.

---

## Source-kind discrimination

### T-092-01: `registry+` source produces `DependencySource::Registry(Crates)`
- Input Cargo.lock entry: `source = "registry+https://github.com/rust-lang/crates.io-index"`.
- Emits `DependencySource::Registry { registry: RegistryType::Crates }`.

### T-092-02: `git+https://` source produces `DependencySource::Git`
- Input: `source = "git+https://github.com/user/repo#abc1234"`.
- Emits `DependencySource::Git { url: "https://github.com/user/repo", ref_: "abc1234" }`.
- The `git+` prefix is stripped from the stored URL.

### T-092-03: `git+ssh://` source produces `DependencySource::Git`
- Input: `source = "git+ssh://git@github.com/user/repo.git#abc1234"`.
- Emits `DependencySource::Git { url: "ssh://git@github.com/user/repo.git", ref_: "abc1234" }`.

### T-092-04: `git+https://` with query parameters stores url without fragment
- Input: `source = "git+https://github.com/user/repo?branch=main#abc1234"`.
- Emits `DependencySource::Git { url: "https://github.com/user/repo?branch=main", ref_: "abc1234" }`.
- The `?branch=main` query is preserved in `url`; only the `#fragment` is split off.

### T-092-05: `git+https://` with `?rev=` query
- Input: `source = "git+https://github.com/user/repo?rev=abc1234#abc1234"`.
- Both the query param and the fragment ref are carried through without loss.

### T-092-06: `git+https://` source with no `#` fragment gets empty ref
- Input: `source = "git+https://github.com/user/repo"`.
- `dep.source.git_ref() == Some("")`.
- No panic.

### T-092-07: Local path dep (no source field) is still skipped
- Input: package with no `source` key.
- Parser skips the entry (no dep emitted). Behavior unchanged.

---

## Name and version preservation

### T-092-08: Name and version are preserved for git-source entries
- Input: `name = "some-crate"`, `version = "0.5.0"`, `source = "git+https://…#abc"`.
- `dep.name == "some-crate"`, `dep.version == "0.5.0"`.

### T-092-09: Git dep with empty version is emitted (version not required for git)
- Input: `name = "crate-no-ver"`, `version = ""` (absent), `source = "git+https://…#abc"`.
- Parser emits the dep without skipping due to empty version.
- `dep.version == ""`.

---

## Mixed Cargo.lock

### T-092-10: Lockfile with registry and git entries produces both kinds
- Input: two packages — one `registry+` source, one `git+` source.
- Emits two deps: one `Registry(Crates)`, one `Git`.

### T-092-11: Local, registry, and git all present — only registry + git emitted
- Input: three packages — no source (local), `registry+`, `git+`.
- Emits exactly two deps; the local dep is skipped.

---

## Ref extraction detail

### T-092-12: Commit SHA as ref is stored verbatim
- Input: `source = "git+https://github.com/user/repo#abcdef1234567890abcdef1234567890abcdef12"`.
- `ref_ == "abcdef1234567890abcdef1234567890abcdef12"`.

### T-092-13: `#` with no content after it gives empty ref, not panic
- Input: `source = "git+https://github.com/user/repo#"`.
- `ref_ == ""`.

---

## Malformed source values

### T-092-14: Unknown source prefix is skipped, not panicked
- Input: `source = "bzr+https://…"` (hypothetical unsupported VCS).
- Parser skips the entry without panicking and without emitting a dep.

### T-092-15: Source value is not a string (TOML integer) — entry is skipped, no panic
- Constructing a malformed TOML string where `source` is an integer would fail
  TOML parsing before reaching this logic. Verify that `parse_cargo_lock` returns
  `Err` for syntactically invalid TOML (not a panic).

---

## Tooling gate

### T-092-16: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

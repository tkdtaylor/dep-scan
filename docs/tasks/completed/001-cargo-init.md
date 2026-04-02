# Task 001 — Cargo project initialization

**Status:** backlog
**Depends on:** ADR 001

## Objective

Initialize the Rust project with Cargo.toml containing all dependencies from ADR 001 and a minimal src/main.rs entry point.

## Acceptance criteria

- [ ] Cargo.toml exists with all dependencies (clap, tokio, reqwest, serde, serde_json, rusqlite, toml, anyhow, thiserror, chrono)
- [ ] Dev-dependencies: wiremock, assert_cmd, predicates, tempfile
- [ ] src/main.rs compiles and runs
- [ ] `cargo build` succeeds
- [ ] `cargo test` succeeds (no tests yet, but no errors)
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo fmt --check` passes

## Notes

- No test spec needed — this is pure scaffolding verified by cargo itself
- Remove src/.gitkeep after creating main.rs

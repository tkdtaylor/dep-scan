# Test Spec — Task 066: Pin MSRV (1.88) in CI test job

## Context

`Cargo.toml` pins `rust-version = "1.88"` but CI's `test` job uses
`dtolnay/rust-toolchain@stable`, which floats. This task adds an explicit
`1.88` toolchain to CI alongside `stable` so MSRV drift is caught
automatically.

---

## Validation

### T-066-01: Valid YAML
- `.github/workflows/ci.yml` parses without errors.

### T-066-02: `test` job matrix includes a `rust` axis
- `jobs.test.strategy.matrix.rust` (or equivalent matrix key) is defined.

### T-066-03: Matrix contains `1.88`
- The `rust` axis list contains the string `"1.88"` (or `1.88` unquoted).

### T-066-04: Matrix contains `stable`
- The `rust` axis list contains the string `"stable"`.

### T-066-05: Toolchain step references the matrix axis
- The `dtolnay/rust-toolchain@…` step uses `with.toolchain: ${{ matrix.rust }}` (or
  the equivalent `@${{ matrix.rust }}` form).

### T-066-06: `clippy` and `fmt` jobs stay on `stable`
- `jobs.clippy.steps[*].uses` contains `dtolnay/rust-toolchain@stable`.
- `jobs.fmt.steps[*].uses` contains `dtolnay/rust-toolchain@stable`.

### T-066-07: Both toolchains pass against current `main`
- Locally: `rustup toolchain install 1.88` + `cargo +1.88 test` exits 0.
- Locally: `cargo +stable test` exits 0.
- These match what CI will run on the first invocation.

### T-066-08: MSRV in Cargo.toml unchanged
- `Cargo.toml` `rust-version` stays at `1.88` — this task pins the value, does
  not bump it.

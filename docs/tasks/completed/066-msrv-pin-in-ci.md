# Task 066 — Pin MSRV (1.88) in CI test job

**Status:** backlog
**Depends on:** none (independent of 064/065 but lands in the same workflow file)
**Source:** post-v1.2.0 holistic review (Tier A #4)
**Touches:** `.github/workflows/ci.yml`

## Objective

Guarantee the project compiles + tests on the declared MSRV (Rust 1.88) by
pinning that toolchain in CI, while still exercising the stable toolchain so
new-rust idioms aren't introduced unnoticed.

## Background

`Cargo.toml` declares `rust-version = "1.88"`. The CI workflow uses
`dtolnay/rust-toolchain@stable`, which floats. A future `stable` release that
inadvertently breaks 1.88-compatible code (e.g. through a default-lint change
that's emitted by `1.91` but not by `1.88`) won't surface until a downstream
user reports it.

Two viable approaches:

- **Single-toolchain pin (1.88).** Simple, but means we won't catch new-rust
  idioms (e.g. accidentally using `let-else` chains that require `1.95`) until
  someone tries to build with 1.88.
- **Dual matrix (1.88 + stable).** Doubles CI time on the test leg, but is
  the only way to catch both directions of drift.

The agent-rules retro from v1.2.0 already calls out CHANGELOG test-count drift
as a hard-to-spot regression. Dual matrix is the equivalent guard for MSRV.

## Behavior

1. Add a second matrix axis `rust: [1.88, stable]` to the `test` job (parallel
   to the `os` axis from task 065).
2. The `dtolnay/rust-toolchain` step's input becomes `${{ matrix.rust }}`.
3. If the cross product is too expensive (six legs for three OSes × two
   toolchains), narrow to: 1.88 only on Ubuntu, stable on all three. Document
   the choice in the workflow comment.
4. `clippy` and `fmt` stay on stable (they always have).

## Acceptance criteria

- [ ] `test` job pins `rust: 1.88` for at least one matrix leg
- [ ] `test` job also runs `rust: stable` for at least one leg
- [ ] Both toolchain legs pass against current `main`
- [ ] Workflow YAML is valid
- [ ] No regressions in CI runtime — if the cross-product made wall-clock too
      long, the chosen narrowing is documented inline in the workflow

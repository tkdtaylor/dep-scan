# Task 053 — Scrub user-visible error output (L-6)

**Status:** backlog
**Depends on:** 002 (CLI skeleton), 003 (config system)
**Security finding:** L-6 (LOW — minor info-leak on multi-user host)
**Touches:** `src/main.rs` only (the top-level error handler and, optionally, a
small formatting helper)

## Objective

Gate the full `anyhow` error chain behind `--verbose` so that default error output
is a concise single-line message and does not leak file-system paths that could
identify users on a shared host.

## Background

`eprintln!("Error: {e:#}")` uses `anyhow`'s alternate (`#`) formatter, which
prints every context frame in the chain separated by newlines.  When the error
originates from a failed file-system open (e.g. the SQLite cache DB, a lockfile,
or a temp requirements file), the chain may include the absolute path that was
passed to `open()`.  On a multi-user host (e.g. a shared CI runner or a dev
container with multiple users) that path can reveal a username.

The fix is small:

```rust
Err(e) => {
    if verbose {
        eprintln!("dep-scan error: {e:#}");   // full chain
    } else {
        eprintln!("dep-scan: {}", e);          // outermost message only
    }
    2
}
```

The `verbose` flag is already available in the `Cli` struct (parsed by clap) but
`main()` currently does not thread it through to the error handler because
`run(cli)` consumes `cli` before the error is handled.  The implementer should
extract `verbose` from `cli` before calling `run(cli)` (or restructure the call
slightly — see acceptance criteria).

## Requirements

- **REQ-053-01:** In non-verbose mode (`--verbose` absent), a top-level error
  prints only the outermost `anyhow` message to stderr — no inner cause frames.
- **REQ-053-02:** In non-verbose mode, no file-system path embedded in an inner
  cause frame appears in the stderr output.
- **REQ-053-03:** In verbose mode (`--verbose` present) or when `RUST_LOG=debug`
  is set, the full `anyhow` chain is printed (existing behavior).
- **REQ-053-04:** The exit code remains `2` for top-level errors in both modes.
- **REQ-053-05:** Per-package warning lines that are already single-line
  (`eprintln!("dep-scan: …")` calls inside `run_check`) are not modified.

## Acceptance criteria

- [ ] Non-verbose error output is a single line with no path separator from inner
  causes (REQ-053-01, REQ-053-02); verified by T-053-01, T-053-04, T-053-05.
- [ ] Verbose error output includes the full chain (REQ-053-03); verified by
  T-053-03, T-053-06.
- [ ] Exit code `2` is preserved (REQ-053-04); verified by T-053-08.
- [ ] `verbose` is extracted from `cli` before `run(cli)` consumes it, so the
  flag is accessible in the error handler.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Structured logging (tracing/log crate integration) — a separate task.
- Redacting paths from within existing per-package `eprintln!` warnings — those
  do not embed absolute paths today.
- `RUST_LOG` environment variable handling — if it's not already wired, leave it
  for a structured-logging task.

## Risk notes

- `main()` is a `#[tokio::main]` async fn that calls `run(cli).await`.  To access
  `verbose` after `run()` returns, extract it before the `run()` call:
  ```rust
  let verbose = cli.verbose;
  let exit_code = match run(cli).await { … };
  ```
  This is a one-line change and does not affect behavior.
- The change to error formatting is deliberately minimal; a future structured-
  logging pass can replace `eprintln!` wholesale.

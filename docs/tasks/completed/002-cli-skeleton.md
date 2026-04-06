# Task 002 — CLI skeleton with clap

**Status:** backlog
**Depends on:** 001

## Objective

Define the CLI structure using clap derive macros. Create subcommands for check, install, and config with appropriate flags and arguments.

## Acceptance criteria

- [x] src/cli.rs defines Cli struct with clap derive
- [x] Subcommands: `check`, `install`, `config`
- [x] Global flags: `--config <path>`, `--verbose`, `--quiet`
- [x] `check` subcommand: positional package name(s), `--registry` flag, `--json` output flag
- [x] `install` subcommand: stub that prints "not yet implemented"
- [x] `config` subcommand: `show` and `init` sub-subcommands
- [x] main.rs parses CLI args and dispatches to subcommands
- [x] `dep-scan --help` shows usage
- [x] `dep-scan check --help` shows check-specific usage
- [x] All tests pass, clippy clean, fmt clean

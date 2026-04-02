# Task 002 — CLI skeleton with clap

**Status:** backlog
**Depends on:** 001

## Objective

Define the CLI structure using clap derive macros. Create subcommands for check, install, and config with appropriate flags and arguments.

## Acceptance criteria

- [ ] src/cli.rs defines Cli struct with clap derive
- [ ] Subcommands: `check`, `install`, `config`
- [ ] Global flags: `--config <path>`, `--verbose`, `--quiet`
- [ ] `check` subcommand: positional package name(s), `--registry` flag, `--json` output flag
- [ ] `install` subcommand: stub that prints "not yet implemented"
- [ ] `config` subcommand: `show` and `init` sub-subcommands
- [ ] main.rs parses CLI args and dispatches to subcommands
- [ ] `dep-scan --help` shows usage
- [ ] `dep-scan check --help` shows check-specific usage
- [ ] All tests pass, clippy clean, fmt clean

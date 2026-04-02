# Task 003 — Configuration system

**Status:** backlog
**Depends on:** 002

## Objective

Implement .dep-scan.toml configuration file loading with sensible defaults and environment variable overrides.

## Acceptance criteria

- [ ] src/config.rs defines Config struct with serde Deserialize
- [ ] Fields: `min_package_age_hours` (default 48), `registries` table with npm/pypi URLs, policy toggles
- [ ] Load precedence: CLI `--config` path -> `.dep-scan.toml` in cwd -> defaults
- [ ] Env var overrides: `DEP_SCAN_MIN_AGE` etc.
- [ ] Registry URLs are configurable, not hardcoded
- [ ] Invalid config files produce clear error messages
- [ ] `config show` prints current effective config
- [ ] `config init` creates a default .dep-scan.toml
- [ ] All tests pass, clippy clean, fmt clean

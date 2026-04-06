# Task 003 — Configuration system

**Status:** backlog
**Depends on:** 002

## Objective

Implement .dep-scan.toml configuration file loading with sensible defaults and environment variable overrides.

## Acceptance criteria

- [x] src/config.rs defines Config struct with serde Deserialize
- [x] Fields: `min_package_age_hours` (default 48), `registries` table with npm/pypi URLs, policy toggles
- [x] Load precedence: CLI `--config` path -> `.dep-scan.toml` in cwd -> defaults
- [x] Env var overrides: `DEP_SCAN_MIN_AGE` etc.
- [x] Registry URLs are configurable, not hardcoded
- [x] Invalid config files produce clear error messages
- [x] `config show` prints current effective config
- [x] `config init` creates a default .dep-scan.toml
- [x] All tests pass, clippy clean, fmt clean

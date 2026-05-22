# Configuration specification

**Status:** Authoritative — code MUST conform.
**Last updated:** 2026-05-22 (v1.2.0)

This document specifies how dep-scan resolves its effective configuration
at runtime: layering order, environment-variable overrides, and the
default values that ship in `Config::default()`.

## Layering order

```
built-in defaults  <  .dep-scan.toml  <  environment variables  <  CLI flags
       low-precedence ──────────────────────────────────────── high-precedence
```

1. **Built-in defaults.** Defined by the `Default` impls in
   [src/config.rs](../../src/config.rs).
2. **TOML file.** Either the path given via `--config <PATH>` or
   `.dep-scan.toml` in the current working directory. Missing fields
   inherit from defaults via `#[serde(default = …)]`. If `--config`
   points at a non-existent path, dep-scan MUST fall back to defaults
   silently (no error) so CI configurations can be optional.
3. **Environment variables.** Applied after file load in
   `Config::apply_env_overrides`.
4. **CLI flags.** Read by the subcommand handlers themselves (e.g.
   `--registry`, `--lockfile`).

Layers are merged, not replaced. A user supplying a partial
`.dep-scan.toml` MUST get defaults for the unset fields.

## Schema

The complete TOML schema is defined by the `Config` struct in
[src/config.rs](../../src/config.rs#L213-L242). At v1.2.0:

```toml
# Top level
min_package_age_hours = 48                   # u64, default 48
cache_path = "/abs/or/relative/cache.db"    # optional override

[registries]
npm_url        = "https://registry.npmjs.org"
pypi_url       = "https://pypi.org"
crates_url     = "https://crates.io"
go_proxy_url   = "https://proxy.golang.org"
go_sum_db_url  = "https://sum.golang.org"

[policies]
check_typosquatting           = true
check_install_scripts         = true
check_min_age                 = true
check_maintainer_changes      = true
check_vulnerabilities         = true
check_obfuscation             = true
check_npm_provenance          = true
require_npm_provenance        = false
check_pypi_provenance         = true
require_pypi_provenance       = false
check_go_sumdb                = true
require_go_sumdb              = false
maintainer_first_seen_warning = false   # opt-in, task 048

[osv]
osv_url = "https://api.osv.dev"

[dependency_confusion]
internal_prefixes = ["internal-", "private-", "corp-"]

[popularity]
min_downloads = 1000
```

> Note: `dep-scan config init` writes the same keys with the same default
> values via `toml::to_string_pretty(self)`. The generated file does NOT
> include explanatory comments and emits `internal_prefixes` as a
> multi-line array. The README example in
> [../../README.md](../../README.md#configuration) is annotated for
> human consumption — annotations are descriptive, not contractual.

## Environment variable overrides

Applied unconditionally over the file-loaded config in
`Config::apply_env_overrides`. A missing env var is a no-op; an empty
value is set verbatim (no special handling).

| Env var | Overrides | Type |
|---------|-----------|------|
| `DEP_SCAN_MIN_AGE` | `min_package_age_hours` | `u64` (parsing failure ignored — no error) |
| `DEP_SCAN_NPM_URL` | `registries.npm_url` | string |
| `DEP_SCAN_PYPI_URL` | `registries.pypi_url` | string |
| `DEP_SCAN_CRATES_URL` | `registries.crates_url` | string |
| `DEP_SCAN_GO_PROXY_URL` | `registries.go_proxy_url` | string |
| `DEP_SCAN_GO_SUM_DB_URL` | `registries.go_sum_db_url` | string |
| `DEP_SCAN_CACHE_PATH` | `cache_path` | string |
| `DEP_SCAN_OSV_URL` | `osv.osv_url` | string |

The complete list is exactly the 8 entries above. Adding a new env var
MUST update this table and the README env-var table in the same PR.

## Cache path resolution

`Config::resolve_cache_path` returns:

1. `cache_path` (from file or env) if set.
2. Otherwise `$HOME/.dep-scan/cache.db` on Unix (or
   `$USERPROFILE\.dep-scan\cache.db` on Windows).
3. If neither `$HOME` nor `$USERPROFILE` is set, fall back to
   `./.dep-scan/cache.db`.

## Mutability

`Config` is immutable after `Config::load`. The runtime MUST NOT mutate
loaded config except via the layering above. Tests that need a modified
config MUST construct a fresh `Config` rather than mutating a shared one.

## Backwards compatibility

- Adding a new field to `PolicyConfig`, `RegistryConfig`, etc., is
  backwards-compatible **if and only if** the field is annotated with
  `#[serde(default = …)]`. Old TOML files MUST continue to parse.
- Removing a field is a breaking change.
- Renaming a field is a breaking change unless aliased via
  `#[serde(alias = "old_name")]`.

## Sensitive values

dep-scan currently has no fields that carry secrets. Registry URLs are
not secret. The OSV.dev endpoint requires no API key. If a future field
ever carries a credential, it MUST be redacted in `dep-scan config show`
output and MUST NOT be logged under `--verbose`.

## Defaults summary

| Field | Default |
|-------|---------|
| `min_package_age_hours` | `48` |
| `cache_path` | `None` (resolved to `$HOME/.dep-scan/cache.db`) |
| `registries.npm_url` | `https://registry.npmjs.org` |
| `registries.pypi_url` | `https://pypi.org` |
| `registries.crates_url` | `https://crates.io` |
| `registries.go_proxy_url` | `https://proxy.golang.org` |
| `registries.go_sum_db_url` | `https://sum.golang.org` |
| `policies.check_*` | all `true` |
| `policies.require_npm_provenance` | `false` |
| `policies.require_pypi_provenance` | `false` |
| `policies.require_go_sumdb` | `false` |
| `policies.maintainer_first_seen_warning` | `false` |
| `osv.osv_url` | `https://api.osv.dev` |
| `dependency_confusion.internal_prefixes` | `["internal-", "private-", "corp-"]` |
| `popularity.min_downloads` | `1000` |

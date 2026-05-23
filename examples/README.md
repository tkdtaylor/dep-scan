# examples/

Copy-paste-ready material for common dep-scan scenarios.

| File | Purpose |
|------|---------|
| `dep-scan.locked-down.toml` | Production CI config — all `require_*` on, 7-day min age, 10 k download floor |
| `dep-scan.permissive.toml` | Local dev config — all checks on but nothing blocked for missing provenance |
| `github-actions.yml` | Complete GitHub Actions workflow — install dep-scan and scan a lockfile on PRs |
| `json-output.json` | Sample `dep-scan check --json` output showing pass / warn / block results |

Copy the config that fits your use case to `.dep-scan.toml` at your project root and
adjust the `internal_prefixes` list to match your organisation's package-name convention.

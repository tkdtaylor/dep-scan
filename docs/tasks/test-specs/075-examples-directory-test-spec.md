# Test Spec — Task 075: Add examples/ directory

## Context

dep-scan lacks copy-paste-ready material for first-time users. This task
adds an `examples/` directory with locked-down and permissive configs, a
CI snippet, and a sample JSON output.

---

## Validation

### T-075-01: examples/ exists
- The directory `examples/` is at repo root.

### T-075-02: locked-down config parses
- `dep-scan config show --config examples/dep-scan.locked-down.toml` exits
  0 and prints a valid effective config.

### T-075-03: locked-down config sets all `require_*` to true
- Grep / TOML-parse confirms `require_npm_provenance = true`,
  `require_pypi_provenance = true`, `require_go_sumdb = true`.

### T-075-04: locked-down config sets min age ≥ 168
- `min_package_age_hours` is at least 168.

### T-075-05: permissive config parses
- `dep-scan config show --config examples/dep-scan.permissive.toml` exits 0.

### T-075-06: permissive config sets all `require_*` to false
- Grep / TOML-parse confirms `require_*` are false.

### T-075-07: CI workflow YAML is valid
- `examples/github-actions.yml` parses without errors.

### T-075-08: CI workflow includes install + check
- The workflow has a step that downloads dep-scan (via install.sh or a
  release asset) AND a step that runs `dep-scan check --lockfile`.

### T-075-09: JSON output is valid
- `cat examples/json-output.json | python -m json.tool` exits 0.

### T-075-10: JSON output matches the documented schema
- Top-level has `scanned_at` (RFC 3339 string) and `packages` (array).
- Each `packages[]` entry has `name`, `version`, `registry`, `result`,
  `reason`, `policies` keys.
- `result` values are exactly `"pass"`, `"warn"`, or `"block"`.

### T-075-11: examples/README.md exists
- A one-paragraph orientation file explains each example.

### T-075-12: README links to examples/
- README.md contains a link to `examples/` (with surrounding context — not
  a bare link).

### T-075-13: No hardcoded non-default registry URLs
- `grep -rn "https://" examples/ | grep -v "files.pythonhosted\|api.osv\|
  registry.npmjs\|pypi.org\|crates.io\|proxy.golang\|sum.golang"` returns
  no matches (no surprise registries in examples).

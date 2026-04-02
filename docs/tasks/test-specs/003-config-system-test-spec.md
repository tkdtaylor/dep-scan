# Test Spec — Task 003: Configuration system

## Unit tests (src/config.rs)

### T-003-01: Default config has expected values
- Expected: min_package_age_hours = 48, npm URL = "https://registry.npmjs.org", pypi URL = "https://pypi.org"

### T-003-02: Load config from TOML string
- Input: TOML with min_package_age_hours = 24
- Expected: Config with min_package_age_hours = 24, other fields at defaults

### T-003-03: Load config from file path
- Setup: write TOML to temp file
- Input: path to temp file
- Expected: Config loaded correctly

### T-003-04: Missing config file falls back to defaults
- Input: non-existent path
- Expected: default Config returned (no error)

### T-003-05: Invalid TOML produces clear error
- Input: malformed TOML string
- Expected: Error with descriptive message

### T-003-06: Env var override for min age
- Setup: set DEP_SCAN_MIN_AGE=12
- Expected: min_package_age_hours = 12 regardless of file

### T-003-07: Registry URLs are configurable
- Input: TOML with custom npm registry URL
- Expected: Config reflects custom URL

### T-003-08: Partial config merges with defaults
- Input: TOML with only min_package_age_hours set
- Expected: registry URLs still at defaults

## Integration tests

### T-003-09: config show prints current config
- Run: `dep-scan config show`
- Expected: output contains "min_package_age_hours" and "48"

### T-003-10: config init creates default file
- Run: `dep-scan config init` in temp dir
- Expected: .dep-scan.toml created with default values

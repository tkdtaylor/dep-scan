# Test Spec — Task 002: CLI skeleton with clap

## Unit tests (src/cli.rs)

### T-002-01: CLI parses check subcommand with package names
- Input: `["dep-scan", "check", "lodash", "express"]`
- Expected: CheckCommand with packages = ["lodash", "express"]

### T-002-02: CLI parses check with --registry flag
- Input: `["dep-scan", "check", "lodash", "--registry", "npm"]`
- Expected: CheckCommand with registry = Some("npm")

### T-002-03: CLI parses check with --json flag
- Input: `["dep-scan", "check", "lodash", "--json"]`
- Expected: CheckCommand with json = true

### T-002-04: CLI parses global --config flag
- Input: `["dep-scan", "--config", "/path/to/config.toml", "check", "lodash"]`
- Expected: Cli with config = Some("/path/to/config.toml")

### T-002-05: CLI parses global --verbose flag
- Input: `["dep-scan", "--verbose", "check", "lodash"]`
- Expected: Cli with verbose = true

### T-002-06: CLI parses config show subcommand
- Input: `["dep-scan", "config", "show"]`
- Expected: ConfigCommand::Show

### T-002-07: CLI parses config init subcommand
- Input: `["dep-scan", "config", "init"]`
- Expected: ConfigCommand::Init

## Integration tests (assert_cmd)

### T-002-08: --help prints usage
- Run: `dep-scan --help`
- Expected: exit code 0, output contains "dep-scan" and "check"

### T-002-09: check --help prints check usage
- Run: `dep-scan check --help`
- Expected: exit code 0, output contains "package" and "--registry"

### T-002-10: install prints not yet implemented
- Run: `dep-scan install lodash`
- Expected: output contains "not yet implemented"

### T-002-11: no args shows help/error
- Run: `dep-scan`
- Expected: exit code non-zero or shows help

# Test Spec — Task 016: v0.2 integration tests + output polish

## Integration tests (assert_cmd + wiremock)

### T-016-01: Multi-policy violations in output
- Setup: wiremock npm JSON for 1h old package + wiremock OSV returns vulnerability
- Run: `dep-scan check new-vuln-pkg --registry npm`
- Expected: exit 1, output shows BOTH age block AND vulnerability block

### T-016-02: Suspicious install script blocks
- Setup: wiremock npm JSON with postinstall containing `eval(require('child_process')...)`
- Run: `dep-scan check evil-pkg --registry npm`
- Expected: exit 1, output mentions install script pattern

### T-016-03: Clean package passes all policies
- Setup: wiremock npm JSON for 72h old package, no vulns, clean scripts
- Run: `dep-scan check clean-pkg --registry npm`
- Expected: exit 0, all policies show pass

### T-016-04: Typosquatting match in output
- Run: `dep-scan check loadsh --registry npm` (wiremock for registry)
- Expected: output warns about similarity to "lodash"

### T-016-05: Config toggle disables policy
- Setup: config with `check_min_age = false`
- Run: `dep-scan check new-pkg --registry npm`
- Expected: no age policy in output, only other policies evaluated

### T-016-06: JSON output has stable multi-policy schema
- Run with `--json`
- Expected: each package has "policies" array, each entry has name/result/reason

### T-016-07: Exit codes with multi-policy
- Package passes age but fails vulnerability
- Expected: exit 1 (worst result wins)

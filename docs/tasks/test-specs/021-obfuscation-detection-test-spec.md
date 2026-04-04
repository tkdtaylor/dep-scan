# Test Spec — Task 021: Obfuscation detection

## Unit tests

### T-021-01: Clean script passes
- Input: ScanContext with one install script containing `"echo hello && npm run build"`
- Expected: `PolicyResult::Pass`

### T-021-02: Long base64 string blocks
- Input: ScanContext with install script containing an 80-character base64 string (e.g. `"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ=="`)
- Expected: `PolicyResult::Block(msg)` where msg contains `"long_base64"`

### T-021-03: Hex escape chain blocks
- Input: ScanContext with install script containing `"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f"` (5+ consecutive hex escapes)
- Expected: `PolicyResult::Block(msg)` where msg contains `"hex_escape_chain"`

### T-021-04: Unicode escape chain detected
- Input: ScanContext with install script containing `"\\u0068\\u0074\\u0074\\u0070"` (4+ consecutive unicode escapes)
- Expected: `PolicyResult::Block(msg)` where msg contains `"unicode_escape_chain"`

### T-021-05: String concatenation building URL warns
- Input: ScanContext with install script containing `var u = "ht" + "tp"`
- Expected: `PolicyResult::Warn(msg)` where msg contains `"string_concat_url"`

### T-021-06: fromCharCode chain blocks
- Input: ScanContext with install script containing `String.fromCharCode(104,116,116,112)`
- Expected: `PolicyResult::Block(msg)` where msg contains `"fromCharCode_chain"`

### T-021-07: No install scripts passes (empty)
- Input: ScanContext with empty `install_scripts` vec
- Expected: `PolicyResult::Pass`

### T-021-08: Policy name is "obfuscation"
- Create an `ObfuscationPolicy` instance
- Call `policy.name()`
- Expected: returns `"obfuscation"`

### T-021-09: chr() chain blocks
- Input: ScanContext with install script containing `chr(104).chr(116).chr(116)`
- Expected: `PolicyResult::Block(msg)` where msg contains `"chr_chain"`

### T-021-10: env_concat warns
- Input: ScanContext with install script containing `process.env["HO" +`
- Expected: `PolicyResult::Warn(msg)` where msg contains `"env_concat"`

### T-021-11: Block takes precedence over warn (mixed patterns)
- Input: ScanContext with install script containing both a base64 block pattern AND a string_concat_url warn pattern
- Expected: `PolicyResult::Block(_)` (block wins over warn)

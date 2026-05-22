# Test Spec — Task 051: Tighten install-script false-positive scope (L-3 + L-4)

## Context

Two patterns in `src/policy/install_script.rs` produce false positives:

- **L-3:** `Detection::Contains("Function(")` matches benign comment text such as
  `// Function() is the constructor for…` in postinstall comments. The fix is to
  strip line comments (`//…` and `#…`) and block comments (`/*…*/`) from the script
  content before applying substring matching.

- **L-4:** `Detection::Regex(r"[A-Za-z0-9+/=]{40,}")` matches any 40+ character
  alphanumeric run, including SHA-256 hex strings (64 hex chars, which fit `A–Z
  0–9`) and Git revisions embedded in build commands. The fix is to require that the
  match contain at least one base64-exclusive character (`+`, `/`, or `=`) so that
  pure-hex sequences (artifact hashes, git SHAs) are excluded.

Both fixes touch only `src/policy/install_script.rs`.

---

## Unit tests — L-3: comment stripping before pattern matching

### T-051-01: `Function(` in a single-line `//` comment does not trigger Block
- Input script content: `"// Function() is the constructor for…\nconsole.log('hello')"`
- Expected: `InstallScriptPolicy::evaluate` returns `Pass`

### T-051-02: `Function(` in a `#` comment does not trigger Block
- Input: `"# Function() is used internally\necho done"`
- Expected: `Pass`

### T-051-03: `Function(` in a `/* … */` block comment does not trigger Block
- Input: `"/* Function() is the constructor\n   for dynamic code */\nconsole.log(1)"`
- Expected: `Pass`

### T-051-04: `Function(` in live code (not inside a comment) still triggers Block
- Input: `"var fn = new Function('return this')()"`
- Expected: `Block` with reason mentioning `"Function constructor"`

### T-051-05: `Function(` appears both in a comment and in live code — Block wins
- Input: `"// Function() is benign\nnew Function('return this')()"`
- Expected: `Block` (the live-code occurrence triggers the pattern after comment removal)

### T-051-06: `eval(` in a `//` comment does not trigger Block
- Input: `"// eval(Buffer.from('x','base64').toString()) — example only\necho done"`
- Expected: `Pass`
- Rationale: comment stripping applies to all `Contains` patterns, not just `Function(`.

### T-051-07: `exec(` after a `#` comment marker does not trigger Block
- Input: `"# exec() removed for security\necho ok"`
- Expected: `Pass`

### T-051-08: Multi-line block comment spanning `child_process` does not trigger Block
- Input: `"/*\n * Calls child_process.exec\n */\nconsole.log('clean')"`
- Expected: `Pass`

---

## Unit tests — L-4: base64 pattern requires at least one base64-exclusive character

### T-051-09: A 64-character hex string (e.g. SHA-256) does not trigger the base64 Warn
- Input script: a postinstall containing a 64-char lowercase hex string
  `"sha256sum: a3b1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829304050607080a"`
- Expected: `Pass` — pure hex sequences must not match `[A-Za-z0-9+/=]{40,}` because
  they contain no `+`, `/`, or `=` characters.

### T-051-10: A 40-character git SHA (hex) does not trigger the base64 Warn
- Input: `"git checkout a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80918"`
- Expected: `Pass`

### T-051-11: A genuine base64-encoded payload (contains `=` padding) triggers Warn
- Input: `"var data = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZA=='"`
- Expected: `Warn` with reason mentioning `"base64"`

### T-051-12: A genuine base64 payload containing `/` triggers Warn
- Input: `"var data = 'YWJjZGVmZ2hpamtsbW5vcHFy/3R1dnd4eXoxMjM0NTY3ODkw'"`
- Expected: `Warn` with reason mentioning `"base64"`

### T-051-13: A genuine base64 payload containing `+` triggers Warn
- Input: `"var data = 'YWJj+GVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw'"`
- Expected: `Warn` with reason mentioning `"base64"`

### T-051-14: A URL containing base64-exclusive chars (`=`) in query string triggers Warn
  only if the base64-looking segment is >= 40 chars and has `+`, `/`, or `=`
- Input: `"fetch('https://cdn.example.com/loader?q=abc+def/ghi/jkl=mno=pqr=stu=vwxyz0')"`
- The segment after `q=` contains `+`, `/`, and `=` — expected: `Warn` (both the http
  URL pattern and the base64 pattern would fire; worst is `Warn`).

### T-051-15: An `atob(` loader context with a >=40-char base64 payload triggers Warn
- Input: `"atob('YWJj+GVmZ2hp/mtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3')"`
- Expected: `Warn` — the string has `+` and `/` so the tightened pattern matches.

---

## Regression tests

### T-051-16: All task 012 install-script tests that were passing before still pass
- Run `cargo test install_script`
- Expected: 0 failures — the existing happy-path, eval, subprocess, os.system,
  http-url, process.env, os.environ, and multiple-scripts tests are unaffected.

### T-051-17: `eval(Buffer.from('bWFsaWNpb3Vz', 'base64').toString())` (T-012-02 fixture)
  still triggers Block after comment stripping is introduced
- The original T-012-02 fixture appears in live code, not a comment.
- Expected: `Block` with reason mentioning `"eval"`.

### T-051-18: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

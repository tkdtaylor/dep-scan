# Task 051 — Tighten install-script false-positive scope (L-3 + L-4)

**Status:** backlog
**Depends on:** 012 (install script analysis)
**Security finding:** L-3, L-4 (LOW — false positives, not false negatives)
**Touches:** `src/policy/install_script.rs` only

## Objective

Reduce false positives from two patterns in the install-script policy without
weakening detection coverage.

## Background

**L-3 — `Function(` substring match hits comments.**
`Detection::Contains("Function(")` at line 77 fires on postinstall scripts that
mention `Function()` in a `//` or `#` line comment or a `/* … */` block comment,
e.g. `// Function() is the constructor for…`. A benign package that documents
its API in a postinstall script comment will be incorrectly blocked.

**L-4 — Base64 regex matches hex strings.**
`Detection::Regex(r"[A-Za-z0-9+/=]{40,}")` at line 83 matches any 40+ char
sequence drawn from that alphabet. A 64-char SHA-256 hex digest (`[0-9a-f]{64}`)
fits within `A-Za-z0-9`, so build scripts that reference artifact checksums or
git revisions (e.g. `git checkout <sha>`) are flagged as suspicious.

## Behavior

### L-3 fix — strip comments before matching

Before applying any `Detection::Contains` or `Detection::Regex` pattern, strip:
- Line comments: everything from `//` to end-of-line (JavaScript/Rust/C style)
- Shell comments: everything from `#` to end-of-line
- Block comments: `/* … */` (non-greedy, multi-line)

The stripping is applied to a working copy of the script content; the original
is preserved for error-message purposes.

### L-4 fix — require a base64-exclusive character in the match

Tighten the regex to require at least one character that cannot appear in a
hex string: `+`, `/`, or `=`. A concrete option:

```
[A-Za-z0-9+/=]{40,}
```
paired with a lookahead or two-pass check that at least one `[+/=]` is present
inside the match. A simple approach is a two-step match:
1. Find spans matching `[A-Za-z0-9+/=]{40,}`.
2. Accept only those spans that contain at least one `[+/=]` character.

Alternatively, replace the single regex with one that structurally requires a
`+`, `/`, or `=`:

```
[A-Za-z0-9]*[+/=][A-Za-z0-9+/=]{38,}
```

Either approach is acceptable; document the choice in source code.

## Requirements

- **REQ-051-01:** `Function(` that appears exclusively inside a `//` comment,
  `#` comment, or `/* … */` block comment does not produce a `Block` verdict.
- **REQ-051-02:** `Function(` that appears in executable code (outside any
  comment) still produces a `Block` verdict.
- **REQ-051-03:** A `//` or `#` comment containing any other block-pattern
  substring (`eval(`, `exec(`, `child_process`, etc.) does not trigger that
  pattern.
- **REQ-051-04:** Comment stripping applies to a copy of the script — the
  original content is not modified and is still usable for diagnostic messages.
- **REQ-051-05:** A 40–70 character pure-hex string (no `+`, `/`, or `=`)
  does not trigger the base64 `Warn`.
- **REQ-051-06:** A string of 40+ characters drawn from `[A-Za-z0-9+/=]` that
  contains at least one `+`, `/`, or `=` still triggers the base64 `Warn`.
- **REQ-051-07:** All task 012 test cases continue to pass.

## Acceptance criteria

- [ ] `Function(` in a `//` comment returns `Pass` (REQ-051-01); verified by T-051-01.
- [ ] `Function(` in a `#` comment returns `Pass` (REQ-051-01); verified by T-051-02.
- [ ] `Function(` in a `/* … */` comment returns `Pass` (REQ-051-01); verified by T-051-03.
- [ ] `Function(` in live code returns `Block` (REQ-051-02); verified by T-051-04.
- [ ] Comment + live code together returns `Block` (REQ-051-02); verified by T-051-05.
- [ ] Other block patterns (`eval(`, `exec(`) in comments return `Pass` (REQ-051-03);
  verified by T-051-06, T-051-07, T-051-08.
- [ ] 64-char hex string returns `Pass` (REQ-051-05); verified by T-051-09.
- [ ] 40-char git SHA returns `Pass` (REQ-051-05); verified by T-051-10.
- [ ] Base64 string with `=` returns `Warn` (REQ-051-06); verified by T-051-11.
- [ ] Base64 string with `/` returns `Warn` (REQ-051-06); verified by T-051-12.
- [ ] Base64 string with `+` returns `Warn` (REQ-051-06); verified by T-051-13.
- [ ] T-012 regression suite passes (REQ-051-07); verified by T-051-16, T-051-17.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` pass.

## Out of scope

- Stripping string literals before matching (a future enhancement).
- Adding new block-pattern detection rules (a separate task).
- Changing the severity levels of any existing patterns.

## Risk notes

- Comment stripping introduces a pre-processing step; care must be taken not to
  corrupt script content that contains `//` inside a string literal (e.g.
  `"https://example.com"`). The stripping need not be perfect — it is a
  false-positive reduction measure, not a security gate. Over-stripping (removing
  too much) is acceptable; under-stripping (not removing a comment) is also
  acceptable, since it only preserves the current false-positive behavior.
- Tightening the base64 regex reduces recall by design. The security audit
  confirmed this is acceptable: pure-hex hashes in build scripts are extremely
  common and the detection has negligible value against attackers who can simply
  avoid `+`, `/`, and `=` in their payload (compression/encoding can be adjusted).

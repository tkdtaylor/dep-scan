# Task 095 — VCS host policy configuration

**Status:** backlog
**Depends on:** 090 (source model — `DependencySource::Git` exists so the policy
               has something to check URLs against)
**ADR:** 008 (piece 2 — VCS client; host-policy config sub-task)
**Touches:** `src/config.rs` (new `[vcs]` section), `src/policy/vcs_host.rs`
            (new — host extraction + allow/deny check logic)

## Objective

Introduce the `[vcs]` config section with `allowed_hosts` and `denied_hosts`
lists, and a `check_host_policy_for_url` function that validates a git URL's
host against those lists before any fetch is attempted. No actual fetch occurs
in this task. This is the config-and-validation precondition for the VCS fetch
client in task 096.

## Background

ADR 008 constraint: "no hardcoded hosts/URLs." There is no built-in trust in
`github.com` over any other host; the default (empty lists) allows any host. An
enterprise operator can restrict fetching to an internal mirror by setting
`allowed_hosts = ["git.corp.example.com"]`. A paranoid operator can deny known
bad hosts with `denied_hosts`. The deny list takes precedence over the allow list.

Fail-closed posture (ADR 003/008): if a URL's host cannot be extracted (malformed
URL), the check must reject it — a dep-scan that cannot determine where it is
fetching from must not proceed silently.

## Requirements

### REQ-095-01: `[vcs]` config section
Add `VcsConfig { allowed_hosts: Vec<String>, denied_hosts: Vec<String> }` to
`Config`. Defaults to empty lists. Unknown fields return `Err` at config load.

### REQ-095-02: `extract_host(url: &str) -> Option<String>`
Pure function that parses the URL, strips any `user@` prefix and `:port` suffix
from the host component, and returns the bare hostname. Returns `None` for
unparseable URLs.

### REQ-095-03: `check_host_policy(host: &str, config: &Config) -> Result<()>`
- Empty `allowed_hosts` AND empty `denied_hosts`: any host is permitted.
- Non-empty `allowed_hosts`: host must appear in the list (case-insensitive).
- Non-empty `denied_hosts`: host must NOT appear in the list; deny takes
  precedence over allow.
- Returns `Err` with a message naming the host and which list rejected it.

### REQ-095-04: `check_host_policy_for_url(url: &str, config: &Config) -> Result<()>`
Wraps `extract_host` + `check_host_policy`. Returns `Err` if the host cannot be
extracted (fail-closed). This is the function the VCS fetch client will call.

### REQ-095-05: No hardcoded hosts in runtime logic
The allow/deny logic must contain no literal registry or VCS host strings.
`"github.com"` may appear only in tests and comments.

### REQ-095-06: `config init` emits `[vcs]` section with commented examples
`config init` writes the `[vcs]` section with `allowed_hosts` and `denied_hosts`
as commented-out lists and an explanatory comment.

## Acceptance criteria

- [ ] `Config::default().vcs.allowed_hosts == []` and `.vcs.denied_hosts == []`
- [ ] Host on allow list → permitted; host not on non-empty allow list → rejected
- [ ] Host on deny list → rejected; deny takes precedence over allow
- [ ] Unresolvable host → rejected fail-closed
- [ ] Case-insensitive host matching
- [ ] No literal `"github.com"` in runtime policy logic
- [ ] `config init` emits `[vcs]` section
- [ ] All T-095-01 through T-095-22 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/095-vcs-host-policy-config-test-spec.md`

## Out of scope

- Actual VCS fetch (task 096)
- Cache integration (task 097)
- Wiring policies onto fetched trees (task 098)
- SSRF prevention beyond host allow/deny (no IP-range blocking in this task)

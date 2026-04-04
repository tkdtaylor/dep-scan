# Task 027 — Install script

**Status:** backlog
**Depends on:** 026 (needs release artifacts to exist)

## Objective

Curl-able install script for easy binary installation.

## Acceptance criteria

- [ ] install.sh at project root
- [ ] Detects OS and architecture
- [ ] Downloads correct binary from latest GitHub release
- [ ] Installs to ~/.local/bin/ or /usr/local/bin/ with sudo
- [ ] Verifies SHA256 checksum
- [ ] Passes shellcheck
- [ ] Dry-run mode (--dry-run flag)

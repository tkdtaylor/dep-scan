# Task 027 — Install script

**Status:** backlog
**Depends on:** 026 (needs release artifacts to exist)

## Objective

Curl-able install script for easy binary installation.

## Acceptance criteria

- [x] install.sh at project root
- [x] Detects OS and architecture
- [x] Downloads correct binary from latest GitHub release
- [x] Installs to ~/.local/bin/ or /usr/local/bin/ with sudo
- [x] Verifies SHA256 checksum
- [x] Passes shellcheck
- [x] Dry-run mode (--dry-run flag)

# Tech Stack

**Project:** dep-scan
**Last updated:** 2026-04-02

## Core stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Rust or Go (TBD — ADR pending) | Cross-platform, fast, single binary distribution |
| Framework | — | |
| Database | Local SQLite / embedded KV store | Hash cache for already-scanned dependencies |
| Infrastructure | — | Local-first CLI tool |

## Development tooling

| Tool | Purpose |
|------|---------|
| Git | Version control |
| GitHub Actions | CI/CD |

## Testing

| Tool | Scope |
|------|-------|
| TBD (language-dependent) | Unit tests |
| TBD | Integration tests (mock registry responses) |
| TBD | End-to-end tests (real package manager invocations) |

## Notes

> Language decision (Rust vs Go) is the first ADR to write. Both are strong candidates:
> - Rust: stronger static analysis, better security guarantees, cargo ecosystem
> - Go: faster compile times, simpler cross-compilation, familiar to more contributors

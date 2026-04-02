# Tech Stack

**Project:** dep-scan
**Last updated:** 2026-04-02

## Core stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Rust | Cross-platform, fast, single binary, strong type system for analysis work ([ADR 001](decisions/001-language-choice.md)) |
| CLI framework | clap (derive) | Mature, ergonomic, auto-generates help and shell completions |
| HTTP client | reqwest + tokio | Async HTTP for parallel registry API calls |
| Serialization | serde + serde_json | Best-in-class JSON deserialization for registry metadata |
| Database | rusqlite (SQLite) | Hash cache for already-scanned dependencies |
| Config | toml (serde) | Parse `.dep-scan.toml` policy files |
| Error handling | anyhow / thiserror | Ergonomic error propagation |
| Infrastructure | — | Local-first CLI tool |

## Development tooling

| Tool | Purpose |
|------|---------|
| Git | Version control |
| GitHub Actions | CI/CD |

## Testing

| Tool | Scope |
|------|-------|
| `cargo test` | Unit tests |
| `cargo test` + `mockito` or `wiremock` | Integration tests (mock registry responses) |
| Shell scripts + `assert_cmd` | End-to-end tests (real CLI invocations) |

## Notes

> Language decision made — see [ADR 001](decisions/001-language-choice.md).

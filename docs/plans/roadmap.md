# Roadmap

**Project:** dep-scan
**Last updated:** 2026-04-04

## Completed milestones

### v0.1 — Foundation (2026-04-02)

- [x] Project setup and tooling (Rust, ADR 001)
- [x] Core CLI skeleton with subcommands (check, install, config)
- [x] Registry API clients (npm, PyPI) for package metadata
- [x] Minimum package age check (configurable, default 48h)
- [x] Local hash cache (SQLite)

### v0.2 — Core detection (2026-04-02)

- [x] Install script analysis (postinstall, setup.py)
- [x] Typosquatting detection (edit distance against popular packages)
- [x] Maintainer/ownership change detection
- [x] Known vulnerability check (OSV.dev)
- [x] Dependency confusion heuristics

### v0.3 — Expanded ecosystem (2026-04-04)

- [x] crates.io and Go module support
- [x] Popularity/download threshold warnings
- [x] Configurable policy file (.dep-scan.toml)
- [x] Obfuscation detection (base64, hex-encoded URLs, env var exfiltration patterns)

### v1.0 — Production ready (2026-04-04)

- [x] Lockfile parsing (package-lock.json, requirements.txt, Cargo.lock, go.sum)
- [x] Install subcommand wrapping all four package managers
- [x] GitHub Actions CI/CD (automated testing + cross-platform releases)
- [x] Install script for easy binary distribution
- [x] Documentation and installation guide

---

## Backlog

Unscheduled work lives in [`tasks/backlog/`](../tasks/backlog/). Items get promoted to a milestone when prioritized.

### Future ideas

- Homebrew / AUR / other package manager distribution
- Lock file auto-detection from project root
- `dep-scan watch` — continuous monitoring mode
- Semgrep integration for deep install script analysis
- NVD / CISA KEV / EPSS enrichment for vulnerability severity scoring
- Bloom filter database for offline package existence checks

# Roadmap

**Project:** dep-scan
**Last updated:** 2026-04-02

## Milestones

### v0.1 — Foundation

- [ ] Project setup and tooling (language decision, build system, CI)
- [ ] Core CLI skeleton with subcommands (check, install, config)
- [ ] Registry API clients (npm, PyPI) for package metadata
- [ ] Minimum package age check (configurable, default 48h)
- [ ] Local hash cache (SQLite or embedded KV)

### v0.2 — Core detection

- [ ] Install script analysis (postinstall, setup.py, build.rs, init())
- [ ] Typosquatting detection (edit distance against popular packages)
- [ ] Maintainer/ownership change detection
- [ ] Known vulnerability check (OSV database)
- [ ] Package manager wrapping (npm, pip)

### v0.3 — Expanded ecosystem

- [ ] cargo and go module support
- [ ] Popularity/download threshold warnings
- [ ] Configurable policy file (.dep-scan.toml or similar)
- [ ] Obfuscation detection (base64, hex-encoded URLs, env var exfiltration patterns)

### v1.0 — Production ready

- [ ] All four package managers wrapped and tested
- [ ] Documentation and installation guide
- [ ] GitHub releases with pre-built binaries
- [ ] Homebrew / AUR / other package manager distribution

---

## Backlog

Unscheduled work lives in [`tasks/backlog/`](../tasks/backlog/). Items get promoted to a milestone when prioritized.

---

## Completed milestones

> Move sections here as milestones are reached, with a completion date.

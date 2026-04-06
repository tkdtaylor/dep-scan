# Architecture Overview

**Project:** dep-scan
**Last updated:** 2026-04-06

## What this is

A cross-platform CLI tool that wraps package managers (npm, pip, cargo, go) to intercept and scan every dependency before installation. Detects supply chain attacks through multiple heuristics: install script analysis, typosquatting detection, minimum package age enforcement, maintainer change detection, and known vulnerability checks. Local-first with a hash cache for already-scanned dependencies.

## High-level design

dep-scan is organized into four layers:

1. **CLI layer** (`cli.rs`, `main.rs`) — parses commands (`check`, `install`, `config`), loads config, dispatches to the appropriate handler
2. **Registry layer** (`registry/`) — async clients for npm, PyPI, crates.io, and Go module proxy. Each implements a shared `Registry` trait that returns `PackageMetadata`
3. **Policy layer** (`policy/`) — a pipeline of checks run against each package's metadata. Each policy (age, install scripts, typosquatting, vulnerability, maintainer change, dependency confusion, obfuscation, popularity) returns a pass/warn/block verdict
4. **Cache layer** (`cache.rs`) — SQLite-backed hash cache. Already-scanned packages skip the registry and policy pipeline entirely

Supporting modules: `config.rs` (layered config: defaults < file < env < CLI flags), `lockfile.rs` (parses package-lock.json, requirements.txt, Cargo.lock, go.sum), `osv.rs` (OSV.dev vulnerability API client), `typosquat.rs` (edit-distance and popular package lists), `types.rs` (shared data types).

## Key decisions

| Decision | Choice | ADR |
|----------|--------|-----|
| Implementation language | Rust | [001](decisions/001-language-choice.md) |
| v0.2 detection strategy | OSV.dev + bloom filters + built-in patterns | [002](decisions/002-detection-strategy.md) |

## Data flow

```
User runs: npmds install express
  → npmds wrapper extracts package names
  → dep-scan check express --registry npm
    → Load config (.dep-scan.toml + env + CLI flags)
    → Check SQLite cache for (npm, express, latest)
      → Cache hit + not expired → return cached verdict
      → Cache miss → query npm registry API for metadata
    → Run policy pipeline against PackageMetadata:
        age → install_scripts → typosquatting → vulnerability (OSV) →
        maintainer_change → dependency_confusion → obfuscation → popularity
    → Cache result
    → Format output (table or JSON)
    → Exit 0 (pass) or 1 (warn/block)
  → If exit 0: npmds runs `npm install express`
  → If exit 1: npmds blocks the install
```

## External dependencies

| Dependency | Purpose | Notes |
|------------|---------|-------|
| OSV.dev API | Known vulnerability lookups | https://api.osv.dev — free, no API key |
| npm registry | Package metadata, publish dates, maintainer info | registry.npmjs.org (configurable) |
| PyPI JSON API | Package metadata, publish dates, maintainer info | pypi.org (configurable) |
| crates.io API | Package metadata, publish dates, maintainer info | crates.io (configurable) |
| Go module proxy | Package metadata and version info | proxy.golang.org (configurable) |

All registry URLs are configurable via `.dep-scan.toml` for testing and enterprise registries.

## Constraints and non-goals

- Not a SaaS product — must work fully offline after initial scan
- Not a replacement for `npm audit` / `pip-audit` — focuses on pre-install prevention, not post-install reporting
- Does not modify packages — only scans and blocks
- No runtime dependencies — single static binary
- No telemetry or network calls except when the user explicitly invokes a scan

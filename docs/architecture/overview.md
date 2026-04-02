# Architecture Overview

**Project:** dep-scan
**Last updated:** 2026-04-02

## What this is

A cross-platform CLI tool that wraps package managers (npm, pip, cargo, go) to intercept and scan every dependency before installation. Detects supply chain attacks through multiple heuristics: install script analysis, typosquatting detection, minimum package age enforcement, maintainer change detection, and known vulnerability checks. Local-first with a hash cache for already-scanned dependencies.

## High-level design

> Describe the main components and how they interact. Add a diagram to `artifacts/diagrams/` if helpful.

## Key decisions

> Summarize the most important design choices here. Full rationale lives in `decisions/NNN-*.md` (ADRs).

| Decision | Choice | ADR |
|----------|--------|-----|
| | | |

## Data flow

> Describe how data enters the system, moves through it, and exits. One paragraph or a simple diagram is enough.

## External dependencies

> Third-party services, APIs, databases, or infrastructure this project relies on.

| Dependency | Purpose | Notes |
|------------|---------|-------|
| OSV database | Known vulnerability lookups | https://osv.dev |
| npm registry API | Package metadata, publish dates, maintainer info | |
| PyPI JSON API | Package metadata, publish dates, maintainer info | |
| crates.io API | Package metadata, publish dates, maintainer info | |
| Go module proxy | Package metadata and version info | proxy.golang.org |

## Constraints and non-goals

> What this project deliberately does NOT do. Helps avoid scope creep.

- Not a SaaS product — must work fully offline after initial scan
- Not a replacement for `npm audit` / `pip-audit` — focuses on pre-install prevention, not post-install reporting
- Does not modify packages — only scans and blocks

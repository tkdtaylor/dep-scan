# dep-scan

A cross-platform CLI tool that wraps package managers to intercept and scan every dependency before installation. Detects supply chain attacks — typosquatting, malicious install scripts, suspicious maintainer changes — and enforces configurable policies like minimum package age. Local-first, fast, open source.

## Structure

| Directory | Purpose |
|-----------|---------|
| `src/` | Source code — written by Claude, committed to repo |
| `artifacts/` | Non-code outputs (diagrams, schemas, exports) |
| `docs/` | All documentation — inputs that guide implementation |

## Navigation

- [Architecture overview](architecture/overview.md) — system design and decisions
- [Tech stack](architecture/tech-stack.md) — languages, frameworks, infrastructure
- [Roadmap](plans/roadmap.md) — milestones and planned work
- [Active tasks](tasks/active/) — what's being worked on now
- [Test specs](tasks/test-specs/) — TDD specs and coverage tracker

## Workflow

1. Pick a task from [`tasks/active/`](tasks/active/) or [`tasks/backlog/`](tasks/backlog/)
2. Verify its paired test spec exists in [`tasks/test-specs/`](tasks/test-specs/)
3. Paste the task file + test spec + relevant architecture sections into a new Claude session
4. Implement until all test cases pass
5. Move the task to [`tasks/completed/`](tasks/completed/) and update the coverage tracker

Tasks follow Unix philosophy — one task does one thing. When in doubt, break it smaller.

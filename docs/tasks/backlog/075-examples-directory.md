# Task 075 — Add `examples/` directory

**Status:** backlog
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier C #10)
**Touches:** `examples/` (new), `README.md` (link)

## Objective

Add an `examples/` directory with copy-paste-ready material that lowers the
barrier to first use: sample configs, a sample CI workflow snippet, and a
sample JSON output for downstream parsing.

## Background

The README already does a good job of *describing* what dep-scan can do.
What it doesn't do is hand the user a working `.dep-scan.toml` for a
specific scenario, or a complete `.github/workflows/dep-scan.yml` they can
drop into their own repo.

A targeted set of examples answers three common "how do I…" questions:

1. **"How do I make this strict enough for production CI?"** → a
   locked-down `.dep-scan.toml` with all `require_*` set to true.
2. **"How do I make this permissive enough for local dev?"** → a config
   with `require_*` all false and the popularity threshold lowered.
3. **"How do I wire this into my GitHub Actions CI?"** → a complete
   workflow snippet.
4. **"What does the JSON output look like, so I can build tooling on it?"**
   → a real captured output from a `dep-scan check` run.

## Behavior

1. Create `examples/` containing:
   - `examples/dep-scan.locked-down.toml` — every `check_*` on, every
     `require_*` on, `min_package_age_hours = 168` (7 days), `min_downloads
     = 10000`, internal_prefixes for a corporate scenario.
   - `examples/dep-scan.permissive.toml` — every `check_*` on (we still
     want signals), every `require_*` off, default age, lower downloads
     threshold.
   - `examples/github-actions.yml` — a complete `.github/workflows/`
     snippet that installs dep-scan and runs `dep-scan check --lockfile`
     on PRs.
   - `examples/json-output.json` — a captured `dep-scan check --json` run
     against a deliberately suspicious package (e.g. `expresss`) showing
     the full schema with `warn`, `pass`, policy-level reasons. Generated,
     not hand-written.
   - `examples/README.md` — one-paragraph orientation pointing at each file.
2. README.md gains an "Examples" subsection (or extends "Setting up with a
   new project") linking to `examples/`.

## Acceptance criteria

- [ ] `examples/dep-scan.locked-down.toml` exists and parses with
      `dep-scan config show --config examples/dep-scan.locked-down.toml`
- [ ] `examples/dep-scan.permissive.toml` exists and parses
- [ ] `examples/github-actions.yml` exists, is valid YAML, and includes a
      working install + check sequence
- [ ] `examples/json-output.json` exists, validates as JSON, matches the
      schema documented in [interfaces.md § JSON output schema](../../spec/interfaces.md#json-output-schema)
- [ ] `examples/README.md` exists with file-by-file orientation
- [ ] README.md links to `examples/`
- [ ] No example references a registry URL not in `default_*_url()` (F-010)

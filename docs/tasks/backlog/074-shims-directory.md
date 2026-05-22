# Task 074 — Ship `shims/` directory with installable wrapper scripts

**Status:** backlog
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier C #9)
**Touches:** `shims/` (new), `README.md` (install snippet), `install.sh`
(optional one-line shims install)

## Objective

Make the wrapper-shim onboarding flow ("type `npmds`, scan-then-install") a
one-line copy instead of a "copy this snippet from the README into your
shell config" multi-step ritual.

## Background

README.md "Wrapping package managers" section shows ~30 lines of shell
function snippets for npm/pip/cargo/go that users are expected to paste
into their shell config. The functions all do the same thing:

1. Separate `--flag` tokens from package-name tokens in `$@`.
2. Run `dep-scan check <pkgs> --registry <r>`.
3. If exit 0, exec the wrapped command unchanged.
4. If non-zero, abort.

Shipping these as executable files in `shims/` lets:

- A user `cp shims/* ~/.local/bin/` and have working wrappers.
- The README install snippet collapse to one line.
- Future shim updates land via a git pull instead of a re-paste.

The shims are tiny (~20 lines each) and pure shell, so they're
cross-distro and have zero runtime deps.

## Behavior

1. Create `shims/` at repo root containing:
   - `shims/npmds`
   - `shims/pipds`
   - `shims/cargods`
   - `shims/gods`
2. Each shim is a POSIX `sh` script (not bash-specific, so they run under
   `dash` too) with `#!/bin/sh` shebang and mode `0755`.
3. Each shim: parses argv, calls `dep-scan check`, execs the underlying tool
   on pass.
4. Add a `shims/README.md` documenting install, customization, and the
   F-001-related expectation that `-`-prefixed tokens get rejected.
5. README.md "Wrapping package managers" section gets a "Quick install"
   subsection at the top pointing at `shims/` with the one-line install.
   The existing manual snippet stays (collapsed in a `<details>` block)
   for users who prefer to inline.
6. Optionally extend `install.sh` with an `--install-shims` flag that copies
   `shims/*` to a chosen path. Out of scope to require it.

## Acceptance criteria

- [ ] `shims/npmds`, `shims/pipds`, `shims/cargods`, `shims/gods` exist
- [ ] Each file is mode `0755` and starts with `#!/bin/sh`
- [ ] Each shim parses flags vs pkgs, calls `dep-scan check`, execs the
      wrapped tool on pass
- [ ] `shims/README.md` documents installation
- [ ] README.md "Quick install" subsection added
- [ ] All four shims work end-to-end: in a sandbox, `npmds install lodash`
      produces a dep-scan check first, then `npm install lodash` on pass

## Out of scope

- PowerShell / cmd.exe shims for Windows — that's a future task.
- A `fish` / `zsh` completion script — separate task if needed.
- Shipping the shims via a separate release artifact — they live in-tree.

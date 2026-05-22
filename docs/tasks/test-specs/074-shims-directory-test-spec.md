# Test Spec — Task 074: Ship shims/ directory

## Context

Wrapper-shim install today requires copying ~30 lines from the README into
shell config. This task ships them as files in `shims/`.

---

## Validation

### T-074-01: Four shim files exist
- `shims/npmds`, `shims/pipds`, `shims/cargods`, `shims/gods` are all
  present.

### T-074-02: Files are executable
- `test -x shims/npmds && test -x shims/pipds && test -x shims/cargods &&
  test -x shims/gods` succeeds.

### T-074-03: POSIX shebang
- First line of each file is `#!/bin/sh` (not `#!/bin/bash`).

### T-074-04: Each shim separates flags from packages
- A `for arg in "$@"; do case … esac done` or equivalent that puts
  `-*`-prefixed tokens in one set and bare names in another.

### T-074-05: Each shim calls `dep-scan check`
- The string `dep-scan check` appears in each file.

### T-074-06: Each shim passes the correct `--registry` value
- `shims/npmds` includes `--registry npm`
- `shims/pipds` includes `--registry pypi`
- `shims/cargods` includes `--registry crates`
- `shims/gods` includes `--registry go`

### T-074-07: Each shim execs the wrapped tool on pass
- After the dep-scan check succeeds, the shim runs `exec npm "$@"` (resp.
  pip / cargo / go) — so the wrapper is transparent to the user's argv.

### T-074-08: Each shim aborts on non-zero check
- The shim exits with the same non-zero code dep-scan returned, without
  running the wrapped tool.

### T-074-09: `shims/README.md` exists with install instructions
- Documents `cp shims/* ~/.local/bin/` (or equivalent), customization
  hints, and the F-001 dash-prefix expectation.

### T-074-10: README.md links to shims/
- The "Wrapping package managers" section in README.md gains a "Quick
  install" subsection that points at `shims/`.

### T-074-11: End-to-end sanity (manual)
- In a clean shell with `dep-scan` and `npm` on PATH, running
  `./shims/npmds install lodash` produces dep-scan output first, then npm
  output on pass. (Validation step; not a Rust test.)

### T-074-12: ShellCheck clean (if available)
- `shellcheck shims/npmds shims/pipds shims/cargods shims/gods` exits 0.
  If shellcheck is not installed, skip; document the expected clean run in
  the task file.

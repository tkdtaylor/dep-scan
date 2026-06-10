# Test Spec — Task 098: Policy pipeline on fetched git trees

## Context

ADR 008 piece 2 (VCS client) — the final wiring step: run the existing policy
pipeline (install-script scanner, obfuscation detector, etc.) against the
contents of a fetched git tree. This is what makes the VCS client meaningful:
policies that previously only saw registry metadata now have actual source files
to inspect.

This task depends on 096 (VCS fetch client returns a `FetchedTree`), 097 (cache
integration — pinned SHA hits bypass the policy run), and the existing policy
modules (`src/policy/install_script.rs`, `src/policy/obfuscation.rs`).

The key change: build a `ScanContext` from the fetched tree's files (not from
registry metadata), feed it through the policy pipeline, and surface the results
in scan output.

---

## ScanContext construction from fetched tree

### T-098-01: `ScanContext` can be constructed from a `FetchedTree`
- Call `ScanContext::from_fetched_tree(&tree)`.
- The resulting context has `install_scripts` populated from any files named
  `install.js`, `binding.gyp`, `preinstall`, `postinstall`, or other install-hook
  names that `InstallScriptPolicy` inspects.

### T-098-02: Files in the tree are treated as untrusted content
- The `ScanContext` builder must not execute any file in the tree (no `.sh`
  spawning, no `eval`-equivalent).
- Confirmed: constructing `ScanContext::from_fetched_tree` on a tree containing
  a shell script with `rm -rf /` does not cause any filesystem modification.

### T-098-03: Empty tree produces a `ScanContext` with no install scripts
- A `FetchedTree` with zero files → `ctx.install_scripts.is_empty() == true`.

---

## Install-script policy against fetched tree

### T-098-04: `InstallScriptPolicy` fires on a malicious install script in fetched tree
- Tree contains a file `scripts/preinstall.js` with content that matches the
  install-script heuristics (e.g. `exec(Buffer.from("…","base64").toString())`).
- `InstallScriptPolicy::check(&ctx)` returns `PolicyVerdict::Block` (or `Warn`
  per config).
- The verdict message references the file name or path in the tree.

### T-098-05: `InstallScriptPolicy` passes on a clean tree
- Tree contains only a `README.md` and a `src/lib.rs` with innocuous content.
- `InstallScriptPolicy::check(&ctx)` returns `PolicyVerdict::Pass`.

---

## Obfuscation policy against fetched tree

### T-098-06: `ObfuscationPolicy` fires on obfuscated JS in fetched tree
- Tree contains a `.js` file with high-entropy base64-like content consistent
  with the obfuscation heuristic.
- `ObfuscationPolicy::check(&ctx)` returns `PolicyVerdict::Warn` or `Block`.

### T-098-07: `ObfuscationPolicy` passes on clean source files
- Tree contains normal Rust or Python source files with no obfuscation markers.
- `ObfuscationPolicy::check(&ctx)` returns `PolicyVerdict::Pass`.

---

## Full pipeline verdict aggregation

### T-098-08: Multiple policies run against the fetched tree; worst verdict wins
- Tree triggers both `InstallScriptPolicy` (Block) and `ObfuscationPolicy`
  (Warn).
- The aggregated `CheckResult.verdict` is `Block` (most severe wins, consistent
  with the existing policy pipeline behavior).

### T-098-09: All policies that can operate on source trees do so
- When a fetched tree is present, ALL enabled policies that accept a source-tree
  `ScanContext` are invoked (not just install-script and obfuscation).
- Confirmed by checking the policy list constructed in `src/main.rs` is identical
  whether the dep is registry or git.

---

## Cache integration — pinned SHA hit bypasses policy run

### T-098-10: On a cache hit for a pinned SHA, the policy pipeline is NOT re-run
- Prime cache with a `Pass` verdict for pinned SHA dep.
- Second scan uses the cache hit; `InstallScriptPolicy::check` is NOT called.
- (Consistent with the registry cache-hit path from earlier tasks.)

### T-098-11: On a cache miss or mutable ref, the full policy pipeline runs
- Mutable ref dep: cache is not consulted; policies run every time.
- Pinned SHA dep on first scan (cold cache): policies run.

---

## Verdict surfacing in output

### T-098-12: Policy verdicts from fetched tree appear in `--format json`
- Scan a git dep whose tree triggers a policy violation.
- JSON output element has the policy name in its `policy` field (or equivalent)
  and the verdict message references a file from the tree.

### T-098-13: `--format native` shows the git dep row with the correct severity icon
- Native table output shows the git dep with a Block or Warn indicator matching
  the policy verdict.

---

## Age, typosquatting, and other registry-only policies

### T-098-14: Age policy is skipped for git deps (no publish timestamp available)
- A git dep has no `publish_date` in its `ScanContext`.
- `AgePolicy::check(&ctx)` returns `Pass` (or is skipped) for git deps.
- No spurious "package too young" verdict for a git dep.

### T-098-15: Typosquatting policy is skipped for git deps
- `TyposquattingPolicy` requires a registry name for comparison; git deps have
  no registry name to compare against.
- Policy returns `Pass` for git deps.

---

## Tooling gate

### T-098-16: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

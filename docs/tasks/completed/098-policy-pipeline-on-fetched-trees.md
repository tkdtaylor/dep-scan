# Task 098 — Policy pipeline on fetched git trees

**Status:** backlog
**Depends on:** 096 (VCS fetch client), 097 (cache integration), 093 (git dep
               routing in scan loop)
**ADR:** 008 (piece 2 — VCS client; wiring existing policies onto fetched trees)
**Touches:** `src/main.rs` (scan arm for git deps — replace warn-only stub with
            full policy run), `src/policy/` (confirm policies accept source-tree
            `ScanContext`; add source-tree path to `ScanContext` if not present)

## Objective

Wire the existing policy pipeline (install-script scanner, obfuscation detector,
and others) against the `FetchedTree` returned by the VCS fetch client. This is
the task that converts the "dep-scan fetches the tree" capability into actual
policy signal. A git dep that was previously warned-about-but-not-scanned now
receives the same policy scrutiny as a registry dep.

## Background

The `InstallScriptPolicy` and `ObfuscationPolicy` currently receive a
`ScanContext` built from registry metadata. When the source being scanned is a
fetched git tree, the context must instead be built from the tree's actual files.
The policies themselves should not need to change their `check` interface — the
change is in how `ScanContext` is populated.

Registry-only policies (age, typosquatting, dependency confusion, provenance
attestations) cannot run against a git dep and must return `Pass` for them rather
than producing spurious verdicts.

## Requirements

### REQ-098-01: `ScanContext::from_fetched_tree(tree: &FetchedTree) -> ScanContext`
Add a constructor that populates `install_scripts` from install-hook file names
in the tree and `source_files` from all other files. Must not execute any file.

### REQ-098-02: Git dep scan arm runs the full policy pipeline
Replace the warn-only stub from task 093 with:
1. Fetch (or cache hit) → `FetchedTree`
2. `ScanContext::from_fetched_tree`
3. Run all applicable policies
4. Aggregate verdicts
5. Store in cache (if pinned SHA)

### REQ-098-03: Registry-only policies skip git deps gracefully
`AgePolicy`, `TyposquattingPolicy`, `DependencyConfusionPolicy`, provenance
policies — all return `Pass` for git deps (no `ScanContext` fields they require
are present). No panics; no spurious blocks.

### REQ-098-04: Cache hit on pinned SHA skips policy run
When task 097's cache lookup returns a hit for a pinned SHA, the policy pipeline
is not invoked. The stored verdict is used directly, consistent with the registry
cache-hit path.

### REQ-098-05: Policy verdicts reference tree-relative file paths in messages
When a policy fires on a file in the fetched tree, the verdict message should
include the file's path relative to the fetch root (e.g. `scripts/preinstall.js`)
so the user knows what was flagged.

## Acceptance criteria

- [ ] `ScanContext::from_fetched_tree` populates install scripts from the tree
- [ ] `InstallScriptPolicy` fires on a malicious preinstall script in a git tree
- [ ] `ObfuscationPolicy` fires on obfuscated JS in a git tree
- [ ] Registry-only policies return `Pass` for git deps (no false positives)
- [ ] Multiple policies: worst verdict wins (aggregate consistent with registry path)
- [ ] Pinned SHA cache hit → policy pipeline not re-run
- [ ] Verdict messages include tree-relative file paths where applicable
- [ ] Both `--format json` and `--format native` show correct verdicts
- [ ] All T-098-01 through T-098-16 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/098-policy-pipeline-on-fetched-trees-test-spec.md`

## Out of scope

- Transitive resolution (task 099)
- Adding new policies specific to git sources (future work)
- Running OSV vulnerability lookup against a fetched tree's manifest (future)

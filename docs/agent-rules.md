# Agent rules — rationalizations to refuse and project retros

The retro-injection hook (`.claude/scripts/inject-retros.py`) parses
this file at session start and surfaces entries that match the active
task's spec. The "Common rationalizations" table is loaded as a
fallback when no per-retro keyword match scores high enough.

Add new entries here, not to CLAUDE.md, when work is lost or significant
time is wasted to a preventable mistake. CLAUDE.md is the orientation
document; this file is the growing log of project-specific lessons.

## Common rationalizations

These are excuses agents use to skip steps. Don't fall for them.

| Excuse | Reality |
|--------|---------|
| "I'll commit after the next task too" | No. Commit now. Batched commits are impossible to untangle later. |
| "This task is too small for a test spec" | The spec defines done — without it you're guessing. Write one. |
| "I'll add tests later" | Later never comes. The test spec comes first, always. |
| "These two tasks are related, I'll do them together" | One task, one commit. If it feels too granular, the tasks are scoped correctly. |
| "The architecture doc doesn't need updating" | If you made a non-obvious design decision, write an ADR. |
| "I'll just quickly fix this other thing I noticed" | Stay on your task. Note it for later — don't scope-creep. |
| "I'll update the spec at the end of the day" | No. Spec drift is silent. Update it in the same commit, every time. |
| "The spec already covers this — close enough" | If "close enough" required reading the code to confirm, the spec is wrong. Fix it now. |
| "I'll add a 'previously this was X' note to the spec" | Don't. Rewrite the entry. The ADR carries history; the spec is a snapshot. |

## Failure modes (starter set)

These anti-patterns have been observed across multiple projects. When any apply, **stop and report** — do not rationalize and ship. Add project-specific entries below as your own retros accumulate; each new entry should name the concrete incident in a "Retro source:" line so future-you can reconstruct what happened.

### No self-justification of new warnings

If your change adds a new linter or typecheck warning compared to the baseline (the pre-change warning count), you must either fix the root cause or stop and report it as a blocker. "Acceptable false positive," "I'll clean it up later," and "the warning is wrong" are not labels you get to apply unilaterally — they are the agent rationalizing around a rule. If a warning is genuinely wrong, the fix is an explicit suppression (e.g. `#[allow(lint_name)]`, `# noqa`, `// eslint-disable-next-line`) with a comment explaining why, not silence.

### No smoke tests where the spec asks for assertions

If a test spec describes a specific assertion ("should return `Some(2)` when the range is unqualified"), the test you write must actually verify that assertion. A test that calls the method and checks it doesn't panic is a smoke test, not a real test. If constructing the state needed to verify the assertion is non-trivial, that is a blocker — stop and report. Do not downgrade the test to a smoke test and tell yourself it's "close enough."

### Git status must be clean after the commit

Run `git status` as your last action before declaring a task complete. It must report `nothing to commit, working tree clean`. If it shows staged, unstaged, or untracked files, you missed something — go back and fix it. The common failure is copying a task file from `backlog/` to `completed/` with `cp` instead of `git mv`, which leaves the original undeleted and the new copy unstaged.

### No dead-code delegates

A delegate method that only exists to preserve a pre-refactor API surface and has no non-test callers is a backwards-compat shim. The rule against backwards-compat shims is already in the "Never" boundaries — this is the refactor-specific version. The correct fix is to update the call sites to use the new path, not to preserve the old path with a thin wrapper.

### Parallel agent dispatches must enforce worktree isolation in two layers

When dispatching ≥2 code-modifying agents in one message, setting `isolation: "worktree"` on the Agent tool is **necessary but not sufficient**. The Claude Code harness can fail to provision a worktree — when that happens the agent reads the parent repo's `pwd`, edits files there, and commits to whatever branch the parent is on (frequently `main`), racing every other concurrent agent and any concurrent Claude session.

**Layer 1 — prompt-level fail-fast.** Every dispatch prompt must include an abort check at the top:

```
BEFORE doing any work, run `pwd`. If the path does NOT contain
'.claude/worktrees/agent-' (i.e. the harness failed to provision
a worktree for this run), STOP IMMEDIATELY. Do not edit any files,
do not run any build/test commands, do not commit. Report back:
"ABORT: no worktree provisioned, parent repo at <pwd>". The parent
session will retry the dispatch.
```

**Layer 2 — post-dispatch verification.** After every parallel dispatch completes, run `scripts/verify-worktree-isolation.sh <agent-id> [<agent-id> ...]` and check that each agent has a `worktree-agent-<id>` branch (and that no recent commit on `main` carries the agent's task signature). For any agent that bypassed isolation, `git revert` its commit and re-dispatch with the Layer-1 preamble in place.

**Why both layers:** Layer 1 stops the agent from polluting main if it can detect the missing worktree. But the agent's introspection isn't always trustworthy — Layer 2 is the parent-side audit that catches what slips through. A single layer is not enough: in a real incident, an agent that thought it was inside its worktree ran `git checkout --` to "restore main repo to clean state," which would have wiped foreign uncommitted work from a concurrent session if any had been present.

### No `git checkout -- <path>` over uncommitted work

When you want to compare current behavior to a prior commit (linter baseline, test count, file size, anything), use `git stash` first or `git worktree add` for the comparison. **Never** reach for `git checkout HEAD -- <path>` or `git checkout <ref> -- <path>` while you have uncommitted changes you intend to keep. The checkout silently overwrites those changes with the prior commit's content, the only recovery path is the reflog (which does not capture uncommitted blobs), and `git fsck --unreachable` can return ambiguous results that look like recoverable work but aren't.

This rule applies to **all** path-checkouts, not just `src/`. `git checkout HEAD -- .` is the same hazard at full-tree scale.

The right tools for "compare to prior state":
- `git stash` + work + `git stash pop` — safe but easy to forget the pop
- `git worktree add ../baseline <ref>` — strongest, forces the comparison into a different directory
- `git diff <ref> -- <path>` / `git show <ref>:<path>` — for read-only comparisons, no checkout needed at all

## dep-scan-specific retros

### Never push between tasks in a batched-task session

Retro source: v1.1.0 / v1.2.0 cuts. Pushing a tiny commit at the end of each task burns through GitHub Actions minutes and produces a flood of CI failures because incremental commits don't always individually pass CI (e.g., a spec commit lands before its paired implementation commit). The rule:

- Commit per milestone (ADR written, spec written, task completed) — *don't* push.
- Push only at one of: explicit user request, full batch finished + local CI clean, release-tag time.
- Local CI clean means all four of: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, `cargo audit`.

This is also captured in the persistent memory at `~/.claude/projects/-home-kevin-Code-Public-dep-scan/memory/feedback_no_push_between_batched_tasks.md`.

### Release decisions require explicit user authorization

Retro source: v1.2.0 was tagged and pushed without authorization, then had to be rolled back. The rule:

- "Cargo.toml version bump" + "CHANGELOG cut" + "git tag" + "push to origin" are four separate decisions, all of which require explicit user authorization.
- Local CI passing is **necessary but not sufficient** to trigger any of them.
- Authorization is per-release, not standing — a prior "yes, ship v1.1.1" is **not** authorization to ship v1.2.0.
- When in doubt, stop and ask: "Want me to tag X.Y.Z and push?"

### Don't infer "the user said keep going, so cut a release"

Retro source: same incident as above. Phrases like "keep going," "work through them all," "fix them all" authorize **continuing the in-flight task batch**, not promoting that batch to a release. Distinguishing question to ask if uncertain: *"Is the version in Cargo.toml ≥ the latest tag?"* If yes, the user has already cut a release that hasn't shipped; if no, you might be the one about to cut one — don't.

### MEDIUM and LOW security findings get tasks, not inline fixes

Retro source: v1.2.0 audit triage. The temptation when a security audit produces 15 findings is to fix them all in one PR. Don't. Each finding becomes a numbered task with a paired test spec, just like any other work. The reasons:

- A bisect-able commit per fix means a future regression's root cause is visible in `git blame`.
- The test spec is the contract for "what this fix means" — future drift audits need it.
- Mixing 15 fixes in one PR makes review effectively impossible.

The right pattern: triage the findings into HIGH / MEDIUM / LOW; create tasks `NNN-…` for each; execute them in order; commit each individually. This is what produced tasks 037-063.

### `cargo test` aggregate counts are the source of truth, not the CHANGELOG

Retro source: post-v1.2.0-cut drift audit found CHANGELOG cited 715 tests, actual was 788. The CHANGELOG was written at the moment the v1.2.0 prep branch was first cut, then the 5 LOW-finding-fixes (tasks 059-063) added 73 more tests without anyone updating the CHANGELOG number. The rule:

- Before tagging a release, run `cargo test 2>&1 | grep -E "test result:" | awk '{print $4}' | paste -sd+ | bc` and sync that number into the CHANGELOG.
- Any documented test-count in any markdown file is a candidate for drift.

### Document deferred dependency bumps with concrete re-attempt paths

Retro source: task 056 (`reqwest 0.12 → 0.13`) was attempted, reverted, and the *reason* nearly got lost — the aws-lc-rs / cmake / cross-compile dependency chain is non-obvious. The rule: a deferred task file MUST document (a) what blocked the attempt, (b) one or more concrete paths to retry, and (c) the conditions under which a retry would succeed. See `docs/tasks/backlog/056-bump-reqwest-0-13.md` as the template.

# Backlog playbook

Shared procedure for the `/backlog-*` slash commands. Each command sets two parameters and then follows this file:

- **mode** — `sequential` (one task-executor at a time) or `parallel` (independent tasks concurrently, in worktrees)
- **posture** — `supervised` (surface blockers for the user before starting) or `autonomous` (research/reason, decide, proceed)

**Optional argument (all commands): `--local`** (alias `--no-push`) — commit and merge each task **locally**, do not push after each task. Default: follow the project's `CLAUDE.md` commit/push rules.

*Why this exists:* many projects run GitHub Actions on push. Pushing after every task in a multi-task run re-triggers the whole CI suite once per task, burning Actions minutes for no added signal. `--local` keeps the work entirely local during the run. At the **end** of the run, offer a single `git push` of the accumulated commits so CI runs **once** over the batch — unless the user asked for no push at all. Never auto-push mid-run under `--local`.

The three phases below run for every variant. Only Phase 2 branches on posture and Phase 3 branches on mode.

---

## Phase 1 — Triage (always, every mode + posture)

1. **Review** — read every `docs/tasks/backlog/*.md` (and anything left in `docs/tasks/active/`). Read `docs/tasks/test-specs/coverage-tracker.md`. Skim `docs/spec/SPEC.md` so you know the current system state.
2. **Prioritize** — order the backlog by explicit priority first, then dependency, then `NNN`.
3. **Dependency graph** — for each task, determine what it depends on (read the task body for stated prerequisites, referenced modules, and spec links). Produce a *leveled* plan: level 0 = tasks with no unmet dependency, level 1 = tasks unblocked once level 0 merges, etc.
4. **Blocker & unknown scan** — classify each task as **READY** (concrete spec, no unmet dependency, no open product/technical decision) or **BLOCKED** (needs a decision, external input, or research before it can be executed with high confidence). If analysis reveals that a *new* task is needed before others can proceed, note it — do not silently skip the gap.
5. **Decision blocks** — for every blocker/unknown, write it in this exact shape (options in recommended order, recommendation called out first, with the reason and trade-offs):

   ```
   ### Decision: <short title>  (task NNN)
   Recommended → **Option A** — <one line why this is the pick>
       Pros: <…>   Cons: <…>
   • Option B — <…>   Pros: <…>   Cons: <…>
   • Option C — <…>   Pros: <…>   Cons: <…>
   ```

6. **Model tier per task** — pick the model each task should run on, so the executor isn't stuck on the default `fast` tier for work that needs more. Use the tier stated in the task file if present; otherwise infer from scope:
   - **fast** (e.g. `haiku`) — scoped implementation with a concrete spec and a pattern to follow.
   - **balanced** (e.g. `sonnet`) — spans multiple files, or sits behind a strict CI/commit gate where a broken commit is costly.
   - **deep** (e.g. `opus`) — cross-subsystem work: new state machines, concurrency, security/trust boundaries, or anything expensive to reverse.

   Record the chosen tier next to each task in the plan. When you dispatch the executor in Phase 3, run it with that model.

Emit a **triage summary**: the ordered/leveled plan, the dependency graph, the READY vs BLOCKED split, the model tier per task, and every decision block. This summary is shown to the user in both postures.

---

## Phase 2 — Resolve blockers (posture-dependent)

- **supervised** — **STOP after triage.** Present the triage summary and all decision blocks, then wait for the user's choices before executing anything. This is "review the work and surface problems *before* starting." Do not begin Phase 3 until the user responds.
- **autonomous** — for each decision: research (WebSearch / framework docs / the codebase) and/or reason it through, then **pick the recommended option**. Record each non-trivial choice as an ADR in `docs/architecture/decisions/` (commit with `[allow-main]` if you are on the default branch) so the decision is traceable. Then proceed to Phase 3. If a blocker genuinely cannot be resolved autonomously (needs credentials, an external party, or a product call only the user can make), mark the task **SKIPPED-blocked** and continue — surface it in the final summary.

---

## Phase 3 — Execute (mode-dependent)

**Confidence bar (both modes, non-negotiable):** never ship low-confidence work. If a `task-executor` returns an escalation (tier mismatch) or you cannot complete a task with high confidence, do **not** force it:
- supervised → stop and surface it;
- autonomous → attempt a higher-tier agent (`architect` / `code-reviewer` / `security-auditor`) or research; if still not confident, mark **SKIPPED-low-confidence** and move on.

Skipped tasks are always listed in the final summary — never buried.

### mode = sequential

For each READY task in priority + dependency order:

1. Dispatch the **task-executor** sub-agent for that one task (pass the task file path and its test-spec path), **running it on the model tier chosen for this task in triage**. It runs `scripts/start-task.sh`, isolates onto `task/NNN-<slug>`, implements under TDD, runs the pre-commit verification gate, and commits 🟡.
2. On return, run the **spec-verifier** agent.
   - **APPROVE** → close the task with **`scripts/finish-task.sh <NNN> <slug>`** (add `--local` to skip the push). It merges `task/NNN-<slug>` into the default branch, deletes the branch, removes the worktree, and **verifies all three** — exiting non-zero if anything is left behind. **If it exits non-zero, stop and resolve before continuing** (handle per posture); a non-zero finish is the signal that a merge or cleanup silently didn't happen. Then promote the `coverage-tracker.md` row per the 🟡→✅ rules.
   - **REJECT** or executor escalated → handle per posture (supervised: stop & surface; autonomous: resolve or skip). Leave the branch/worktree in place for inspection.
3. **Never start the next task before the current one is committed and closed.** Re-evaluate readiness — a merge may unblock a dependent — then continue.

### mode = parallel

1. Compute the current **READY set** (tasks with no unmet dependency).
2. Dispatch up to **N concurrently** (cap N at 3–4) — each a `task-executor` sub-agent **with `isolation: worktree`**, one task each, **each run on the model tier chosen for that task in triage**. `start-task.sh` detects it is already inside a linked worktree and isolates the task branch there without touching the main checkout.
   - **Tell each executor to skip its `coverage-tracker.md` update** (overriding its usual step 7). In parallel mode the tracker is written once per chunk by this orchestrator, not by the task branches — see step 4 for why. Each executor still moves its **own** task file `backlog/` → `completed/`; distinct file paths don't conflict, only the shared tracker does.
3. As agents return: run **spec-verifier** on each, then close **APPROVED** tasks **one at a time** with **`scripts/finish-task.sh <NNN> <slug>`** (`--local` to skip the push) — it merges, deletes the branch, removes the worktree, and verifies all three, serializing the merges to avoid races. **If any `finish-task.sh` exits non-zero, stop and resolve it** rather than dispatching the next wave. Run `scripts/verify-worktree-isolation.sh` to confirm each agent stayed in its own worktree.
4. **Update the tracker for the whole chunk, once.** After the wave's merges land on the default branch, update `coverage-tracker.md` for every task in the chunk in a single commit — status per the 🟡/✅ rules, with the **Verified by** evidence taken from each executor's report. The tracker table is the one file every branch would otherwise edit, so per-branch updates conflict on essentially every parallel merge; a single writer on the default branch removes that conflict entirely while preserving the verification-ladder status the tracker exists to carry.
5. Handle rejections/escalations per posture.
6. Recompute the READY set (merges unblock dependents) and dispatch the next wave. Repeat until the backlog is drained or only BLOCKED tasks remain.

---

## Final summary (always)

- **Completed** — task NNN, commit SHA, highest verification level reached (L1–L6).
- **Skipped / blocked** — task NNN, reason (blocked / low-confidence), and for autonomous the decision recorded (ADR path).
- **Decisions** — ADRs written (autonomous) or decision blocks still awaiting the user (supervised).
- **New tasks identified** during triage but not yet created, if any.
- **Push** — under `--local`, offer a single `git push` of all accumulated commits now (one CI run over the whole batch), unless the user asked for no push at all.

Then run a **closure sweep** to confirm nothing leaked:

```bash
git branch --list 'task/*'                 # should list ONLY incomplete (skipped/blocked) tasks
git worktree list                          # should show no leftover .claude/worktrees/* entries
```

Every `task/*` branch or `.claude/worktrees/*` entry that does **not** correspond to a deliberately skipped/blocked task is a merge or cleanup that didn't complete — report it explicitly and, if its task was actually finished, close it with `scripts/finish-task.sh <NNN> <slug>`.

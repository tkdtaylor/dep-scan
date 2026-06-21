---
description: Point at a project and build it through autonomously — plan tasks from the roadmap/goal when needed, work the whole backlog, open one PR at the end
argument-hint: ["high-level goal"] [--local] [--per-task]
---
Follow `.claude/backlog-playbook.md` with **mode=sequential, posture=autonomous, plan=on, advance=integration**.

This is `/backlog-autopilot` plus a planning front-end and a single end-of-run PR. Use it to point the agent at a whole project — a repo with only a roadmap/goal, or one with a backlog — and have it work through unattended.

1. **Phase 0 (plan, autonomous).** If the READY backlog does not already cover the next increment toward the goal, analyze the codebase + `docs/plans/roadmap.md` (weighting any goal text in `$ARGUMENTS`) and author the task files + paired test specs needed — dependency-ordered, one responsibility each, via the `task-planner` agent. Plan-and-go: do **not** stop for approval.
2. **Phases 1–3 (work through, autonomous).** Triage → resolve each blocker as an ADR → execute each task (`task-executor` → `spec-verifier` → `finish-task.sh --local` into the integration branch), holding the confidence bar; skip only the genuinely-stuck.
   - **Keep the executor moving.** When a sub-agent asks a question, presents options, hedges, or stops early, that's a model quirk, not a real blocker — *you* decide it (research/reason, pick the best option, record an ADR if non-trivial) and re-dispatch with the answer and an instruction to proceed without asking. Only credentials / external parties / irreversible product calls are real blockers. See the playbook's "Keep the executor moving" rule.
3. **Advance = integration branch.** All tasks land on one integration branch off the default branch — `main` is never touched mid-run. At the end, push it and open **one PR** (integration → default) for review; do not merge it.
4. **Re-plan loop.** After draining the READY set, re-check coverage against the goal; if executable work remains, plan the next increment and continue. Stop when the goal is met or only blocked/low-confidence work is left (bounded — stop after 2 plan rounds that add nothing executable).

Stop only for blockers that genuinely require you (credentials, external input, a product call). Emit the final summary + closure sweep, then the integration-PR link.

`--local` keeps everything local (no push of the integration branch; report it instead of opening a PR). `--per-task` overrides `advance=integration` with the classic per-task merge to the default branch. $ARGUMENTS

---
description: Triage and work through the backlog in parallel (worktree sub-agents), surfacing blockers for your decision before starting
argument-hint: [--local]
---
Follow `.claude/backlog-playbook.md` with **mode=parallel, posture=supervised**.

Run Phase 1 (triage: prioritize, dependency-order, scan for blockers/unknowns), then **stop and surface** every decision in recommended order before executing anything. Once decisions are settled, dispatch independent ready-tasks concurrently in worktrees, respecting the dependency graph, and merge approved branches one at a time. Hold the confidence bar — skip what you can't do with high confidence and summarize at the end.

Pass `--local` to commit and merge each task locally without pushing. $ARGUMENTS

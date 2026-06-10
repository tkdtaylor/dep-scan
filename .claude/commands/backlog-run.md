---
description: Triage and work through the backlog sequentially via task-executor sub-agents, surfacing blockers for your decision before starting
argument-hint: [--local]
---
Follow `.claude/backlog-playbook.md` with **mode=sequential, posture=supervised**.

Run Phase 1 (triage: prioritize, dependency-order, scan for blockers/unknowns), then **stop and surface** every decision in recommended order before executing anything. Once decisions are settled, execute one task at a time. Hold the confidence bar — skip what you can't do with high confidence and summarize at the end.

Pass `--local` to commit and merge each task locally without pushing. $ARGUMENTS

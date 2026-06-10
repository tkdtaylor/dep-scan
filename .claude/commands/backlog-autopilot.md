---
description: Triage and work through the backlog sequentially via task-executor sub-agents, resolving blockers autonomously (research/reason, decide, record ADRs)
argument-hint: [--local]
---
Follow `.claude/backlog-playbook.md` with **mode=sequential, posture=autonomous**.

Run Phase 1 (triage: prioritize, dependency-order, scan for blockers/unknowns). For each blocker, research/reason, pick the recommended option, and record the decision as an ADR — then proceed without waiting. Execute one task at a time. Hold the confidence bar — escalate to a higher-tier agent or research; if still not confident, skip and summarize at the end. Only stop for blockers that genuinely require the user (credentials, external input, a product call).

Pass `--local` to commit and merge each task locally without pushing. $ARGUMENTS

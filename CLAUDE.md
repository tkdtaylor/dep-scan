# dep-scan — Claude Code layer

The canonical, harness-neutral briefing for this repo is **[AGENTS.md](AGENTS.md)** —
project orientation, structure, commands, design principles, conventions, the task
workflow, commit rules, boundaries, and the load-bearing process rules all live
there. It is imported below so it loads in full for Claude Code, exactly as if it
were inline here.

@AGENTS.md

Everything below is **Claude Code-specific** — the mechanics only this harness
understands. Keep harness-neutral content in `AGENTS.md`, not here.

## Plan mode

When you exit plan mode, a hook automatically restructures the plan:
- Each step becomes a task file in `docs/tasks/backlog/`
- Test spec stubs are created for each task
- The plan is replaced with a lightweight skeleton to save context tokens
- The full plan is backed up to `docs/plans/`

Use the **task-executor** agent to work through tasks one at a time. Each agent call
is ephemeral — it reads the task file, does the work, commits, and reports back
without bloating the main conversation.

```
use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md
```

## Subagents

The `.claude/agents/` directory defines role prompts Claude Code can spawn as
subagents:

- **architect** — review designs, CLI structure, and data flow against the
  architecture. "use the architect agent to review this design"
- **task-planner** — break features into scoped tasks with test specs. "use the
  task-planner to break down [feature]"
- **task-executor** — execute a single task end-to-end (read spec, implement, test,
  commit). Ephemeral context. `use task-executor — task: ..., spec: ...`
- **qa** — verify implementations against test specs, find coverage gaps. Read-only
  on source. "use the qa agent on task NNN"
- **spec-verifier** — assertion-by-assertion check that the implementation matches
  the spec; last gate before commit. "use the spec-verifier on task NNN"
- **code-reviewer** — review changed files against architecture, conventions, and
  the test spec before commit. "use the code-reviewer on these changes"
- **security-auditor** — audit dep-scan's own code for injection, TOCTOU, regex DoS,
  and bypass risks. Critical since this is a security tool handling adversarial
  input. "use the security-auditor on [module]"
- **dependency-auditor** — audit `Cargo.toml`/`Cargo.lock` for outdated, CVE-flagged,
  abandoned, or unused crates. "use the dependency-auditor"
- **docs-writer** — generate or update README sections, CLI help, docstrings, and
  changelog entries from actual source. "use the docs-writer to document [feature]"

## Skills

- **code-scanner** — scan third-party dependencies and packages for malicious code
  before integrating them. Directly relevant since dep-scan is a security tool that
  should eat its own dog food. Trigger: "scan this package for vulnerabilities"
- **simplify** — review changed code for over-engineering, dead code, and reuse
  opportunities after heavy implementation sprints. Trigger: "simplify this"

## Hook profiles

Hooks run automatically and are gated by profile level. Control via environment
variables:

```bash
export CLAUDE_HOOK_PROFILE=minimal    # Safety hooks only (secret protection, block-no-verify, config-protection, protect-checkout)
export CLAUDE_HOOK_PROFILE=standard   # + workflow hooks (plan restructuring, compaction, checkpoints) — default
export CLAUDE_HOOK_PROFILE=strict     # + formatting, fitness, notifications (batch-format-typecheck, edit-tracker, check-fitness, desktop-notify)
export CLAUDE_DISABLED_HOOKS=desktop-notify,batch-format-typecheck  # Disable specific hooks
```

A post-edit lint/format hook can run `cargo clippy` and `cargo fmt --check` after
every Edit/Write (configure via `/update-config`).

## Retro injection

The `inject-retros.py` SessionStart hook reads the project retro sources —
`AGENTS.md`, `CLAUDE.md`, and `docs/agent-rules.md` — keyword-matches the active
task against retro headings, and surfaces only the relevant entries at session
start. Adding an entry to `docs/agent-rules.md` is how a one-time mistake becomes a
permanent guard for Claude Code sessions; its essentials are also inlined into
`AGENTS.md` so every harness gets them.

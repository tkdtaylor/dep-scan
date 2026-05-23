# dep-scan

A cross-platform CLI tool that wraps package managers to intercept and scan every dependency before installation. Detects supply chain attacks — typosquatting, malicious install scripts, suspicious maintainer changes — and enforces configurable policies like minimum package age. Local-first, fast, open source.

## Project structure

```
src/          ← code outputs (what you write)
artifacts/    ← non-code outputs (diagrams, schemas, exports)
docs/         ← documentation inputs (what guides your work)
  architecture/   system design, ADRs, tech stack (descriptive)
  spec/           authoritative behavioral & security contracts
  plans/          roadmap, sprints
  tasks/          active, backlog, completed task files
    test-specs/   TDD specs — always written before implementation
```

The key distinction: `docs/` is the input side (read before you act), `src/` is the output side (what gets produced).

## Tech stack

Rust (see [ADR 001](docs/architecture/decisions/001-language-choice.md)). Cross-platform CLI, single binary distribution. Local SQLite for hash cache.

## Commands

```bash
cargo test              # run all tests
cargo build --release   # build optimized binary
cargo run -- <args>     # run the CLI
cargo clippy            # lint
cargo fmt --check       # check formatting
cargo fmt               # auto-format
cargo audit             # audit dependencies for known RustSec advisories
                        # To suppress an advisory, add an [advisories.ignore] entry in
                        # .cargo/audit.toml with a justification comment — never use --ignore on the CLI

# Repo-state guards (idempotent, exit 0 on clean state)
scripts/check-task-state.sh           # fail if a task file is tracked in two of {backlog, active, completed}
scripts/verify-worktree-isolation.sh  # check parallel sub-agents aren't sharing a worktree (run before/after parallel agent dispatches that write code)

# Docker (run from host, outside the container)
# Note: this workflow is aspirational. The .env file it references is not
# maintained in-tree; create your own .env from the variables listed below
# if you want to use the dev container.
docker run --rm -it \
  -v dep-scan-workspace:/app \
  -v "$(pwd)":/host:ro \
  -v "$HOME/.claude":/home/developer/.claude \
  -v "$(pwd)/.env":/app/.env \
  --env-file .env \
  dep-scan-dev:latest

# Export workspace → host
docker run --rm -v dep-scan-workspace:/src:ro -v "$(pwd)":/dst debian:bookworm-slim cp -r /src/. /dst/

# Backup / restore workspace volume
docker run --rm -v dep-scan-workspace:/src:ro -v "$(pwd)":/dst debian:bookworm-slim tar czf /dst/workspace-backup.tar.gz -C /src .
docker run --rm -v dep-scan-workspace:/dst -v "$(pwd)":/src debian:bookworm-slim tar xzf /src/workspace-backup.tar.gz -C /dst
```

## Conventions

- Task files are named `NNN-short-name.md` (zero-padded, sequential across all task states)
- Every task has a paired test spec; no implementation starts without one
- Tasks follow Unix philosophy — one task, one responsibility; break things smaller when in doubt
- ADRs live in `docs/architecture/decisions/` — add one whenever a significant design decision is made

## Working in this project

1. Start each session by reading the relevant task file and its test spec
2. Check `docs/architecture/overview.md` for system context
3. Write the test spec before any implementation code
4. Move tasks to `completed/` and update `coverage-tracker.md` when done
5. **Commit and push immediately after each milestone** — never start the next task without committing the current one first

## Release process

Before cutting a release, follow [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
The checklist includes the explicit-authorization gate — do not tag or push
without it.

## Commit rules

**You must commit and push after every milestone.** Do not batch multiple tasks into one commit. Do not continue to the next task until the current one is committed and pushed.

| Milestone | What to stage | Message |
|-----------|--------------|---------|
| ADR written | `docs/architecture/decisions/NNN-*.md` | `docs: add ADR NNN — <decision title>` |
| Test spec written | `docs/tasks/test-specs/NNN-*-test-spec.md`, updated `coverage-tracker.md` | `test: add spec for task NNN — <name>` |
| Task completed | `src/` changes, moved task file, updated `coverage-tracker.md` | `feat: complete task NNN — <name>` |

After each milestone:
```bash
git add <relevant files>
git commit -m "<message>"
git push
```

## Plan mode

When you exit plan mode, a hook automatically restructures the plan:
- Each step becomes a task file in `docs/tasks/backlog/`
- Test spec stubs are created for each task
- The plan is replaced with a lightweight skeleton to save context tokens
- The full plan is backed up to `docs/plans/`

Use the **task-executor** agent to work through tasks one at a time. Each agent call is ephemeral — it reads the task file, does the work, commits, and reports back without bloating the main conversation.

```
use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md
```

## Boundaries

### Always
- Write the test spec before any implementation code
- Commit and push after every milestone (task completed, spec written, ADR written)
- Read the task file and test spec before starting work on a task
- Create an ADR for significant design decisions

### Ask first
- Modifying files in `docs/` — they are planning documents, not implementation
- Deleting or renaming existing source files
- Adding dependencies not already in the tech stack
- Changing the project structure beyond what a task requires

### Never
- Create files in `src/` without a corresponding task and test spec
- Combine unrelated changes in one task or commit
- Skip the test spec — even for "small" changes
- Force push or rewrite published git history
- Add a `Co-Authored-By` line to commits unless explicitly asked
- Scan or interact with the network without user consent during development — dep-scan should only make network calls when the user explicitly invokes a scan
- Hardcode registry URLs — they should be configurable for testing and future extensibility

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

## Recommended tooling

### Skills
- **code-scanner** — scan third-party dependencies and packages for malicious code before integrating them. Directly relevant since dep-scan is a security tool that should eat its own dog food. Trigger: "scan this package for vulnerabilities"
- **simplify** — review changed code for over-engineering, dead code, and reuse opportunities after heavy implementation sprints. Trigger: "simplify this" or "review these changes"

### Hooks
- Post-edit lint/format: add a PostToolUse hook to run `cargo clippy` and `cargo fmt --check` after every Edit/Write (configure via `/update-config`)

### Agents
- **architect** — review designs, CLI structure, and data flow against the architecture. Invoke: "use the architect agent to review this design"
- **task-planner** — break features into scoped tasks with test specs. Invoke: "use the task-planner to break down [feature]"
- **task-executor** — execute a single task end-to-end (read spec, implement, test, commit). Ephemeral context. Invoke: `use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md`
- **qa** — verify implementations against test specs, find coverage gaps. Read-only on source. Invoke: "use the qa agent on task NNN"
- **spec-verifier** — assertion-by-assertion check that the implementation matches the spec; last gate before commit. Complements qa. Invoke: "use the spec-verifier on task NNN"
- **code-reviewer** — review changed files against architecture, conventions, and the test spec before commit. Invoke: "use the code-reviewer on these changes"
- **security-auditor** — audit dep-scan's own code for injection, TOCTOU, regex DoS, and bypass risks. Critical since this is a security tool handling adversarial input. Invoke: "use the security-auditor on [module]"
- **dependency-auditor** — audit `Cargo.toml`/`Cargo.lock` for outdated, CVE-flagged, abandoned, or unused crates. dep-scan eating its own dog food. Invoke: "use the dependency-auditor"
- **docs-writer** — generate or update README sections, CLI help text, docstrings, and changelog entries from actual source code. Invoke: "use the docs-writer to document [module or feature]"

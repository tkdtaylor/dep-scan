# dep-scan — Agent briefing (canonical)

This is the **canonical, harness-neutral briefing** for dep-scan. It is the single
source of truth for project context, commands, conventions, the task workflow,
verification expectations, commit rules, and the load-bearing process rules every
agent must follow.

Every coding-agent harness loads this file:

- **Codex** auto-loads `AGENTS.md` (this file).
- **Antigravity / Gemini** load it via `GEMINI.md` (a symlink to this file).
- **Claude Code** loads `CLAUDE.md`, which imports this file (`@AGENTS.md`) and adds
  the Claude-specific mechanics (skills, subagents, hook profiles, plan mode,
  retro injection).

Keep this file harness-neutral. Anything that only one harness understands belongs
in that harness's layer (`CLAUDE.md` for Claude Code), not here.

## What this is

dep-scan is a cross-platform CLI tool that wraps package managers (npm, pip, cargo,
go) to intercept and scan every dependency before installation. It detects supply
chain attacks — typosquatting, malicious install scripts, suspicious maintainer
changes, dependency confusion, known vulnerabilities — and verifies cryptographic
provenance (sigstore for npm + PyPI, sumdb signature for Go) against embedded
out-of-band trust roots. It also enforces configurable policies like minimum
package age. Local-first, fast, open source. Content-addressable SQLite cache.

It is a security tool that handles adversarial input — correctness and
fail-closed behavior are not optional.

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
  agent-rules.md  process rules + project retros (the growing log of lessons)
```

The key distinction: `docs/` is the input side (read before you act), `src/` is the
output side (what gets produced).

`docs/spec/` holds the **authoritative behavioral & security contracts** — the
external behaviors and security invariants the code MUST satisfy. The code is one
realization of the spec. Spec and code that disagree means one of them is wrong;
fix it in the same change.

## Tech stack

Rust (see [ADR 001](docs/architecture/decisions/001-language-choice.md)).
Cross-platform CLI, single-binary distribution. Local SQLite for the hash cache.

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
scripts/start-task.sh <NNN> <slug>    # create task/NNN-slug branch (or worktree) and switch to it; run as Step 0 of any task
scripts/dogfood-gate.py               # pre-release gate: scan dep-scan's own dependencies with dep-scan before tagging

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

## Design principles

This project follows **Unix philosophy** — favoring **composability over monolithic
design**. Complex behavior emerges from combining small, independent components that
communicate through standardized interfaces, not by growing one large one. The
short version is four structural properties to design for:

- **Modularity** — independent units that can be built, understood, and changed on
  their own (the registry clients, the policy checks, the cache, the verification
  helpers are each separable)
- **Interface standardization** — stable, well-defined contracts between components
  (the `Registry` trait, the policy pass/warn/block verdict, the `PackageMetadata`
  shape, plain-text configs)
- **Maintainability** — changes in one module should not cascade across unrelated
  ones
- **Reusability** — components should be liftable into another project without
  entanglement

Derived working rules:

- **One thing, well** — each module, check, and function has a single clear
  responsibility
- **Small, composable pieces** over large configurable ones
- **Plain text** for configs, intermediate artifacts, and data interchange where
  possible
- **Explicit over implicit** — surface assumptions in code and types, not in comments
- **Fail fast, fail closed** on unexpected or adversarial state — for a security tool
  this is load-bearing, never silently paper over it
- **Test in isolation** — every component runnable without the whole stack
- **Defer premature decisions** — no abstractions until the second or third concrete
  use case demands them

See [docs/architecture/overview.md](docs/architecture/overview.md) for the system
layout these principles produced.

## Conventions

- Task files are named `NNN-short-name.md` (zero-padded, sequential across all task
  states)
- Every task has a paired test spec; no implementation starts without one
- Tasks follow Unix philosophy — one task, one responsibility; break things smaller
  when in doubt
- ADRs live in `docs/architecture/decisions/` — add one whenever a significant
  design decision is made
- **Spec is updated in the same commit as the code change.** A task that changes
  externally-visible behavior, the data model, an interface, a policy verdict, or
  configuration is not done until the matching `docs/spec/` file reflects the new
  state. Stale spec entries are rewritten in place — never appended to. The ADR
  carries the history; the spec carries the current truth.
- Don't hardcode registry URLs — they must be configurable for testing and future
  extensibility.

## Working in this project

Every task lives on its own branch (or worktree under concurrent sessions). Working
directly on `main` is blocked by the `no-commit-on-main` hook —
`scripts/start-task.sh` is how you pick the right isolation for the moment.

1. Start each session by reading the relevant task file and its test spec
2. Check [docs/architecture/overview.md](docs/architecture/overview.md) for system
   context
3. Write the test spec before any implementation code
4. Implement via your harness's task-execution flow. Its Step 0 runs
   `scripts/start-task.sh <NNN> <slug>` to set up either:
   - `BRANCH task/NNN-<slug>` (solo session — the common case), or
   - `WORKTREE <path>` (concurrent session detected; `cd` into it)
5. Implement, test, then run the **spec-verifier** role on the task — it returns
   APPROVE or BLOCK based on per-assertion evidence
6. Move the task file to `completed/` and update `coverage-tracker.md` when done
7. **Commit and push after each milestone** — never start the next task without
   committing the current one first

The separation between the task branch and `main` is the load-bearing rule for
multi-session safety. Two sessions on different `task/*` branches can work in
parallel without stepping on each other; two sessions both editing `main` cannot.

## Release process

Before cutting a release, follow [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md). The
checklist includes the explicit-authorization gate — do not tag or push without it.
dep-scan eats its own dog food: `scripts/dogfood-gate.py` scans dep-scan's own
dependencies with dep-scan before a tag.

## Commit rules

**You must commit and push after every milestone.** Do not batch multiple tasks into
one commit. Do not continue to the next task until the current one is committed and
pushed. All task commits land on the **task branch** (`task/NNN-<slug>`), never on
`main` directly.

| Milestone | What to stage | Message |
|-----------|--------------|---------|
| ADR written | `docs/architecture/decisions/NNN-*.md`, any superseded spec entries rewritten in `docs/spec/` | `docs: add ADR NNN — <decision title>` |
| Test spec written | `docs/tasks/test-specs/NNN-*-test-spec.md`, updated `coverage-tracker.md` | `test: add spec for task NNN — <name>` |
| Task completed | `src/` changes, moved task file, updated `coverage-tracker.md`, **and any affected `docs/spec/` files** | `feat: complete task NNN — <name>` |

After each milestone:
```bash
git add <relevant files>
git commit -m "<message>"
git push
```

Do **not** add a `Co-Authored-By` line to commits unless explicitly asked. For
genuine main-only commits (a standalone doc fix, a hotfix), include `[allow-main]`
in the message — it's self-documenting in `git log`.

## Load-bearing process rules

These are the rules that exist specifically to stop a preventable mistake. The
**full treatment, with the incident that motivated each, lives in
[docs/agent-rules.md](docs/agent-rules.md)** — read it. The essentials, so they
reach you even without that file loaded:

- **Commit after every milestone — now, not "after the next task too."** Batched
  commits are impossible to untangle. One task, one commit.
- **Test spec before implementation — always.** No "this is too small for a spec."
  The spec defines done; without it you're guessing.
- **Never work directly on the default branch.** First action of any task is
  `scripts/start-task.sh <NNN> <slug>`, which puts you on `task/NNN-<slug>` or in a
  worktree. When it prints `WORKTREE <path>`, your **next command must be `cd
  <path>`** — editing the parent repo while believing you're isolated is the silent
  failure.
- **"Done" means operationally verified, not "code merged."** A verification
  ladder: (1) code merged → (2) unit tests pass → (3) lint/format/`cargo audit`
  clean → (4) CI → (5) the live CLI path exercised → (6) the built binary observed.
  Levels 1–4 are 🟡; only 5 or 6 flips a coverage-tracker row to ✅. Never claim a
  level you did not reach. The 🟡 (code) and ✅ (verified) states are distinct
  artifacts — never mark a row ✅ in the same act as the implementation.
- **Trace producer→consumer before declaring done on cross-module state.** A test
  that sets a field by hand proves the gate works *given* the field; it does not
  prove the field is ever set on the live path. Grep the write site and the read
  site and identify the live path. For dep-scan this is acute: a policy that
  blocks *given* a metadata field still has to prove that field is populated by the
  registry client on the real scan path.
- **No smoke tests where the spec asks for assertions.** If the spec says a scan
  returns a `block` verdict, the test must assert that verdict, not merely that the
  call doesn't panic. If constructing the state is hard, that's a blocker to report
  — not a license to downgrade the test. A security tool whose tests only check
  "didn't crash" is a security tool with no test coverage.
- **No new warnings self-justified away.** A change that adds a clippy/`cargo audit`
  warning over baseline must fix the root cause or stop and report. Use an explicit
  suppression with a written reason (e.g. an `[advisories.ignore]` entry with a
  justification), never a unilateral "acceptable false positive" or a CLI
  `--ignore`.
- **Run it when the change is runtime-visible.** Logging, CLI/exit codes, scan
  output, config resolution, file outputs, side effects — `cargo test` is not
  verification of these. Run the CLI path and quote the output.
- **Never `git checkout -- <path>` over uncommitted work.** It silently overwrites
  and the reflog cannot recover it. Use `git stash`, `git worktree add <ref>`, or
  `git diff <ref> -- <path>` / `git show <ref>:<path>` instead. A `protect-checkout`
  hook blocks this; the rule stands even if the hook is off.
- **Git status must be clean before declaring a task complete.** `git status` must
  report `nothing to commit, working tree clean`. The common miss: `cp` instead of
  `git mv` when moving a task file leaves the original undeleted.

## Boundaries

### Always
- Write the test spec before any implementation code
- Commit and push after every milestone (task completed, spec written, ADR written)
- Read the task file and test spec before starting work on a task
- Create an ADR for significant design decisions
- **Update `docs/spec/` in the same commit** as any code change that alters
  externally-visible behavior, the data model, an interface, a policy verdict, or
  configuration
- Start every task on its own branch via `scripts/start-task.sh <NNN> <slug>`

### Ask first
- Modifying files in `docs/plans/`, `docs/tasks/`, or
  `docs/architecture/decisions/` — they are planning and historical documents
- Deleting or renaming existing source files
- Adding dependencies not already in the tech stack
- Changing the project structure beyond what a task requires
- Reorganizing `docs/spec/` — the structure is a stable contract

### Never
- Create files in `src/` without a corresponding task and test spec
- Combine unrelated changes in one task or commit
- Skip the test spec — even for "small" changes
- Force push or rewrite published git history
- Add a `Co-Authored-By` line to commits unless explicitly asked
- Append to spec entries instead of rewriting them (the ADR keeps history; the spec
  is a snapshot)
- Scan or interact with the network without user consent during development —
  dep-scan should only make network calls when the user explicitly invokes a scan
- Hardcode registry URLs — they must be configurable for testing and extensibility
- Commit directly to `main` (use `[allow-main]` in the message for genuine main-only
  fixes)
- Run `git checkout -- <path>` over a dirty working tree

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

The full retro log — every project-specific lesson with the incident that motivated
it — lives in [docs/agent-rules.md](docs/agent-rules.md). Read it.

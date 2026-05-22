# Task 073 — Remove (or relocate) scaffold leftovers

**Status:** backlog
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier B #7)
**Touches:** `requirements.txt`, `.env.example` (delete or move); `CLAUDE.md`
(optional one-line note)

## Objective

Remove the Python `requirements.txt` and `.env.example` from the repo root.
Both are leftover from the original Docker dev-container scaffold and have no
relationship to dep-scan as a Rust CLI. They confuse first-time readers
("why is there a Python requirements file in a Rust project?") and reference
`ANTHROPIC_API_KEY` which is unrelated to the binary's behavior.

## Background

`requirements.txt` contents:

```
# requirements.txt — dep-scan
# Add project Python dependencies here.
# Install inside the container: pip install -r requirements.txt
# The base image provides: python3, pip, git, build-essential
...
```

`.env.example` contents:

```
# .env.example — copy to .env and fill in real values
ANTHROPIC_API_KEY=
PYTHONPATH=/app/src
# Fine-grained personal access token scoped to this repository only.
GIT_TOKEN=
```

Both reference the dev-container workflow described in CLAUDE.md's "Docker
(run from host…)" command block, NOT anything dep-scan itself uses.

Two viable approaches:

A. **Delete.** Cleanest. Anyone wanting the Docker dev workflow can pull it
   back from git history. CLAUDE.md gets a one-line note that the Docker
   block is currently aspirational rather than maintained.

B. **Relocate.** Move both files under `.devcontainer/` and update CLAUDE.md
   to point there. Preserves the workflow option for users who want it.

Recommend A — the Docker block in CLAUDE.md is the only place these files
were used, and it hasn't been exercised in this session's record of work.

## Behavior

**If A (delete):**

1. `git rm requirements.txt .env.example`
2. CLAUDE.md's "Docker (run from host, outside the container)" section: add
   a leading note like "Note: the Docker dev-container workflow below is
   aspirational. The `.env` / `requirements.txt` files it references are not
   currently maintained in-tree."

   Or remove the Docker block entirely if it's not used. Decide based on
   whether the user still uses it.

**If B (relocate):**

1. `mkdir .devcontainer`
2. `git mv requirements.txt .devcontainer/requirements.txt`
3. `git mv .env.example .devcontainer/.env.example`
4. Update CLAUDE.md's Docker block to reference the new paths.

## Acceptance criteria

- [ ] Repo root no longer has `requirements.txt` and `.env.example` (or they
      have moved to `.devcontainer/`)
- [ ] `.gitignore` still excludes any `.env` file appropriately
- [ ] CLAUDE.md's Docker block either points to the new location or notes
      the deprecation
- [ ] No other docs reference the old paths (grep across `docs/`, `README.md`,
      `.github/` confirms zero hits to the old root paths)
- [ ] Working tree clean after the move/delete

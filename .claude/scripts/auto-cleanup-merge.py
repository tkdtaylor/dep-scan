#!/usr/bin/env python3
"""PostToolUse hook for Bash — auto-clean task branches and worktrees after merge.

When a `task/NNN-<slug>` branch is merged into main (via `git merge` or
`gh pr merge`), this hook removes the local artifacts so the repo stays
tidy without manual cleanup:

  - `git branch -d task/NNN-<slug>` — safe delete; refuses if unmerged
  - `git worktree remove .claude/worktrees/NNN-<slug>/` — if the task ran
    under worktree isolation

Both operations are best-effort. Failures are surfaced as a note, never
as a hard error — the merge itself already succeeded; cleanup is hygiene,
not correctness.

This hook is tech/data only because research projects don't use the
worktree-isolation pattern (no compiled artifacts, no test gates).
Research still gets branch-per-task via `no-commit-on-main.py`; the
branch cleanup can be added later if it becomes valuable.
"""

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "standard")

TASK_REF_RE = re.compile(r"^task/(.+)$")


def parse_merged_ref(tokens: list[str]) -> str | None:
    """Extract the ref argument from `git merge [opts] <ref>`.

    Returns None if the command isn't a git merge invocation.
    """
    SEPARATORS = {"&&", "||", ";", "|", "&"}
    in_git = False
    seen_merge = False
    for tok in tokens:
        if tok in SEPARATORS:
            in_git = False
            seen_merge = False
            continue
        if not in_git:
            if tok == "git":
                in_git = True
            continue
        if not seen_merge:
            if tok.startswith("-"):
                continue
            if tok == "merge":
                seen_merge = True
                continue
            # A different subcommand — bail.
            return None
        # in_git AND seen_merge: scan for the first non-flag positional arg.
        if tok.startswith("-"):
            continue
        return tok
    return None


def is_gh_pr_merge(tokens: list[str]) -> bool:
    """Detect a `gh pr merge ...` invocation."""
    SEPARATORS = {"&&", "||", ";", "|", "&"}
    seen_gh = False
    seen_pr = False
    for tok in tokens:
        if tok in SEPARATORS:
            seen_gh = False
            seen_pr = False
            continue
        if not seen_gh:
            if tok == "gh":
                seen_gh = True
            continue
        if not seen_pr:
            if tok == "pr":
                seen_pr = True
            continue
        if tok == "merge":
            return True
        if not tok.startswith("-"):
            return False
    return False


def gh_pr_head_branch(cwd: Path) -> str | None:
    """Ask gh for the head branch of the most recently merged PR."""
    try:
        out = subprocess.run(
            ["gh", "pr", "view", "--json", "headRefName,state"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    try:
        payload = json.loads(out.stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if payload.get("state") not in {"MERGED", "merged"}:
        return None
    return payload.get("headRefName")


def normalize_task_ref(ref: str) -> str | None:
    """Strip optional `refs/heads/` or remote prefix and confirm task/ shape.

    Returns the canonical `task/<slug>` form, or None if not a task branch.
    """
    # Remote-tracking refs like `origin/task/NNN-foo` are still task branches.
    if "/" in ref and not ref.startswith("task/"):
        parts = ref.split("/")
        if "task" in parts:
            idx = parts.index("task")
            ref = "/".join(parts[idx:])
    if ref.startswith("refs/heads/"):
        ref = ref[len("refs/heads/") :]
    if not ref.startswith("task/"):
        return None
    return ref


def cleanup(cwd: Path, task_ref: str, notes: list[str]) -> None:
    """Safe-delete the branch and remove its worktree if present."""
    match = TASK_REF_RE.match(task_ref)
    if not match:
        return
    slug = match.group(1)

    # Worktree first — `git branch -d` refuses to delete a branch with a
    # live worktree, so we have to clean the worktree before the branch.
    worktree_path = cwd / ".claude" / "worktrees" / slug
    if worktree_path.exists():
        try:
            wt = subprocess.run(
                ["git", "worktree", "remove", str(worktree_path)],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if wt.returncode == 0:
                notes.append(f"removed worktree {worktree_path.relative_to(cwd)}")
            else:
                # Try --force as a fallback (worktree had local changes).
                wt2 = subprocess.run(
                    ["git", "worktree", "remove", "--force", str(worktree_path)],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if wt2.returncode == 0:
                    notes.append(
                        f"force-removed worktree {worktree_path.relative_to(cwd)} "
                        f"(it had local changes — review with `git reflog`)"
                    )
                else:
                    notes.append(
                        f"worktree {worktree_path.relative_to(cwd)} not removed: "
                        f"{wt.stderr.strip() or wt.stdout.strip()}"
                    )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            notes.append(f"worktree cleanup skipped: {exc}")

    # Branch — `-d` is the safe variant; refuses if not fully merged.
    try:
        br = subprocess.run(
            ["git", "branch", "-d", task_ref],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if br.returncode == 0:
            notes.append(f"deleted branch {task_ref}")
        elif "not fully merged" in (br.stderr.lower() + br.stdout.lower()):
            notes.append(
                f"branch {task_ref} kept — not fully merged (use `git branch -D` "
                f"if you really meant to discard it)"
            )
        else:
            notes.append(
                f"branch {task_ref} not deleted: "
                f"{br.stderr.strip() or br.stdout.strip()}"
            )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        notes.append(f"branch cleanup skipped: {exc}")


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    # PostToolUse fires whether the command succeeded or not. If the merge
    # failed (conflict, dirty tree, etc.), cleanup would be wrong — bail.
    tool_response = hook_input.get("tool_response", {})
    interrupted = tool_response.get("interrupted")
    is_error = tool_response.get("is_error") or tool_response.get("isError")
    if interrupted or is_error:
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    try:
        tokens = shlex.split(command)
    except ValueError:
        sys.exit(0)

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    merged_ref = parse_merged_ref(tokens)
    if not merged_ref and is_gh_pr_merge(tokens):
        merged_ref = gh_pr_head_branch(project)
    if not merged_ref:
        sys.exit(0)

    task_ref = normalize_task_ref(merged_ref)
    if not task_ref:
        sys.exit(0)

    notes: list[str] = []
    cleanup(project, task_ref, notes)

    if notes:
        print("[auto-cleanup-merge] " + " · ".join(notes), file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()

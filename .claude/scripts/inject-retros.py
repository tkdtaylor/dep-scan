#!/usr/bin/env python3
"""SessionStart hook — inject relevant Failure-mode entries from CLAUDE.md
when a session starts on a project that has an active task.

The "Failure modes" section in CLAUDE.md grows over a project's lifetime
with project-specific retros. Loading every retro into every session wastes
tokens; the agent ignores ones that don't apply to the current work. This
hook reads the active task spec, keyword-matches against retro headings,
and injects only the matching entries.

Output uses additionalContext (same pattern as post-compact.py) so it lands
in context but doesn't pollute the visible transcript.
"""

import json
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "standard")

# Words that are too common to use as match anchors.
STOP_WORDS = {
    "the", "and", "for", "with", "from", "into", "this", "that",
    "task", "spec", "test", "tests", "code", "file", "files",
    "must", "should", "when", "then", "else", "have", "has",
    "what", "which", "where", "while", "after", "before",
    "your", "you", "we", "our", "it", "is", "are", "be", "to",
    "of", "in", "on", "at", "by", "as", "an", "a", "or", "if",
    "all", "any", "no", "not", "do", "does", "did", "done",
    "use", "using", "used", "set", "get", "run", "ran",
}


def keywords(text: str, max_count: int = 40) -> set[str]:
    """Extract content words longer than 4 chars, lowercased, deduplicated."""
    words = re.findall(r"[A-Za-z][A-Za-z0-9_]{4,}", text.lower())
    return {w for w in words if w not in STOP_WORDS}


def parse_retro_section(claude_md: str) -> list[tuple[str, str]]:
    """Extract retros from CLAUDE.md. Returns list of (heading, body) tuples.

    Looks for ## Failure modes first; falls back to ## Common rationalizations.
    Each retro entry is delimited by ### or by paragraph breaks.
    """
    # Find the section.
    sections = ["Failure modes", "Common rationalizations"]
    section_text = ""
    for section in sections:
        m = re.search(
            rf"^##\s+{re.escape(section)}\s*$(.*?)(?=^##\s+|\Z)",
            claude_md, re.MULTILINE | re.DOTALL,
        )
        if m:
            section_text = m.group(1)
            break

    if not section_text:
        return []

    # Split on ### headings (most retros are structured this way).
    parts = re.split(r"^###\s+(.+)$", section_text, flags=re.MULTILINE)
    retros: list[tuple[str, str]] = []

    if len(parts) > 1:
        # Skip parts[0] (preamble before first ###).
        for i in range(1, len(parts), 2):
            heading = parts[i].strip()
            body = parts[i + 1].strip() if i + 1 < len(parts) else ""
            if heading and body:
                retros.append((heading, body))
    else:
        # No ### subsections — fall back to paragraph splits for tables/lists.
        # Useful for the "Common rationalizations" table format.
        paragraphs = re.split(r"\n\s*\n", section_text)
        for p in paragraphs:
            p = p.strip()
            if len(p) > 50 and not p.startswith(">"):
                retros.append(("rationalizations", p))

    return retros


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not project.is_dir():
        sys.exit(0)

    # Look for retros in CLAUDE.md and also in docs/architecture/agent-rules.md
    # (the latter is where projects move retros once CLAUDE.md gets too large).
    sources = [
        project / "CLAUDE.md",
        project / "docs" / "architecture" / "agent-rules.md",
    ]

    retros: list[tuple[str, str]] = []
    for src in sources:
        if not src.exists():
            continue
        try:
            text = src.read_text(encoding="utf-8")
        except OSError:
            continue
        retros.extend(parse_retro_section(text))

    if not retros:
        sys.exit(0)

    # Find active task spec (or fall back to active task file).
    spec_kw: set[str] = set()
    active_dir = project / "docs" / "tasks" / "active"
    spec_dir = project / "docs" / "tasks" / "test-specs"

    active_task: Path | None = None
    if active_dir.is_dir():
        tasks = sorted(active_dir.glob("*.md"))
        if tasks:
            active_task = tasks[-1]

    if active_task:
        # Pull keywords from task name + spec body.
        spec_kw |= keywords(active_task.stem.replace("-", " "))
        spec_file = spec_dir / f"{active_task.stem}-test-spec.md"
        if spec_file.exists():
            try:
                spec_kw |= keywords(spec_file.read_text(encoding="utf-8"))
            except OSError:
                pass
        try:
            spec_kw |= keywords(active_task.read_text(encoding="utf-8"))
        except OSError:
            pass

    # Score each retro by how many spec keywords appear in it.
    matches: list[tuple[int, str, str]] = []
    for heading, body in retros:
        retro_kw = keywords(heading + " " + body)
        score = len(spec_kw & retro_kw)
        if score >= 2:
            matches.append((score, heading, body))

    # Always inject "rationalizations" if present (it's the universal table).
    rationalizations = [r for r in retros if r[0] == "rationalizations"]

    matches.sort(reverse=True)
    selected = matches[:3]  # Cap to keep injection tight.

    if not selected and not rationalizations:
        sys.exit(0)

    parts = []
    if selected:
        parts.append("Project-specific retros relevant to the active task:")
        for score, heading, body in selected:
            # Truncate long bodies to keep injection compact.
            body_short = body if len(body) < 600 else body[:600].rsplit("\n", 1)[0] + " […]"
            parts.append(f"\n**{heading}**\n{body_short}")

    if rationalizations and not selected:
        # Only inject rationalizations as a fallback when no scored matches.
        body = rationalizations[0][1]
        body_short = body if len(body) < 800 else body[:800].rsplit("\n", 1)[0] + " […]"
        parts.append("Common rationalizations to watch for:\n" + body_short)

    if not parts:
        sys.exit(0)

    context = "[Retro injection — relevant CLAUDE.md entries]\n" + "\n".join(parts)

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }))


if __name__ == "__main__":
    main()

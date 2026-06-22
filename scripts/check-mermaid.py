#!/usr/bin/env python3
"""check-mermaid.py — lint Mermaid code blocks for syntax that GitHub won't render.

GitHub's Mermaid renderer rejects a handful of patterns that look fine in an editor
but fail with "Unable to render rich display / Parse error on line N". This is a
zero-dependency heuristic linter for the recurring offenders; it does NOT replace a
full parser, but it catches every cause we have actually hit in practice.

Usage:
    python3 scripts/check-mermaid.py [FILE ...]

With no arguments it scans `README.md` and every `*.md` under `docs/`.
Exits non-zero if any issue is found, so it can gate a check or an audit.

Patterns flagged (inside ```mermaid fences only):
  - `;` in a label/message/note — Mermaid treats it as a statement separator.
  - HTML entities (`&lt;` `&gt;` `&amp;` `&#…;`) — the `;` inside them breaks parsing.
  - A reserved keyword used as a participant/actor id (`box`, `note`, `end`, `loop`,
    `alt`, `opt`, `par`, `rect`, `class`, `state`, `activate`, `deactivate`, …).
  - An inline `%%` comment — Mermaid comments must be on their own line.
  - Parentheses inside a flowchart edge label `|...|`. GitHub does NOT honor `"…"`
    quotes inside pipe labels, so quoting does not help — remove/rephrase the parens.
  - Square brackets `[` `]` in a sequenceDiagram message or note. GitHub parses `[`
    as syntax, not message text, and fails — drop them or use `(` `)`.

The fix is almost always: replace `;` with `,`/" and ", rename the participant id,
move the `%%` to its own line, drop the parens from an edge label, or swap `[..]`
for `(..)` in a sequence message.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Keywords that break when used as a sequenceDiagram participant/actor id.
# Verified empirically against the Mermaid parser — `state`/`class`/`namespace`/
# `direction`/`as` are NOT included because they parse fine as participant ids.
RESERVED_PARTICIPANT_IDS = {
    "box", "note", "end", "loop", "alt", "opt", "par", "and", "rect",
    "critical", "break", "activate", "deactivate", "link", "over", "title",
    "participant", "actor",
}

_part_re = re.compile(r"^\s*(?:participant|actor)\s+([A-Za-z_][\w-]*)\b", re.IGNORECASE)
_entity_re = re.compile(r"&(?:[a-zA-Z]+|#\d+);")
_edge_label_re = re.compile(r"\|([^|]*)\|")

# A sequenceDiagram message (`A->>B: text`) or a note/loop/alt/opt with trailing
# text after a `:`. Sequence arrows: -> --> ->> -->> -x --x -) --) and the
# bidirectional <<->> / <<-->>. We only need the text after the first `:`.
_seq_arrow_re = re.compile(r"(?:<<-?-?>>|--?>>?|--?x|--?\))")
_seq_msg_re = re.compile(r"^\s*\S.*?" + _seq_arrow_re.pattern + r".*?:\s*(?P<msg>.*)$")
_seq_note_re = re.compile(r"^\s*(?:note|loop|alt|opt|par|rect|critical|break)\b.*?:\s*(?P<msg>.*)$",
                          re.IGNORECASE)


def block_kind(body: list[str]) -> str:
    """First non-blank, non-comment body line names the diagram kind (lowercased)."""
    for raw in body:
        s = raw.strip()
        if not s or s.startswith("%%"):
            continue
        return s.split()[0].lower()
    return ""


def find_blocks(text: str):
    """Yield (start_line, [lines]) for each ```mermaid fenced block (1-based lines)."""
    lines = text.split("\n")
    cur = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if cur is None and re.fullmatch(r"```+mermaid", stripped):
            cur = (i + 2, [])  # first body line number
            continue
        if cur is not None and re.fullmatch(r"```+", stripped):
            yield cur
            cur = None
            continue
        if cur is not None:
            cur[1].append(line)
    # unclosed block: ignore (a separate markdown problem)


def lint_block(start_line: int, body: list[str]):
    issues = []
    kind = block_kind(body)
    is_sequence = kind in ("sequencediagram",)
    for offset, raw in enumerate(body):
        lineno = start_line + offset
        line = raw.rstrip("\n")
        no_lead = line.lstrip()

        # Own-line comments are exempt from the content checks below.
        if no_lead.startswith("%%"):
            continue

        # Strip double-quoted spans first: `;`, entities, and `%%` are all harmless
        # inside a quoted label/description (e.g. C4 element text) and render fine.
        unq = re.sub(r'"[^"]*"', "", line)

        # Inline %% (comment not on its own line).
        if "%%" in unq:
            issues.append((lineno, "inline `%%` comment — Mermaid comments must be on their own line", line))

        # HTML entities (the trailing `;` breaks the parser).
        if _entity_re.search(unq):
            issues.append((lineno, "HTML entity (e.g. &lt; &gt;) — the `;` breaks parsing; use plain text", line))
        elif re.search(r";\s*\S", unq):
            # A `;` with content after it is a statement separator splitting a label.
            # (A trailing `;` is a legal flowchart terminator, so it's not flagged.)
            issues.append((lineno, "`;` acts as a statement separator — replace with `,` or ` and `", line))

        # Reserved keyword as a participant/actor id.
        m = _part_re.match(line)
        if m and m.group(1).lower() in RESERVED_PARTICIPANT_IDS:
            issues.append((lineno, f"`{m.group(1)}` is a reserved Mermaid keyword — rename this participant id", line))

        # Parentheses inside a flowchart edge label |...|. GitHub does NOT honor
        # `"…"` quoting inside pipe labels, so a quoted label with parens still
        # fails — flag regardless of quotes; the fix is to remove/rephrase them.
        if not is_sequence:
            for em in _edge_label_re.finditer(line):
                label = em.group(1).strip()
                if "(" in label or ")" in label:
                    issues.append((lineno, "parentheses in an edge label break GitHub "
                                   "(quotes are not honored here) — remove or rephrase them", line))
                    break

        # Square brackets in a sequenceDiagram message/note — GitHub parses `[` as
        # syntax, not text, and fails. (Brackets are legal node syntax elsewhere.)
        if is_sequence:
            m = _seq_msg_re.match(line) or _seq_note_re.match(line)
            if m and ("[" in m.group("msg") or "]" in m.group("msg")):
                issues.append((lineno, "`[`/`]` in a sequence message break GitHub's "
                               "parser — drop them or use `(`/`)`", line))
    return issues


def default_targets() -> list[Path]:
    targets = []
    if Path("README.md").is_file():
        targets.append(Path("README.md"))
    docs = Path("docs")
    if docs.is_dir():
        targets.extend(sorted(docs.rglob("*.md")))
    return targets


def main(argv: list[str]) -> int:
    args = [Path(a) for a in argv[1:]] or default_targets()
    total_blocks = 0
    total_issues = 0
    for path in args:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for start, body in find_blocks(text):
            total_blocks += 1
            for lineno, msg, src in lint_block(start, body):
                total_issues += 1
                print(f"{path}:{lineno}: {msg}\n    | {src.strip()}")

    if total_issues:
        print(f"\n✗ {total_issues} Mermaid issue(s) across {total_blocks} block(s). "
              f"GitHub will likely fail to render these.")
        return 1
    print(f"✓ {total_blocks} Mermaid block(s) checked, no GitHub-render hazards found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
"""Stop hook — flag tests in the current diff that don't assert anything.

Catches the "smoke test where spec asks for assertion" failure mode by
scanning newly-added or modified test functions for the absence of any
assertion-like construct. Advisory only — prints to stderr.

Per-language detection:
  - Rust: function with #[test] attribute → check for assert!, assert_eq!,
    assert_ne!, panic!, ?, .unwrap_err()
  - Python: function `def test_*` → check for assert, pytest.raises,
    self.assert*, with raises(...)
  - JavaScript / TypeScript: it(...) or test(...) blocks → check for
    expect(, assert., chai, .toBe, .toEqual, .toThrow
  - Go: func Test*(t *testing.T) → check for t.Error, t.Fatal,
    require., assert., t.Errorf
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "standard")


# Per-language test-fn detector and assertion-pattern matcher.
LANGS: dict[str, dict[str, str]] = {
    ".rs": {
        # Function preceded by #[test] attribute (or #[tokio::test], etc).
        # We extract the body and look for assertions.
        "fn_re": r"#\[(?:[a-zA-Z0-9_:]+)?test(?:[^\]]*)?\]\s*\n\s*(?:async\s+)?fn\s+(\w+)\s*\([^)]*\)\s*(?:->\s*[^{]+)?\{",
        "assert_re": r"\b(?:assert|assert_eq|assert_ne|panic|debug_assert|debug_assert_eq|debug_assert_ne)!|\.unwrap_err\(\)|\?\s*;|\bbail!|\bensure!|expect\(",
    },
    ".py": {
        "fn_re": r"def\s+(test_\w+)\s*\([^)]*\)\s*(?:->[^:]+)?:",
        "assert_re": r"\bassert\b|pytest\.raises|self\.assert[A-Z]\w*|with\s+raises|@pytest\.mark\.xfail",
    },
    ".ts": {
        "fn_re": r"(?:^|\s)(?:it|test)\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{",
        "assert_re": r"\bexpect\s*\(|\bassert[\.\(]|\.to(?:Be|Equal|Throw|Match|Contain|HaveBeenCalled)|chai\.|should\.",
    },
    ".tsx": {  # alias
        "fn_re": r"(?:^|\s)(?:it|test)\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{",
        "assert_re": r"\bexpect\s*\(|\bassert[\.\(]|\.to(?:Be|Equal|Throw|Match|Contain|HaveBeenCalled)|chai\.|should\.",
    },
    ".js": {
        "fn_re": r"(?:^|\s)(?:it|test)\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{",
        "assert_re": r"\bexpect\s*\(|\bassert[\.\(]|\.to(?:Be|Equal|Throw|Match|Contain|HaveBeenCalled)|chai\.|should\.",
    },
    ".jsx": {
        "fn_re": r"(?:^|\s)(?:it|test)\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{",
        "assert_re": r"\bexpect\s*\(|\bassert[\.\(]|\.to(?:Be|Equal|Throw|Match|Contain|HaveBeenCalled)|chai\.|should\.",
    },
    ".go": {
        "fn_re": r"func\s+(Test\w+)\s*\(\s*\w+\s*\*testing\.[TBF]\s*\)\s*\{",
        "assert_re": r"\bt\.(?:Error|Fatal|Errorf|Fatalf|Fail)|\b(?:require|assert)\.\w+",
    },
    ".rb": {
        "fn_re": r"(?:def\s+(test_\w+)|it\s+['\"]([^'\"]+)['\"])",
        "assert_re": r"\bassert\w*|\bexpect\s*\(|\.must_|\.wont_|\.to\s+|\.not_to\s+|raise_error",
    },
}


def find_block_end(text: str, start: int) -> int:
    """Return index of matching closing brace for the block starting at `start`
    (which should be just after the opening `{`). Naive — ignores strings/comments
    but good enough for the heuristic."""
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text)


def find_python_block_end(text: str, fn_start_line: int) -> int:
    """Find the end of a Python function by indentation. Returns line index."""
    lines = text.split("\n")
    if fn_start_line >= len(lines):
        return len(lines)

    # Determine the indent level of the first body line.
    body_indent = None
    end = fn_start_line + 1
    for i in range(fn_start_line + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if body_indent is None:
            body_indent = indent
        elif indent < body_indent and stripped:
            return i
        end = i + 1
    return end


def scan_file(path: Path) -> list[tuple[str, str]]:
    """Return list of (test_name, reason) for tests with no assertions."""
    suffix = path.suffix
    if suffix not in LANGS:
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    cfg = LANGS[suffix]
    fn_re = re.compile(cfg["fn_re"], re.MULTILINE)
    assert_re = re.compile(cfg["assert_re"])

    findings: list[tuple[str, str]] = []

    for m in fn_re.finditer(text):
        # Get test name from whichever capture group matched.
        name = next((g for g in m.groups() if g), "<anonymous>")

        if suffix == ".py":
            line_idx = text[: m.end()].count("\n")
            end_line = find_python_block_end(text, line_idx)
            body = "\n".join(text.split("\n")[line_idx:end_line])
        else:
            # Brace-delimited languages: body starts after the {
            brace_pos = text.find("{", m.start())
            if brace_pos < 0:
                continue
            end = find_block_end(text, brace_pos + 1)
            body = text[brace_pos + 1 : end]

        # Strip line comments (rough — good enough).
        body_clean = re.sub(r"//[^\n]*", "", body)
        body_clean = re.sub(r"#[^\n]*", "", body_clean) if suffix == ".py" else body_clean

        if not assert_re.search(body_clean):
            findings.append((name, "no assertion / panic / expect found in body"))

    return findings


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not (project / ".git").exists():
        sys.exit(0)

    # Only scan test files in the current diff to avoid noise from old code.
    try:
        result = subprocess.run(
            ["git", "diff", "HEAD", "--name-only"],
            capture_output=True, text=True, timeout=5, cwd=str(project),
        )
    except Exception:
        sys.exit(0)

    changed = [project / line.strip() for line in result.stdout.splitlines() if line.strip()]
    test_paths = [
        p for p in changed
        if p.is_file()
        and p.suffix in LANGS
        and (
            "test" in p.name.lower()
            or "/tests/" in str(p)
            or "/__tests__/" in str(p)
            or p.name.endswith("_test.go")
        )
    ]

    if not test_paths:
        sys.exit(0)

    all_findings: list[tuple[Path, str, str]] = []
    for path in test_paths:
        for name, reason in scan_file(path):
            rel = path.relative_to(project)
            all_findings.append((rel, name, reason))

    if not all_findings:
        sys.exit(0)

    # Cap output at 8 to keep it skimmable.
    print("[detect-smoke-tests] tests in current diff with no assertions:", file=sys.stderr)
    for rel, name, reason in all_findings[:8]:
        print(f"  {rel}::{name} — {reason}", file=sys.stderr)
    if len(all_findings) > 8:
        print(f"  ... and {len(all_findings) - 8} more", file=sys.stderr)
    print(
        "Per CLAUDE.md → Failure modes: a test that calls the function "
        "without asserting the spec's behavior is a smoke test, not a real test.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

# Task 072 — Refresh `docs/plans/roadmap.md` through v1.2.0

**Status:** backlog
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier B #6)
**Touches:** `docs/plans/roadmap.md`

## Objective

Bring the roadmap up to date. It currently stops at v1.0 (2026-04-04) and
misses v1.1.0 (cache integrity + sigstore), v1.1.1 (HIGH security audit
fixes, tasks 037-042), and v1.2.0 (MEDIUM/LOW audit fixes, tasks 043-063).

## Background

Anyone arriving at the repo today and reading `docs/plans/roadmap.md` would
think dep-scan stopped at v1.0. That's misleading — three more releases have
shipped, and a substantial security audit work batch landed across them.

The roadmap is the natural "what has shipped and what's next" landing point.
Keeping it current matters more for OSS than for an internal tool.

## Behavior

1. Add new "Completed milestones" blocks for v1.1.0, v1.1.1, v1.2.0 modeled
   on the existing v0.1/v0.2/v0.3/v1.0 blocks. Each block lists the
   headline items and links to the relevant CHANGELOG entry.
2. Move any "Future ideas" items that have since shipped out of the
   "Future ideas" list (audit it for staleness while we're in there).
3. The dates use the actual release dates from `CHANGELOG.md`.
4. The "Backlog" section at the bottom stays; "Future ideas" gets pruned to
   items that genuinely haven't shipped.

## Acceptance criteria

- [ ] `docs/plans/roadmap.md` contains a v1.1.0 milestone block
- [ ] Contains a v1.1.1 milestone block (with task-037-042 reference)
- [ ] Contains a v1.2.0 milestone block (with tasks 043-063 reference)
- [ ] Dates match CHANGELOG.md
- [ ] "Future ideas" list does not contain items already shipped
- [ ] No broken cross-document links

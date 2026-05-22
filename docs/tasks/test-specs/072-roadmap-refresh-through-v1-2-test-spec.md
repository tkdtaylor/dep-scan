# Test Spec — Task 072: Refresh roadmap.md through v1.2.0

## Context

`docs/plans/roadmap.md` is stale — it documents up to v1.0 but the project
has shipped v1.1.0, v1.1.1, v1.2.0. This task brings it current.

---

## Validation

### T-072-01: v1.1.0 milestone block present
- The roadmap contains a `### v1.1.0 — …` heading with a dated subtitle and
  a checklist of headline items (cache content-hash verification,
  --require-hashes passthrough, sigstore Fulcio chain walk, Rekor inclusion
  proof, npm + PyPI provenance, Go sumdb).

### T-072-02: v1.1.1 milestone block present
- A `### v1.1.1 — …` heading exists referencing tasks 037-042 (HIGH security
  fixes).

### T-072-03: v1.2.0 milestone block present
- A `### v1.2.0 — …` heading exists referencing tasks 043-063 (MEDIUM, LOW,
  dep refreshes, post-cut hardening). Includes a note about task 056
  deferral.

### T-072-04: Milestone dates match CHANGELOG
- Each milestone heading's date matches the corresponding `## [X.Y.Z] — DATE`
  entry in `CHANGELOG.md`.

### T-072-05: "Future ideas" list pruned of shipped items
- The "Future ideas" list at the bottom no longer contains items shipped in
  v1.1 / v1.1.1 / v1.2 (e.g. nothing about content-hash verification or
  sigstore integration if those were ever listed).

### T-072-06: No broken links
- Every relative link in the file resolves to an existing file.

### T-072-07: "Last updated" field current
- The `**Last updated:**` line at the top is set to today's date (or the
  date the task is completed).

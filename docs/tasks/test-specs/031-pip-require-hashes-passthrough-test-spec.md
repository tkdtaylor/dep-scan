# Test Spec — Task 031: Close TOCTOU window for pip via `--require-hashes`

## Unit tests (requirements file construction)

### T-031-01: Build requirements file from metadata triples
- Input: `[("requests", "2.31.0", Some("sha256:aaaa")), ("urllib3", "2.0.7", Some("sha256:bbbb"))]`
- Expected: file contents are exactly two lines:
  ```
  requests==2.31.0 --hash=sha256:aaaa
  urllib3==2.0.7 --hash=sha256:bbbb
  ```

### T-031-02: Refuse to build when any hash is None
- Input: `[("requests", "2.31.0", Some("sha256:aaaa")), ("evil-pkg", "0.1.0", None)]`
- Expected: builder returns an error (or `None` sentinel) — caller must fall back to plain `pip install`

### T-031-03: Hash algorithm prefix is stripped correctly
- Input metadata: `content_hash = "sha256:abcdef"`
- Expected: requirements line contains `--hash=sha256:abcdef` (full `algo:hex` preserved verbatim; pip accepts this format)

### T-031-04: Non-sha256 algorithm rejected for pip
- Input metadata: `content_hash = "sha512:abcd"` (shouldn't happen from PyPI client, but defense in depth)
- Expected: builder returns error — falls back to plain install with a warning

## Unit tests (temp file lifecycle)

### T-031-05: Temp file is removed after successful invocation
- Build requirements file, simulate pip exit 0
- Expected: temp file no longer exists on disk

### T-031-06: Temp file is removed after failed invocation
- Build requirements file, simulate pip exit 1
- Expected: temp file no longer exists on disk

### T-031-07: Temp file is removed on panic / early return
- Implement via `Drop` or equivalent RAII; force an early return between file creation and pip exec
- Expected: temp file is still cleaned up

## Integration tests (assert_cmd + wiremock + mock pip)

### T-031-08: Clean pip install uses --require-hashes -r passthrough
- wiremock PyPI returns metadata with sdist `digests.sha256 = "abcd…"`, age passes
- Mock pip (a stub binary on `PATH`) that records its argv to a file
- Run: `dep-scan install requests --registry pypi`
- Expected: exit 0, pip's recorded argv contains `install`, `--require-hashes`, `-r`, and a path to a temp file; the temp file is deleted post-run

### T-031-09: Missing hash falls back to plain pip install
- wiremock PyPI returns metadata with no `digests` block (`content_hash = None`)
- Run: `dep-scan install obscure-pkg --registry pypi`
- Expected: exit 0, pip argv is `install obscure-pkg` (no `--require-hashes`), stderr contains a warning naming the registry URL and the package

### T-031-10: Mixed packages — fallback (all-or-nothing)
- wiremock returns hash for `pkg-a` but not for `pkg-b`
- Run: `dep-scan install pkg-a pkg-b --registry pypi`
- Expected: pip argv is `install pkg-a pkg-b` (no `--require-hashes`), stderr contains a warning naming `pkg-b`

### T-031-11: Non-pip registries are unchanged
- Run: `dep-scan install lodash --registry npm` against clean wiremock
- Expected: pip-related code is not exercised; npm argv is `install lodash` exactly as before

### T-031-12: --force after hash-mismatch re-scan still uses --require-hashes with the new hash
- Pre-populate cache with `(pkg, "latest", pypi, "pass", content_hash="sha256:aaaa")`
- wiremock returns metadata with `digests.sha256 = "bbbb"` and a fresh published_at (fails age policy)
- Run: `dep-scan install pkg --registry pypi --force`
- Expected: re-scan is triggered (per task 030), verdict is `block` for age, `--force` bypasses the verdict, pip argv contains `--require-hashes -r <file>` and the requirements file contains `--hash=sha256:bbbb` (the freshly observed hash, NOT the stale cached `aaaa`)

## Regression / safety

### T-031-13: Empty package list is a no-op
- Run: `dep-scan install --registry pypi` with no positional args
- Expected: CLI rejects empty input (existing behavior), no temp file is created

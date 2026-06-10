# Test Spec — Task 091: npm lockfile git URL parser

## Context

ADR 008 piece 1 — the npm lockfile parser in `src/lockfile.rs` currently skips
any `package-lock.json` entry whose `version` field is empty, and never reads the
`resolved` field. A git dependency has a `resolved` value of the form
`git+ssh://git@github.com/user/repo.git#<ref>`,
`git+https://github.com/user/repo#<ref>`, or a shorthand such as
`github:user/repo#<ref>` / `gitlab:user/repo#<ref>`. The `version` field for such
entries may be a SemVer placeholder (e.g. `"1.0.0"`) or absent/empty.

This task teaches `parse_package_lock_json` to detect a git `resolved` URL and
emit `DependencySource::Git { url, ref_ }` instead of either dropping the entry
or emitting a `Registry` dep with a placeholder version. It depends on task 090
for the `DependencySource::Git` variant.

---

## URL form recognition

### T-091-01: `git+https://` resolved URL is recognised
- Input package entry: `"resolved": "git+https://github.com/user/repo.git#abc1234"`.
- Parser emits one `LockfileDependency` with
  `source = DependencySource::Git { url: "https://github.com/user/repo.git", ref_: "abc1234" }`.
- The `git+` prefix is stripped from the URL stored in `source.url`.

### T-091-02: `git+ssh://` resolved URL is recognised
- Input: `"resolved": "git+ssh://git@github.com/user/repo.git#abc1234"`.
- Emits `DependencySource::Git { url: "ssh://git@github.com/user/repo.git", ref_: "abc1234" }`.

### T-091-03: `git+http://` resolved URL is recognised
- Input: `"resolved": "git+http://git.example.com/org/repo#deadbeef"`.
- Emits `DependencySource::Git { … }` (insecure plain http scheme is parsed but
  stored as-is; policy decisions about http vs https are out of scope for the
  parser).

### T-091-04: GitHub shorthand `github:user/repo#ref` is recognised
- Input: `"resolved": "github:user/repo#abc1234"`.
- Emits `DependencySource::Git { url: "https://github.com/user/repo", ref_: "abc1234" }`.

### T-091-05: GitLab shorthand `gitlab:user/repo#ref` is recognised
- Input: `"resolved": "gitlab:user/repo#abc1234"`.
- Emits `DependencySource::Git { url: "https://gitlab.com/user/repo", ref_: "abc1234" }`.

### T-091-06: Bitbucket shorthand `bitbucket:user/repo#ref` is recognised
- Input: `"resolved": "bitbucket:user/repo#abc1234"`.
- Emits `DependencySource::Git { url: "https://bitbucket.org/user/repo", ref_: "abc1234" }`.

### T-091-07: Package name is preserved from the lockfile key
- Input: key `"node_modules/evil-pkg"`, `"resolved": "git+https://github.com/bad/evil#main"`.
- Emitted `dep.name == "evil-pkg"`.

### T-091-08: Non-git `resolved` URL does not trigger git parsing
- Input: `"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"`, `"version": "4.18.2"`.
- Emits `DependencySource::Registry { registry: RegistryType::Npm }` as before.

---

## Ref extraction

### T-091-09: Ref is extracted from the `#` fragment
- Input: `"resolved": "git+https://github.com/user/repo#abc1234def5678901234567890abcdef12345678"`.
- `dep.source.git_ref() == Some("abc1234def5678901234567890abcdef12345678")`.

### T-091-10: URL without `#` fragment gets empty ref
- Input: `"resolved": "git+https://github.com/user/repo"` (no `#`).
- Emits `DependencySource::Git { url: "https://github.com/user/repo", ref_: "" }`.
- No panic, no drop.

### T-091-11: `#` in URL but no ref after it gets empty ref
- Input: `"resolved": "git+https://github.com/user/repo#"`.
- `dep.source.git_ref() == Some("")`.

---

## Entries previously dropped now emitted

### T-091-12: Entry with empty `version` but git `resolved` is no longer dropped
- Input: package with `"version": ""` (or absent) and
  `"resolved": "git+https://github.com/user/repo#abc"`.
- Parser emits exactly one `LockfileDependency`.
- Previously this entry was silently skipped (version-is-empty guard).

### T-091-13: Entry with placeholder version and git `resolved` emits Git dep, not Registry dep
- Input: `"version": "1.0.0"`, `"resolved": "git+https://github.com/user/repo#abc"`.
- Emits `DependencySource::Git`, not `DependencySource::Registry`.
- The placeholder version `"1.0.0"` must not be used to route the dep to npm.

---

## Mixed lockfile

### T-091-14: Lockfile with both registry and git deps produces both kinds
- Input: a `package-lock.json` with two packages — one with an npm tarball
  `resolved` URL and one with a `git+https://` resolved URL.
- Parser emits two deps: one `Registry(Npm)`, one `Git`.

### T-091-15: v1 `dependencies` format also parses git `resolved` URLs
- Input: a v1-format lockfile (top-level `"dependencies"` key) with one entry
  whose `resolved` is `"git+https://github.com/user/repo#abc"`.
- Emits `DependencySource::Git`.

---

## Scoped packages

### T-091-16: Scoped package with git `resolved` preserves scoped name
- Key: `"node_modules/@myorg/mylib"`, `"resolved": "git+https://github.com/myorg/mylib#abc"`.
- `dep.name == "@myorg/mylib"`.

---

## Malformed input

### T-091-17: Truncated git URL (no host, no path) is stored as-is, not panicked
- Input: `"resolved": "git+https://"` (degenerate).
- Parser does not panic; emits a `Git` dep with whatever URL was present after
  stripping `git+`.

### T-091-18: `resolved` value is not a string (JSON number) — entry is skipped, no panic
- Input: `"resolved": 12345` (wrong JSON type).
- Parser skips the entry without panicking.

---

## Tooling gate

### T-091-19: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

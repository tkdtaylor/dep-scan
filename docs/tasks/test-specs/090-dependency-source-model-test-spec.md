# Test Spec — Task 090: Dependency source model (`DependencySource` enum)

## Context

ADR 008 piece 1 — the `LockfileDependency` struct in `src/lockfile.rs` currently
carries only `name`, `version`, and `registry: RegistryType`. There is no way to
represent a git-sourced dependency; such entries are currently dropped or
mis-routed to a registry client. This task introduces a `DependencySource` enum
(`Registry { registry: RegistryType }` | `Git { url: String, ref_: String }`) and
embeds it as a `source` field on `LockfileDependency`, replacing the flat
`registry` field.

All existing callers that pattern-match on the `registry` field must be updated to
match on `source`; no behavior changes to existing registry-path logic are
permitted in this task — this is purely a model change.

---

## DependencySource type

### T-090-01: `DependencySource::Registry` carries `RegistryType`
- Construct `DependencySource::Registry { registry: RegistryType::Npm }`.
- `source.registry_type()` (or equivalent accessor) returns `Some(RegistryType::Npm)`.

### T-090-02: `DependencySource::Git` carries `url` and `ref_` strings
- Construct `DependencySource::Git { url: "https://github.com/user/repo".into(), ref_: "abc123".into() }`.
- `.url()` returns `"https://github.com/user/repo"`.
- `.git_ref()` returns `"abc123"`.

### T-090-03: `DependencySource::Registry` returns `None` for `git_ref()`
- `DependencySource::Registry { registry: RegistryType::Crates }.git_ref()` returns `None`.

### T-090-04: `DependencySource::Git` returns `None` for `registry_type()`
- `DependencySource::Git { url: "…".into(), ref_: "…".into() }.registry_type()` returns `None`.

### T-090-05: `DependencySource` implements `Debug`, `Clone`, `PartialEq`
- Two identical `DependencySource::Git` values compare equal.
- Two identical `DependencySource::Registry` values compare equal.
- `Registry(Npm) != Registry(PyPI)`.
- `Git { url: "a", ref_: "b" } != Git { url: "a", ref_: "c" }`.

---

## LockfileDependency with new source field

### T-090-06: `LockfileDependency` has a `source: DependencySource` field
- Constructing `LockfileDependency { name: "foo".into(), version: "1.0.0".into(), source: DependencySource::Registry { registry: RegistryType::Npm } }` compiles.
- `.source` returns the correct `DependencySource`.

### T-090-07: A git-sourced `LockfileDependency` can be constructed
- `LockfileDependency { name: "evil-pkg".into(), version: "".into(), source: DependencySource::Git { url: "https://github.com/evil/repo".into(), ref_: "main".into() } }` compiles and round-trips through `Clone`.

### T-090-08: Old `registry` flat field no longer exists on `LockfileDependency`
- Accessing `dep.registry` on a `LockfileDependency` does not compile.
- All construction sites use the `source` field instead.
- (Verified by the project compiling cleanly with `cargo build`.)

---

## Existing parsers still produce Registry-source deps

### T-090-09: `parse_package_lock_json` produces `DependencySource::Registry { registry: RegistryType::Npm }` for normal packages
- Parse a minimal `package-lock.json` with a single versioned package.
- `deps[0].source == DependencySource::Registry { registry: RegistryType::Npm }`.

### T-090-10: `parse_cargo_lock` produces `DependencySource::Registry { registry: RegistryType::Crates }` for registry packages
- Parse a `Cargo.lock` with one `registry+` source entry.
- `deps[0].source == DependencySource::Registry { registry: RegistryType::Crates }`.

### T-090-11: `parse_requirements_txt` produces `DependencySource::Registry { registry: RegistryType::PyPI }`
- Parse a requirements.txt with one `==`-pinned line.
- `deps[0].source == DependencySource::Registry { registry: RegistryType::PyPI }`.

### T-090-12: `parse_go_sum` produces `DependencySource::Registry { registry: RegistryType::Go }`
- Parse a `go.sum` with one line.
- `deps[0].source == DependencySource::Registry { registry: RegistryType::Go }`.

---

## main.rs scan loop compiles and routes correctly after model change

### T-090-13: Registry-sourced deps still route to registry clients after refactor
- In the scan loop (unit-testable helper if extracted), a `DependencySource::Registry { registry: RegistryType::Npm }` dep still dispatches to the npm client.
- No behavioral change on the existing happy path.

### T-090-14: `PackageRef::from_lockfile_dep` accepts the new `LockfileDependency` shape
- `PackageRef::from_lockfile_dep(dep.name, dep.version)` continues to compile
  (or is updated to accept the new struct); existing tests in the scan loop are
  unaffected.

---

## Tooling gate

### T-090-15: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.
- `cargo build` exits 0 (compilation gate for the removed `registry` field).

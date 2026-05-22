# Test Spec — Task 078: Lockfile scanner uses pinned versions

## Context

`src/main.rs` discards the version field parsed from lockfile entries and
calls `Registry::get_metadata(name, None)`, which fetches the registry's
current "latest" instead of the lockfile-pinned bytes. This task plumbs the
pinned version through so lockfile scans actually verify what the lockfile
pins.

CLI-arg-supplied packages MUST continue to get `None` (query latest), since
the user explicitly didn't pin a version. The distinction matters:

- `dep-scan check lodash --registry npm` → `get_metadata("lodash", None)` →
  latest
- `dep-scan check --lockfile package-lock.json` with `lodash@4.17.21` →
  `get_metadata("lodash", Some("4.17.21"))` → the pinned bytes

---

## Unit tests — `PackageRef` propagation in `main.rs::run_check`

### T-078-01: CLI-arg packages produce `PackageRef { version: None }`
- Given `packages = vec!["lodash".into(), "express".into()]` and no
  lockfile path.
- After the lockfile-parse branch, `all_packages` (or its replacement) is
  exactly `[PackageRef { name: "lodash", version: None }, PackageRef { name:
  "express", version: None }]`.

### T-078-02: Cargo.lock entries produce `PackageRef { version: Some(_) }`
- Given a synthetic `Cargo.lock` containing `[[package]] name = "serde"
  version = "1.0.214"` and no CLI args.
- After parsing, `all_packages` contains a `PackageRef` with
  `name: "serde"`, `version: Some("1.0.214")`.

### T-078-03: package-lock.json entries produce `PackageRef { version: Some(_) }`
- Given a synthetic `package-lock.json` with one dependency
  `lodash` at `4.17.21`.
- After parsing, the corresponding `PackageRef` has
  `version: Some("4.17.21")`.

### T-078-04: requirements.txt with `==` pin produces `Some(_)`
- Given `requirements.txt` with `requests==2.31.0`.
- Result: `PackageRef { name: "requests", version: Some("2.31.0") }`.

### T-078-05: requirements.txt with bare name produces `None`
- Given `requirements.txt` with a bare `pytest` (no version specifier).
- Result: `PackageRef { name: "pytest", version: None }` — the package is
  not actually pinned, so querying latest is correct.

### T-078-06: requirements.txt with `>=` constraint produces `None`
- Given `requirements.txt` with `flask>=2.0`.
- Result: `PackageRef { name: "flask", version: None }` — `>=` is a
  constraint, not a pin. (Matches existing
  `lockfile::parse_requirements_txt` behavior of leaving version empty in
  this case.)

### T-078-07: go.sum entries produce `PackageRef { version: Some(_) }`
- Given a synthetic `go.sum` with `github.com/gin-gonic/gin v1.9.1 h1:…`.
- Result: `PackageRef { name: "github.com/gin-gonic/gin", version:
  Some("v1.9.1") }`.

---

## Integration tests — scan flow uses the propagated version

### T-078-08: Crates registry receives the pinned version
- Spin up a wiremock server. CLI: `dep-scan check --lockfile <synthetic
  Cargo.lock with serde@1.0.0> --lockfile-type crates --json`.
- The recorded mock request URL contains `/crates/serde/1.0.0` (or
  equivalent endpoint with the pinned version), NOT
  `/crates/serde` (latest-resolution path).

### T-078-09: npm registry receives the pinned version
- Wiremock again. CLI: `dep-scan check --lockfile <synthetic
  package-lock.json with lodash@4.17.20> --lockfile-type npm --json`.
- The mock request URL is for `lodash` and the version `4.17.20` is the
  one whose metadata is consumed.

### T-078-10: PyPI registry receives the pinned version
- Wiremock. CLI: `dep-scan check --lockfile <synthetic requirements.txt
  with requests==2.31.0> --lockfile-type pypi --json`.
- The mock receives a request whose URL targets `pypi/requests/2.31.0`
  (not just `pypi/requests/json`).

### T-078-11: Go proxy receives the pinned version
- Wiremock. CLI: `dep-scan check --lockfile <synthetic go.sum with
  github.com/x/y v1.0.0>`.
- The mock receives a request targeting
  `/github.com/x/y/@v/v1.0.0.info` (not `@latest`).

### T-078-12: CLI-arg scan still queries latest
- Wiremock. CLI: `dep-scan check serde --registry crates --json`.
- The mock receives a request to the latest-version endpoint, NOT a
  specific-version endpoint. Confirms no regression of the CLI-arg path.

---

## Verbose-output assertions

### T-078-13: Verbose log line includes version when known
- CLI: `dep-scan check --lockfile <Cargo.lock with serde@1.0.214>
  --lockfile-type crates --verbose`.
- Stderr contains `Checking serde@1.0.214 on crates...`.

### T-078-14: Verbose log line omits version when unknown
- CLI: `dep-scan check serde --registry crates --verbose`.
- Stderr contains `Checking serde on crates...` — no `@<version>` suffix
  (since no version was pinned).

---

## Dog-food integration (closes T-067-08)

### T-078-15: Dog-food scan against current main has zero block verdicts
- `cargo build --release`
- `./target/release/dep-scan check --lockfile Cargo.lock --lockfile-type
  crates --json > /tmp/dogfood.json`
- `jq '.packages[] | select(.result == "block")' /tmp/dogfood.json`
  returns empty.
- This is the same assertion T-067-08 makes; after task 078 lands the
  coverage-tracker row 067 goes back to `10/10 | ✅`.

### T-078-16: Dog-food scan reports the pinned versions in JSON output
- For at least three packages from `/tmp/dogfood.json`, the `version`
  field matches what `Cargo.lock` pins (cross-checked manually or via a
  small jq script). No package's reported version is the registry's
  current latest if Cargo.lock pins something different.

---

## Spec-doc sync

### T-078-17: behaviors.md B-004 updated
- `docs/spec/behaviors.md` B-004 contains a clause stating that for
  lockfile-driven scans, the resolved version is the **pinned** version
  from the lockfile (not registry latest), and that CLI-arg scans
  continue to use latest.

### T-078-18: No regressions
- `cargo test` (the full suite) reports ≥788 passing tests after the
  change.
- `cargo clippy --all-targets --all-features -- -D warnings` exit 0.
- `cargo fmt --check` exit 0.
- `cargo audit` exit 0.

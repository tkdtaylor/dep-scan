# Test Spec — Task 023: Lockfile parser

## Unit tests (src/lockfile.rs)

### T-023-01: Parse package-lock.json
- Input: realistic package-lock.json with express, lodash, debug
- Expected: Vec with 3 entries, each (name, version, RegistryType::Npm)

### T-023-02: Parse requirements.txt
- Input: "requests==2.31.0\nflask==3.0.0\n# comment\n-r other.txt\n"
- Expected: Vec with 2 entries (requests, flask), comments and flags skipped

### T-023-03: Parse Cargo.lock
- Input: realistic Cargo.lock with [[package]] entries
- Expected: Vec with entries, each (name, version, RegistryType::Crates)

### T-023-04: Parse go.sum
- Input: "github.com/gin-gonic/gin v1.9.1 h1:abc=\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n"
- Expected: Vec with 1 entry (deduplicated), RegistryType::Go

### T-023-05: Auto-detect format from filename
- "package-lock.json" → Npm
- "requirements.txt" → PyPI
- "Cargo.lock" → Crates
- "go.sum" → Go

### T-023-06: --lockfile-type override
- File named "deps.txt" with --lockfile-type=pypi
- Expected: parsed as requirements.txt format

### T-023-07: Malformed input returns error
- Invalid JSON for package-lock.json
- Expected: clear error message

### T-023-08: Empty lockfile returns empty Vec
- Expected: Ok(vec![])

## Integration tests

### T-023-09: check --lockfile with real fixture
- Create temp requirements.txt with known packages
- Run: dep-scan check --lockfile <path> (with wiremock)
- Expected: scans all packages from file

### T-023-10: check --lockfile combined with explicit packages
- dep-scan check --lockfile reqs.txt extra-pkg --registry pypi
- Expected: scans both lockfile packages and extra-pkg

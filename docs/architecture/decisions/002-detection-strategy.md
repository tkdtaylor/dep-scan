# ADR 002 — v0.2 detection strategy and external data sources

**Status:** Accepted
**Date:** 2026-04-02

## Context

dep-scan v0.1 ships with a single detection mechanism: minimum package age policy. v0.2 adds four more detectors:

1. **Install script analysis** — detect malicious postinstall scripts (npm), setup.py (PyPI), build.rs (cargo)
2. **Typosquatting detection** — flag packages whose names are suspiciously similar to popular ones
3. **Maintainer/ownership change detection** — flag packages where maintainers changed recently
4. **Known vulnerability check** — flag packages with published CVEs

Research into three existing tools (agent-security-scanner-mcp, Semgrep MCP, VulnMCP) informed this decision. See the reference memory for full findings.

## Constraints

- **No paid subscriptions.** All external data sources must be free and publicly accessible.
- **No new runtime dependencies.** dep-scan ships as a single Rust binary. No Python, Node.js, or other runtimes required at runtime.
- **Optional integrations only.** Tools like Semgrep may be invoked if the user has them installed, but dep-scan must function fully without them.
- **Local-first.** Network calls happen only when the user explicitly runs a scan. Cached data must be usable offline.

## Decision

### 1. Known vulnerability check — OSV.dev batch API (direct integration)

Use the OSV.dev batch query API as the primary vulnerability data source.

- **Endpoint:** `POST https://api.osv.dev/v1/querybatch`
- **Cost:** Free, no API key required, no rate limit published (be respectful)
- **Coverage:** npm, PyPI, crates.io, Go, RubyGems, and more
- **Batch size:** Up to 1,000 packages per request
- **Cache:** Store results in local SQLite with a configurable TTL (default 24h)

**Why OSV.dev over NVD/CISA KEV/EPSS:**
- OSV.dev is ecosystem-native — queries by package name + version, not CVE ID
- No API key signup required
- Covers all our target ecosystems in one API
- NVD requires a free API key (extra setup friction) and queries by CVE ID (requires a mapping step)
- CISA KEV and EPSS are enrichment sources — useful for severity scoring but not for discovery

**Deferred:** NVD/CISA KEV/EPSS enrichment can be added later as optional severity scoring. All three are free public APIs but add complexity without improving detection coverage.

### 2. Typosquatting detection — bloom filters + edit distance (built-in)

Build typosquatting detection in two layers:

**Layer 1: Package existence check (bloom filter)**
- Download and cache package name lists for each ecosystem (npm, PyPI)
- Build bloom filters in Rust (use the `bloomfilter` crate or similar)
- Check whether a scanned package name is a known real package vs. a potential impostor
- Inspired by agent-security-scanner-mcp's approach, but built natively in Rust

**Layer 2: Edit distance against popular packages**
- Maintain a curated list of popular packages per ecosystem (top 500–1,000 by downloads)
- Compute normalized Levenshtein distance, with additional heuristics:
  - Keyboard proximity weighting (e.g., `lodas` vs `lodash`)
  - Common prefix/suffix manipulation (`-js`, `-node`, `python-`, `py-`)
  - Character transposition and repetition
- Flag packages within configurable distance threshold

**Why not reuse agent-security-scanner-mcp's data directly:**
- Their bloom filter JSON is serialized with a JS-specific library — not portable
- Their typosquatting check is shallow (~200 hardcoded names, plain Levenshtein)
- Their raw package name `.txt` files could seed our bloom filters, but we can also fetch fresh lists from registries directly

### 3. Install script analysis — built-in pattern matching, optional Semgrep

**Built-in (no external dependencies):**
- Extract and inspect install-time scripts from package metadata:
  - npm: `scripts.preinstall`, `scripts.postinstall`, `scripts.install` in package.json
  - PyPI: `setup.py`, `setup.cfg` `[options.entry_points]`
  - Cargo: `build.rs`
- Pattern match against known malicious indicators:
  - `eval()`, `exec()`, `child_process`, `subprocess`, `os.system`
  - Base64/hex-encoded strings above a length threshold
  - HTTP/HTTPS URLs in install scripts (potential exfiltration)
  - Environment variable reads (`process.env`, `os.environ`) in install context
  - Obfuscation patterns (string concatenation to build URLs, char code assembly)

**Optional Semgrep integration (user must install Semgrep separately):**
- If `semgrep` binary is on `$PATH`, offer a `--deep-scan` flag
- Invoke `semgrep scan --json --config <our-custom-rules>` on extracted scripts
- Ship custom Semgrep rules in a `rules/` directory targeting supply chain patterns
- Graceful degradation: if Semgrep not available, fall back to built-in patterns only

**Why not depend on Semgrep:**
- Adds a Python runtime dependency — violates single-binary constraint
- The built-in patterns catch the most common attack vectors
- Semgrep adds value for sophisticated obfuscation but is not essential for v0.2

### 4. Maintainer/ownership change detection — registry API diffing (original)

No prior art found in the researched tools. Build from scratch:

- On first scan of a package, record its maintainer list in the local cache
- On subsequent scans, compare against the cached list
- Flag if maintainers were added/removed since last scan
- Additional heuristic: if a package has only 1 maintainer and that maintainer's account is newer than the package itself, flag for review
- Data source: same registry APIs already used in v0.1 (npm, PyPI)

### 5. Dependency confusion detection — simple heuristics (ported)

Port the heuristics from agent-security-scanner-mcp:

- Flag packages with internal-looking names (`internal-*`, `private-*`, `@company/*` scoped names)
- Configurable list of internal namespace prefixes in `.dep-scan.toml`
- Warn if a public registry has a package matching an internal namespace pattern

## Implementation order

| Priority | Feature | Complexity | External dependency |
|----------|---------|-----------|-------------------|
| 1 | Known vulnerability check (OSV.dev) | Medium | OSV.dev API (free, no key) |
| 2 | Install script analysis (built-in) | Medium | None |
| 3 | Typosquatting detection | High | Package name lists (free, public) |
| 4 | Maintainer change detection | Medium | Registry APIs (already integrated) |
| 5 | Dependency confusion heuristics | Low | None |
| 6 | Semgrep integration (optional) | Low | Semgrep CLI (user-provided) |

## Consequences

- dep-scan remains a single Rust binary with no runtime dependencies
- All external data sources are free and publicly accessible
- Network calls only happen during explicit scans; all results are cached locally
- Semgrep integration is opt-in and degrades gracefully
- The bloom filter database will need periodic refresh — add a `dep-scan update` command
- NVD/CISA KEV/EPSS enrichment is deferred to v0.3 as optional severity scoring

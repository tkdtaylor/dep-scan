# Test Spec — Task 020: Popular package lists for crates.io + Go

## Unit tests

### T-020-01: POPULAR_CRATES contains expected entries
- List includes "serde", "tokio", "clap", "reqwest", "anyhow"
- List has >= 100 entries

### T-020-02: POPULAR_GO contains expected entries
- List includes entries with "gin", "mux", "testify"
- List has >= 100 entries

### T-020-03: Crate typosquat detected
- Package "srde" → warns about "serde"
- Package "tokoi" → warns about "tokio"

### T-020-04: Real crate name passes
- Package "serde" → Pass

### T-020-05: Go module typosquat detected
- Package "github.com/gin-gonic/gn" → warns about gin
- Uses last path segment normalization

### T-020-06: Real Go module passes
- Package with last segment matching a popular Go package → Pass

### T-020-07: Go path segment extraction
- "github.com/gin-gonic/gin" → extract "gin" for comparison

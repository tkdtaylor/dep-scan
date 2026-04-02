# Test Spec — Task 013: Typosquatting detection

## Unit tests (edit distance engine)

### T-013-01: Identical strings have distance 0
- "lodash" vs "lodash" → 0.0

### T-013-02: Single character difference
- "lodash" vs "lodas" → small normalized distance

### T-013-03: Transposition detected
- "lodash" vs "loadsh" → small distance

### T-013-04: Completely different strings have high distance
- "lodash" vs "express" → high normalized distance

### T-013-05: Affix normalization
- "lodash-js" normalized to "lodash" before comparison

## Unit tests (TyposquattingPolicy)

### T-013-06: Known popular package passes
- Package name "lodash" (IS in popular list)
- Expected: Pass

### T-013-07: Typosquat of popular package warns
- Package name "loadsh" (close to "lodash")
- Expected: Warn with message mentioning "lodash"

### T-013-08: Very close typosquat blocks
- Package name "1odash" (1 char, edit distance 1)
- Expected: Block

### T-013-09: Unrelated package name passes
- Package name "my-unique-lib-xyz"
- Expected: Pass

### T-013-10: PyPI typosquat detected
- Package name "reqests" (close to "requests")
- Expected: Warn or Block mentioning "requests"

### T-013-11: Configurable thresholds
- Custom warn_threshold = 0.3 (very permissive)
- Package "lodas" → should pass with permissive threshold

# Test Spec — Task 013: Typosquatting detection

## Unit tests (edit distance engine — src/typosquat.rs)

### T-013-01: Identical strings have distance 0
- `normalized_levenshtein("lodash", "lodash")` returns 0.0

### T-013-02: Single character difference
- `normalized_levenshtein("lodash", "lodas")` returns a small positive value
- Specifically: raw distance 1, normalized = 1/6 ~ 0.167

### T-013-03: Transposition detected
- `normalized_levenshtein("lodash", "loadsh")` returns a small distance
- Raw distance is 2 (swap a/d), normalized = 2/6 ~ 0.333

### T-013-04: Completely different strings have high distance
- `normalized_levenshtein("lodash", "express")` returns value > 0.7

### T-013-05: Affix normalization
- `normalize_package_name("lodash-js")` returns "lodash"
- `normalize_package_name("lodash-node")` returns "lodash"
- `normalize_package_name("python-requests")` returns "requests"
- `normalize_package_name("py-requests")` returns "requests"
- `normalize_package_name("requests-python")` returns "requests"
- `normalize_package_name("lodash")` returns "lodash" (no affix)

### T-013-05b: find_closest_match returns best match within threshold
- `find_closest_match("loadsh", &["lodash", "express", "react"], 0.5)` returns Some(("lodash", distance))
- `find_closest_match("zzzzzzzzz", &["lodash", "express"], 0.3)` returns None

### T-013-05c: Empty strings edge case
- `normalized_levenshtein("", "")` returns 0.0
- `normalized_levenshtein("", "abc")` returns 1.0
- `normalized_levenshtein("abc", "")` returns 1.0

## Unit tests (TyposquattingPolicy — src/policy/typosquatting.rs)

### T-013-06: Known popular package passes
- Package name "lodash" (IS in popular list)
- Expected: PolicyResult::Pass

### T-013-07: Typosquat of popular package warns
- Package name "loadsh" (distance to "lodash" > block_threshold, < warn_threshold)
- Expected: PolicyResult::Warn with message mentioning "lodash"

### T-013-08: Very close typosquat blocks
- Package name "1odash" (distance to "lodash" = 1/6 ~ 0.167, which is <= block_threshold when set appropriately)
- With default thresholds (block=0.08, warn=0.15), a single char substitution on a 6-char name gives distance ~0.167 which is a warn
- Adjust: test with block_threshold=0.2 or use a longer popular package name to get distance below 0.08
- Alternative: use "expresss" vs "express" (1/7 ~ 0.143) with block_threshold=0.15

### T-013-09: Unrelated package name passes
- Package name "my-unique-lib-xyz"
- Expected: PolicyResult::Pass

### T-013-10: PyPI typosquat detected
- Package name "reqests" (close to "requests")
- Expected: Warn or Block mentioning "requests"

### T-013-11: Configurable thresholds
- Custom thresholds: warn=0.01, block=0.005 (very strict, almost nothing triggers)
- Package "loadsh" with these thresholds → Pass (distance too high for strict thresholds)

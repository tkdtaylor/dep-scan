# Test Spec — Task 008: Minimum package age policy

## Unit tests

### T-008-01: Package older than min_age passes
- Setup: AgePolicy with min_age = 48h, package published 72h ago
- Expected: PolicyResult::Pass

### T-008-02: Package younger than min_age is blocked
- Setup: AgePolicy with min_age = 48h, package published 1h ago
- Expected: PolicyResult::Block with reason mentioning age

### T-008-03: Package exactly at threshold passes
- Setup: AgePolicy with min_age = 48h, package published exactly 48h ago
- Expected: PolicyResult::Pass (>= threshold passes)

### T-008-04: Missing published_at date warns
- Setup: AgePolicy with min_age = 48h, package with published_at = None
- Expected: PolicyResult::Warn with reason mentioning missing date

### T-008-05: Zero min_age means everything passes
- Setup: AgePolicy with min_age = 0h, package published 1 second ago
- Expected: PolicyResult::Pass

### T-008-06: Custom min_age is respected
- Setup: AgePolicy with min_age = 168h (1 week), package published 3 days ago
- Expected: PolicyResult::Block

### T-008-07: Block message includes package name and age
- Setup: AgePolicy with min_age = 48h, package published 1h ago
- Expected: Block reason includes package name and actual age

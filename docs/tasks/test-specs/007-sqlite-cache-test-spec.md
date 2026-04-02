# Test Spec — Task 007: SQLite hash cache

## Unit tests (in-memory SQLite)

### T-007-01: Cache::new creates table
- Create Cache with `:memory:`
- Expected: no error, table exists

### T-007-02: Insert and lookup
- Insert entry (name="lodash", version="4.17.21", registry="npm", result="pass")
- Lookup same key
- Expected: returns the inserted result

### T-007-03: Lookup miss returns None
- Lookup non-existent entry
- Expected: None

### T-007-04: Insert upserts on conflict
- Insert entry, then insert again with different result
- Lookup
- Expected: returns the updated result

### T-007-05: Invalidate removes entry
- Insert entry, invalidate it, lookup
- Expected: None

### T-007-06: Invalidate non-existent is no-op
- Invalidate non-existent entry
- Expected: no error

### T-007-07: Clear removes all entries
- Insert multiple entries, clear, lookup each
- Expected: all return None

### T-007-08: Different registries are distinct keys
- Insert (name="foo", version="1.0", registry="npm", result="pass")
- Insert (name="foo", version="1.0", registry="pypi", result="block")
- Lookup each
- Expected: returns respective results

### T-007-09: Cache::new is idempotent
- Create Cache, insert entry, drop, create again on same path
- Expected: entry still exists (persistent)

### T-007-10: scanned_at is set on insert
- Insert entry, lookup
- Expected: scanned_at is a valid timestamp

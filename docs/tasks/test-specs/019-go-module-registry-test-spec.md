# Test Spec — Task 019: Go module proxy client

## Unit tests (wiremock)

### T-019-01: Fetch metadata for existing module
- wiremock serves /@v/list with "v1.9.1\nv1.9.0" and /@v/v1.9.1.info with version+time
- Expected: correct name, version="v1.9.1", published_at from Time field

### T-019-02: Module not found returns NotFound
- wiremock returns 404 for /@v/list
- Expected: RegistryError::NotFound

### T-019-03: Gone (410) returns NotFound
- wiremock returns 410
- Expected: RegistryError::NotFound

### T-019-04: Module path is URL-encoded
- Module "github.com/gin-gonic/gin" → request path "/github.com/gin-gonic/gin/@v/list"
- Verify wiremock receives correct path

### T-019-05: Empty version list returns NotFound
- wiremock returns 200 with empty body for /@v/list
- Expected: RegistryError::NotFound or metadata with no version

### T-019-06: Custom base URL is used
- wiremock on custom port
- Expected: request hits wiremock

### T-019-07: Maintainers and downloads are None
- Expected: metadata.maintainers is empty, downloads is None

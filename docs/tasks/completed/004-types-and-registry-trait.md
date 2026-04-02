# Task 004 — Package metadata types + registry trait

**Status:** backlog
**Depends on:** 003

## Objective

Define the shared data types (PackageMetadata) and the async Registry trait that all registry clients will implement.

## Acceptance criteria

- [ ] src/types.rs: `PackageMetadata` struct (name, version, description, published_at, maintainers, downloads, repository_url)
- [ ] src/registry/mod.rs: `Registry` async trait with `async fn get_metadata(&self, name: &str, version: Option<&str>) -> Result<PackageMetadata, RegistryError>`
- [ ] `RegistryType` enum: Npm, PyPI (extensible for future Cargo, Go)
- [ ] `RegistryError` with thiserror: NotFound, RateLimited, NetworkError, ParseError
- [ ] Types derive appropriate traits (Debug, Clone, Serialize, Deserialize where needed)
- [ ] All tests pass, clippy clean, fmt clean

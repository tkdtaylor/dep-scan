//! VCS (git) source handling — ADR 008.
//!
//! [`fetch`] holds the sandboxed, read-only fetch client (task 096) that
//! retrieves a repository at a pinned ref into an ephemeral, isolated working
//! area for static analysis, without ever executing code from the repository.

pub mod fetch;

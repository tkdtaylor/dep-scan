// SPDX-License-Identifier: Apache-2.0
//! VCS (git) source handling — ADR 008.
//!
//! [`fetch`] holds the sandboxed, read-only fetch client (task 096) that
//! retrieves a repository at a pinned ref into an ephemeral, isolated working
//! area for static analysis, without ever executing code from the repository.
//!
//! [`manifest`] holds the manifest edge reader (task 101, ADR 009 Decision 1
//! manifest-fallback): reads direct dependency edges from an already-fetched
//! [`fetch::FetchedTree`] without any additional network I/O.

pub mod fetch;
pub mod manifest;

#![forbid(unsafe_code)]

//! Memory-dump mounting (the `MemProcFS` / `MemNixFS` paradigm): a second
//! `ForensicFs` provider backed by memf's analysis library, exposing a memory
//! dump's `proc/`, `sys/`, and `forensic/` views as a browsable filesystem.
//!
//! See `docs/plans/2026-06-25-memory-dump-mounting.md`. This module is built
//! only under the `memory` feature. Phase 0 extracted memf's analysis bootstrap
//! into the `memf-session` library crate so 4n6mount can drive it headlessly;
//! later phases add the synthetic tree and lazy artifact rendering.

pub mod inode;
pub mod memoryfs;

#[cfg(test)]
mod smoke {
    /// Phase-1 Task 1.1 smoke test: the memf analysis library surface — the
    /// universal format opener and the extracted bootstrap — is reachable as a
    /// library dependency (not the CLI). This is the seam the memory provider
    /// builds on.
    #[test]
    fn memf_library_surface_in_scope() {
        // memf-session (Phase 0 extraction) links and its types are usable.
        assert_eq!(memf_session::OsProfile::Windows.to_string(), "Windows");
        // memf-format's universal dump opener is linkable as a function item.
        let _open = memf_format::open_dump;
    }
}

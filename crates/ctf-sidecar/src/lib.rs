//! ctf-sidecar — spawn helper binaries (yafu, tiny python glue) with timeouts
//! and manifest-pinned checksums.
//!
//! Capability coverage: sidecar execution for domains 3/19 (factoring, later
//! SMT). No unsafe code.

pub mod bkcrack;
pub mod manifest;
pub mod spawn;
pub mod yafu;

pub use manifest::SidecarManifest;

//! PUBG SDK + offset management.
//!
//! Strategy: external offset dumper service publishes JSON (build_id + table).
//! Cheat fetches at startup, caches locally, refreshes on game version mismatch.

pub mod offsets;
pub mod uworld;
pub mod player;
pub mod dumper;

pub use offsets::Offsets;
pub use dumper::{DumpResult, Pattern, Resolver, SigDef, Tok};

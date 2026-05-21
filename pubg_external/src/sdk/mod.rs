//! SDK module aggregator. PUBG-specific layout lives in `pubg_offsets`.

pub mod uworld;
pub mod player;
pub mod dumper;
pub mod pubg_offsets;
pub mod xenuine;

pub use dumper::{DumpResult, Pattern, Resolver, SigDef, Tok};
pub use pubg_offsets::PubgOffsets;

/// Project-wide alias. PUBG is the live target so the typed `Offsets` view
/// is the PUBG one. Lyra-Stage-2 (sig-scan path) uses `dumper::DumpResult`
/// directly without a typed wrapper.
pub type Offsets = PubgOffsets;

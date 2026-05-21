//! Offset table for PUBG (TslGame.exe / UE4 family).
//!
//! Two layers:
//!
//! 1. **Class field offsets** — stable across most PUBG patches because they
//!    derive from the engine's UStruct layout. Sourced from the public
//!    `Quebeux/PUBG-OFFSETS` mirror of the TJ888 SDK dump (UE 4.x family with
//!    PUBG modifications). When PUBG ships a UE engine bump, recompute via
//!    `Dumper.exe` against the new build and update these numbers.
//!
//! 2. **Engine global VAs** — `GWorld`, `GNames`, `GObjects` — change every
//!    patch (and within a build, ASLR-relocated). Resolved at runtime via
//!    `sdk::dumper` sig-scans driven by the UE4-generic patterns in
//!    `engine_sigs()` below. Result is cached to `ofs.bin` keyed on the live
//!    image's `IMAGE_NT_HEADERS.FileHeader.TimeDateStamp`.
//!
//! Sigs are PUBG-volatile (BE/PUBG ship custom obfuscation passes on every
//! few patches). When a sig misses, dump fresh from the live binary in IDA
//! and replace.

use crate::hv_pipe::{Session, Target};
use crate::sdk::dumper::{self, DumpResult, Resolver, SigDef};
use anyhow::{anyhow, Context, Result};

// =====================================================================
//  Class field offsets (UE4 + PUBG modifications)
// =====================================================================

// AActor (size ~0x3B0 for UE 4.18-era PUBG)
pub const AACTOR_ROOT_COMPONENT: u32 = 0x0188;
pub const AACTOR_INSTIGATOR: u32 = 0x0170;

// USceneComponent
pub const USCENECOMP_RELATIVE_LOCATION: u32 = 0x02D0;
pub const USCENECOMP_RELATIVE_ROTATION: u32 = 0x02DC;
pub const USCENECOMP_COMPONENT_VELOCITY: u32 = 0x0348;

// AController -> APawn -> ACharacter
pub const ACONTROLLER_PAWN: u32 = 0x03B8;
pub const ACONTROLLER_PLAYER_STATE: u32 = 0x03D0;
pub const ACONTROLLER_CONTROL_ROTATION: u32 = 0x03E0;

pub const APAWN_PLAYER_STATE: u32 = 0x03D0;
pub const APAWN_CONTROLLER: u32 = 0x03E8;

pub const ACHARACTER_MESH: u32 = 0x0410;
pub const ACHARACTER_CHARACTER_MOVEMENT: u32 = 0x0418;
pub const ACHARACTER_CAPSULE_COMPONENT: u32 = 0x0420;

// APlayerController
pub const APLAYER_CONTROLLER_PLAYER: u32 = 0x0418;
pub const APLAYER_CONTROLLER_ACK_PAWN: u32 = 0x0428;
pub const APLAYER_CONTROLLER_CAMERA_MGR: u32 = 0x0448;

// APlayerState
pub const APLAYERSTATE_SCORE: u32 = 0x03B0;
pub const APLAYERSTATE_PING: u32 = 0x03B4;
pub const APLAYERSTATE_PLAYER_NAME: u32 = 0x03B8;
pub const APLAYERSTATE_PLAYER_ID: u32 = 0x03D8;

// AGameStateBase
pub const AGAMESTATE_PLAYER_ARRAY: u32 = 0x03C8;

// UGameInstance
pub const UGAMEINSTANCE_LOCAL_PLAYERS: u32 = 0x0038;

// UPlayer / ULocalPlayer
pub const UPLAYER_PLAYER_CONTROLLER: u32 = 0x0030;
pub const ULOCALPLAYER_VIEWPORT_CLIENT: u32 = 0x0058;

// UGameViewportClient
pub const UVIEWPORTCLIENT_WORLD: u32 = 0x0080;
pub const UVIEWPORTCLIENT_GAME_INSTANCE: u32 = 0x0088;

// UWorld
pub const UWORLD_PERSISTENT_LEVEL: u32 = 0x0030;
pub const UWORLD_OWNING_GAME_INSTANCE: u32 = 0x0140;
pub const UWORLD_GAME_STATE: u32 = 0x00F8;
pub const UWORLD_LEVELS: u32 = 0x0110;

// ULevel
pub const ULEVEL_OWNING_WORLD: u32 = 0x00C0;
// ULevel.Actors is a TArray<AActor*> embedded near offset 0x98 in the dump
// (TArray data ptr + count + slack). Use the engine-typical pair below; if
// PUBG bumps engine, re-derive against UnknownData00 boundary.
pub const ULEVEL_ACTORS_PTR: u32 = 0x0098;
pub const ULEVEL_ACTORS_COUNT: u32 = 0x00A0;

// USkeletalMeshComponent (mesh tree for bones)
pub const USKELMESH_COMPONENT_TO_WORLD: u32 = 0x01F0; // FTransform
pub const USKELMESH_BONE_ARRAY: u32 = 0x0B60;         // CachedBoneSpaceTransforms

// APlayerCameraManager
pub const APCM_CAMERA_CACHE: u32 = 0x0420;
pub const APCM_DEFAULT_FOV: u32 = 0x03C8;

// =====================================================================
//  Sig-resolved engine globals
// =====================================================================

/// Stable name keys for engine globals stored in `Offsets::engine`.
pub const SIG_GWORLD: &str = "GWorld";
pub const SIG_GNAMES: &str = "GNames";
pub const SIG_GOBJECTS: &str = "GObjects";

/// UE4-generic sig templates. PUBG/BE may obfuscate; replace per patch.
///
/// `GWorld`: `mov rax, [rip+disp32]` callsite — the canonical 7-byte
/// `48 8B 05 ?? ?? ?? ??` shape. `RipRel32 { off: 3 }` resolves to the global.
///
/// `GNames`: `lea reg, [rip+disp32]` against the FName pool — same RIP-rel
/// math, varying initial `lea` opcode (`48 8D 05`). Some PUBG builds replace
/// with `4C 8D 05`; both forms supplied below.
///
/// `GObjects`: `mov reg64, [rip+disp32]` against UObject array — same shape.
///
/// Each sig is preceded by a 1-byte instruction signature so we don't false-
/// match on every `48 8B 05` in `.text`. Tweak after running once vs the
/// live target — leave the loosest sig that produces exactly one match.
pub fn engine_sigs() -> Vec<SigDef> {
    vec![
        // Loose first cut. Tighten with surrounding context after first
        // run if `match_count > 1`.
        SigDef::new(
            SIG_GWORLD,
            "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9",
            Resolver::RipRel32 { off: 3 },
        )
        .expect("static GWorld sig"),
        SigDef::new(
            SIG_GNAMES,
            "48 8D 05 ? ? ? ? 48 89 03 48 8D 4B 08",
            Resolver::RipRel32 { off: 3 },
        )
        .expect("static GNames sig"),
        SigDef::new(
            SIG_GOBJECTS,
            "48 8B 05 ? ? ? ? 48 8B 0C C8 48 8D 04 D1 EB",
            Resolver::RipRel32 { off: 3 },
        )
        .expect("static GObjects sig"),
    ]
}

/// High-level offset bundle, populated from the dumper.
#[derive(Debug, Clone)]
pub struct Offsets {
    /// Build identity (TimeDateStamp from PE header).
    pub build_id: u32,
    /// Sig-resolved engine globals.
    pub gworld: u64,
    pub gnames: u64,
    pub gobjects: u64,
}

impl Offsets {
    /// Resolve engine globals against the live target via the dumper.
    /// Cache file is `ophion_dump_<exe>.bin` under `%LOCALAPPDATA%\...\WER\Temp\`.
    pub fn resolve(session: &Session, target: &Target, exe_name: &str) -> Result<Self> {
        let cache = format!("ophion_dump_{}.bin", exe_name.replace('.', "_"));
        let sigs = engine_sigs();
        let dump = dumper::dump_or_load(session, target, &sigs, &cache)
            .with_context(|| format!("dump_or_load {}", exe_name))?;
        Self::from_dump(&dump)
    }

    pub fn from_dump(d: &DumpResult) -> Result<Self> {
        let g = |k: &str| {
            d.entries
                .get(k)
                .copied()
                .ok_or_else(|| anyhow!("dumper missing {k}"))
        };
        Ok(Self {
            build_id: d.timedate_stamp,
            gworld: g(SIG_GWORLD)?,
            gnames: g(SIG_GNAMES)?,
            gobjects: g(SIG_GOBJECTS)?,
        })
    }
}

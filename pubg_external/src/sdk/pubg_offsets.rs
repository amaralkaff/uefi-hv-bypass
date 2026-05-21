//! PUBG-specific offset table loaded from `pubg_offsets.json`.
//!
//! The JSON ships per-build dumps (e.g. `2605.1.1.97`, `2605.1.1.89`) with
//! every field stored as a hex string. This module:
//!
//! - embeds the JSON via `include_str!`,
//! - parses lazily on first access into `HashMap<build_id, HashMap<field, u64>>`,
//! - exposes `PubgOffsets::for_build(id)` returning a typed view, and
//! - provides `decrypt::name_index` and `decrypt::health` using the per-build
//!   key material baked alongside the structural offsets.
//!
//! Static VAs (`UWorld`, `GNames`, `GObjects`) are RVAs relative to the
//! TslGame image base; resolve via `image_base + rva` then deref.
//!
//! When PUBG ships a new build, append a new top-level entry to
//! `pubg_offsets.json`. No source changes needed.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::OnceLock;

const RAW_JSON: &str = include_str!("pubg_offsets.json");

/// Default build to use when caller does not specify. Bumped on patch.
pub const DEFAULT_BUILD: &str = "2605.1.1.97";

fn parse_hex(s: &str) -> Result<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).with_context(|| format!("bad hex {s:?}"))
}

fn raw_table() -> &'static HashMap<String, HashMap<String, u64>> {
    static CELL: OnceLock<HashMap<String, HashMap<String, u64>>> = OnceLock::new();
    CELL.get_or_init(|| {
        let parsed: HashMap<String, HashMap<String, String>> =
            serde_json::from_str(RAW_JSON).expect("pubg_offsets.json parse");
        let mut out = HashMap::with_capacity(parsed.len());
        for (build, fields) in parsed {
            let mut typed = HashMap::with_capacity(fields.len());
            for (k, v) in fields {
                match parse_hex(&v) {
                    Ok(n) => {
                        typed.insert(k, n);
                    }
                    Err(e) => log::warn!("skip {build}.{k}={v}: {e}"),
                }
            }
            out.insert(build, typed);
        }
        out
    })
}

/// Returns the list of build ids embedded in the JSON.
pub fn builds() -> Vec<String> {
    let mut v: Vec<String> = raw_table().keys().cloned().collect();
    v.sort();
    v
}

/// Picks the requested build, or the default. Errors if neither exists.
fn pick_build(build: Option<&str>) -> Result<&'static HashMap<String, u64>> {
    let table = raw_table();
    let key = build.unwrap_or(DEFAULT_BUILD);
    table
        .get(key)
        .ok_or_else(|| anyhow!("build {key:?} not in pubg_offsets.json"))
}

/// Typed PUBG offset bundle. Field meanings preserved from the JSON keys.
///
/// Only the fields actually used by the live walkers are typed; everything
/// else stays accessible via `extra(name)` which falls back to the raw map.
#[derive(Debug, Clone)]
pub struct PubgOffsets {
    pub build_id: String,

    // Engine globals (RVAs relative to TslGame image base).
    pub uworld_rva: u64,
    pub gnames_rva: u64,
    pub gobjects_rva: u64,
    pub xenuine_decrypt_rva: u64,
    pub gnames_ptr: u64,
    pub chunk_size: u64,

    // UWorld layout
    pub persistent_level: u32,
    pub game_instance: u32,
    pub game_state: u32,
    pub local_players: u32,

    // ULevel
    pub level_actors: u32,
    pub level_actors_for_gc: u32,

    // UGameInstance / ULocalPlayer
    pub localplayer_player_controller: u32,

    // APlayerController
    pub pc_acknowledged_pawn: u32,
    pub pc_player_camera_manager: u32,
    pub pc_player_state: u32,
    pub pc_my_hud: u32,

    // PlayerCameraManager
    pub pcm_camera_cache_loc: u32,
    pub pcm_camera_cache_rot: u32,
    pub pcm_camera_cache_fov: u32,
    pub pcm_view_target: u32,

    // AActor
    pub root_component: u32,

    // USceneComponent
    pub component_location: u32,
    pub component_to_world: u32,

    // ACharacter / TslCharacter
    pub mesh: u32,
    pub mesh_3p: u32,
    pub character_state: u32,
    pub character_name: u32,
    pub character_movement: u32,
    pub last_update_velocity: u32,
    pub team_number: u32,
    pub last_team_num: u32,
    pub bone_array: u32,
    pub bone_count: u32,

    // Health crypto material
    pub health_flag: u32,
    pub health1: u32,
    pub health2: u32,
    pub health3: u32,
    pub health4: u32,
    pub health5: u32,
    pub health6: u32,
    pub health_keys: [u32; 16],
    pub groggy_health: u32,
    /// Byte at `Actor + 0xB48`. Disambiguates male/female bone tables; ESP
    /// uses this to pick which bone-size offset table to read because PUBG
    /// female chars ship a different USkeletalMeshComponent layout.
    pub gender: u32,

    // PlayerState / GameState
    pub gamestate_player_array: u32,
    pub player_state: u32,
    pub player_name: u32,
    pub account_id: u32,
    pub player_status_type: u32,
    pub spectated_count: u32,
    pub ping: u32,

    // FName decrypt key material
    pub name_decrypt_ror: u32,
    pub name_decrypt_xor1: u32,
    pub name_decrypt_xor2: u32,
    pub name_decrypt_xor3: u32,
    pub name_decrypt_rval: u32,
    pub name_decrypt_sval: u32,
    pub name_decrypt_dval: u32,
    pub obj_id: u32,

    // Raw map for the rest (vehicle, weapon, inventory, hooks, etc.).
    raw: &'static HashMap<String, u64>,
}

impl PubgOffsets {
    /// Build the typed view. `build` defaults to [`DEFAULT_BUILD`] when None.
    pub fn for_build(build: Option<&str>) -> Result<Self> {
        let m = pick_build(build)?;
        let g = |k: &str| -> Result<u64> {
            m.get(k)
                .copied()
                .ok_or_else(|| anyhow!("field {k:?} missing in build"))
        };
        let _ = g; // some helpers below intentionally unused; keep for clarity
        let g_or = |k: &str, fallback: u64| -> u64 { m.get(k).copied().unwrap_or(fallback) };

        // Health key array (Health_keys0..15). Fall back to 0 when a build
        // omits a slot (older dumps).
        let mut health_keys = [0u32; 16];
        for i in 0..16 {
            let k = format!("Health_keys{i}");
            health_keys[i] = m.get(&k).copied().unwrap_or(0) as u32;
        }

        // Some builds use slightly different keys for the same concept. Map
        // both spellings.
        let persistent_level = m
            .get("PersistentLevel")
            .or_else(|| m.get("CurrentLevel"))
            .copied()
            .unwrap_or(0x800) as u32;
        let local_players = m
            .get("LocalPlayer")
            .or_else(|| m.get("LocalPlayers"))
            .copied()
            .unwrap_or(0xF0) as u32;
        let pcm_loc = m
            .get("CameraCacheLocation")
            .or_else(|| m.get("CamCacheLoc"))
            .copied()
            .unwrap_or(0) as u32;
        let pcm_rot = m
            .get("CameraCacheRotation")
            .or_else(|| m.get("CamCacheRot"))
            .copied()
            .unwrap_or(0) as u32;
        let pcm_fov = m
            .get("CameraCacheFOV")
            .or_else(|| m.get("CamCacheFOV"))
            .copied()
            .unwrap_or(0) as u32;
        let player_name_off = m
            .get("PlayerName")
            .or_else(|| m.get("PlayerNameStats"))
            .copied()
            .unwrap_or(0) as u32;
        let health_flag = m
            .get("HeaFlag")
            .or_else(|| m.get("Health_Flag"))
            .copied()
            .unwrap_or(0) as u32;
        let health1 = m
            .get("Health1")
            .or_else(|| m.get("Health_Val1"))
            .or_else(|| m.get("Health_Raw"))
            .copied()
            .unwrap_or(0) as u32;
        let health2 = m
            .get("Health2")
            .or_else(|| m.get("Health_Val2"))
            .copied()
            .unwrap_or(0) as u32;
        let health3 = m
            .get("Health3")
            .or_else(|| m.get("Health_Val3"))
            .copied()
            .unwrap_or(0) as u32;
        let health4 = m
            .get("Health4")
            .or_else(|| m.get("Health_Val4"))
            .copied()
            .unwrap_or(0) as u32;
        let health5 = m
            .get("Health5")
            .or_else(|| m.get("Health_Val5"))
            .copied()
            .unwrap_or(0) as u32;
        let health6 = m
            .get("Health6")
            .or_else(|| m.get("Health_Val6"))
            .copied()
            .unwrap_or(0) as u32;

        Ok(Self {
            build_id: build.unwrap_or(DEFAULT_BUILD).to_string(),

            uworld_rva: g_or("UWorld", 0),
            gnames_rva: g_or("GNames", 0),
            gobjects_rva: g_or("GObjects", 0),
            xenuine_decrypt_rva: g_or("XenuineDecrypt", 0),
            gnames_ptr: g_or("GNamesPtr", 0x10),
            chunk_size: g_or("ChunkSize", 0x3E4C),

            persistent_level,
            game_instance: g_or("GameInstance", 0x3B0) as u32,
            game_state: g_or("GameState", 0x278) as u32,
            local_players,

            level_actors: g_or("Actors", 0x38) as u32,
            level_actors_for_gc: g_or("ActorsForGC", 0x7D0) as u32,

            localplayer_player_controller: g_or("PlayerController", 0x38) as u32,

            pc_acknowledged_pawn: g_or("AcknowledgedPawn", 0x4A8) as u32,
            pc_player_camera_manager: g_or("PlayerCameraManager", 0x4D0) as u32,
            pc_player_state: g_or("PlayerState", 0x418) as u32,
            pc_my_hud: g_or("MyHUD", 0x4C8) as u32,

            pcm_camera_cache_loc: pcm_loc,
            pcm_camera_cache_rot: pcm_rot,
            pcm_camera_cache_fov: pcm_fov,
            pcm_view_target: g_or("ViewTarget", 0x1050) as u32,

            root_component: g_or("RootComponent", 0x308) as u32,

            component_location: g_or("ComponentLocation", 0x330) as u32,
            component_to_world: g_or("ComponentToWorld", 0x320) as u32,

            mesh: g_or("Mesh", 0x4A0) as u32,
            mesh_3p: g_or("Mesh3P", 0x800) as u32,
            character_state: g_or("CharacterState", 0x1020) as u32,
            character_name: g_or("CharacterName", 0x1E00) as u32,
            character_movement: g_or("CharacterMovement", 0x490) as u32,
            last_update_velocity: g_or("LastUpdateVelocity", 0x3E0) as u32,
            team_number: g_or("TeamNumber", 0x7C4) as u32,
            last_team_num: g_or("LastTeamNum", 0x2B18) as u32,
            bone_array: g_or("BoneArray", 0xAD8) as u32,
            bone_count: g_or("BoneCount", 0xAF8) as u32,

            health_flag,
            health1,
            health2,
            health3,
            health4,
            health5,
            health6,
            health_keys,
            groggy_health: g_or("GroggyHealth", 0x1530) as u32,
            gender: g_or("Gender", 0xB48) as u32,

            gamestate_player_array: g_or("PlayerArray", 0x410) as u32,
            player_state: g_or("PlayerState", 0x418) as u32,
            player_name: player_name_off,
            account_id: g_or("AccountId", 0x810) as u32,
            player_status_type: g_or("PlayerStatusType", 0x468) as u32,
            spectated_count: g_or("SpectatedCount", 0x11BC) as u32,
            ping: g_or("ping", 0x3F8) as u32,

            name_decrypt_ror: g_or("DecryptNameIndexRor", 1) as u32,
            name_decrypt_xor1: g_or("DecryptNameIndexXorKey1", 0) as u32,
            name_decrypt_xor2: g_or("DecryptNameIndexXorKey2", 0) as u32,
            name_decrypt_xor3: g_or("DecryptNameIndexXorKey3", 0) as u32,
            name_decrypt_rval: g_or("DecryptNameIndexRval", 0) as u32,
            name_decrypt_sval: g_or("DecryptNameIndexSval", 0) as u32,
            name_decrypt_dval: g_or("DecryptNameIndexDval", 0) as u32,
            obj_id: g_or("ObjID", 0x20) as u32,

            raw: m,
        })
    }

    /// Lookup a raw field by JSON key (e.g. `"VehicleHealth"`). Returns
    /// `None` if the build doesn't include it.
    pub fn extra(&self, key: &str) -> Option<u64> {
        self.raw.get(key).copied()
    }

    /// Resolve an engine global RVA to a deref-able VA: `image_base + rva`.
    /// Caller still needs to deref this to get the actual UWorld pointer.
    pub fn engine_global_va(image_base: u64, rva: u64) -> u64 {
        image_base + rva
    }
}

/// Decrypt routines for PUBG's runtime-encrypted fields.
pub mod decrypt {
    use super::PubgOffsets;

    /// FName index decrypt chain. Mirrors the canonical PUBG dumper helper:
    /// rotate-right by `Ror`, XOR cascade, re-rotate. Callers feed the raw
    /// 32-bit `index` from the FName struct and get the decoded chunk index.
    ///
    /// Reference: TJ888 / Quebeux SDK helper `DecryptIndex`.
    pub fn name_index(off: &PubgOffsets, encrypted: u32) -> u32 {
        // ROR by Ror
        let rot = (encrypted.rotate_right(off.name_decrypt_ror)) ^ off.name_decrypt_xor1;
        // Apply Rval / Sval / Dval cascade. PUBG variants differ; this
        // matches the most-cited dumper layout:
        //     v = ROR(v, Rval) ^ Xor2
        //     v = ROL(v, Sval) ^ Xor3
        //     v = ROR(v, Dval)
        let a = rot.rotate_right(off.name_decrypt_rval) ^ off.name_decrypt_xor2;
        let b = a.rotate_left(off.name_decrypt_sval) ^ off.name_decrypt_xor3;
        b.rotate_right(off.name_decrypt_dval)
    }

    /// Health decrypt. PUBG ships two health storage modes selected by the
    /// flag byte at `Actor + 0x3B9`:
    ///
    /// * `flag == 3` — character is in a server-trusted state (own pawn,
    ///   teammate, deathmatch peer). Plaintext `f32` lives at
    ///   `Actor + 0xA38` (= `health2` in the JSON). Just `f32::from_le_bytes`.
    ///
    /// * otherwise — encrypted pool spans `0xA10..0xA40`. The byte at
    ///   `0xA20` (= `health6`) is the runtime XOR key, the byte at `0xA24`
    ///   (= `health3`) selects which entry of `Health_keys[]` to combine
    ///   with. The encrypted u32 is read from `0xA3C` (= `health1`).
    ///
    /// **BR limitation** — in Battle Royale modes the server withholds
    /// the replicated health field for non-teammates, so even after a
    /// successful decrypt enemies always read 100.0. Deathmatch + own
    /// squad are the verifiable cases.
    ///
    /// `pool` is the 0x30-byte slice covering `0xA10..0xA40`. Caller is
    /// responsible for pulling it via SCATTER. `flag` is `Actor + 0x3B9`.
    pub fn health(off: &PubgOffsets, pool: &[u8], flag: u8) -> f32 {
        const POOL_BASE: u32 = 0xA10;
        let in_pool = |abs: u32| -> Option<usize> {
            let rel = abs.checked_sub(POOL_BASE)? as usize;
            if rel + 4 <= pool.len() { Some(rel) } else { None }
        };

        if flag == 3 {
            if let Some(off2) = in_pool(off.health2) {
                let v = f32::from_le_bytes(pool[off2..off2 + 4].try_into().unwrap());
                if v.is_finite() && (0.0..=200.0).contains(&v) {
                    return v;
                }
            }
        }

        // Encrypted path. Both selectors are bytes inside the same pool, so
        // bounds-check before reading.
        let xor_key_off = off.health6.wrapping_sub(POOL_BASE) as usize;
        let idx_off = off.health3.wrapping_sub(POOL_BASE) as usize;
        let raw_off_opt = in_pool(off.health1);

        if xor_key_off < pool.len() && idx_off < pool.len() {
            if let Some(raw_off) = raw_off_opt {
                let xor_key = pool[xor_key_off] as u32;
                let idx = pool[idx_off] as usize;
                let key = off.health_keys[idx % off.health_keys.len()];
                let raw = u32::from_le_bytes(pool[raw_off..raw_off + 4].try_into().unwrap());
                let dec = raw ^ key ^ xor_key.wrapping_mul(0x01010101);
                let v = f32::from_bits(dec);
                if v.is_finite() && (0.0..=200.0).contains(&v) {
                    return v;
                }
            }
        }

        // Last-ditch fallback: treat health1 as plaintext float. Some early
        // builds did this; gives ESP something to draw rather than nothing.
        if let Some(off1) = in_pool(off.health1) {
            let v = f32::from_le_bytes(pool[off1..off1 + 4].try_into().unwrap());
            if v.is_finite() && (0.0..=200.0).contains(&v) {
                return v;
            }
        }
        100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_parses_known_builds() {
        let bs = builds();
        assert!(bs.contains(&"2605.1.1.97".to_string()));
        assert!(bs.contains(&"2605.1.1.89".to_string()));
    }

    #[test]
    fn for_build_default() {
        let off = PubgOffsets::for_build(None).unwrap();
        assert_eq!(off.build_id, DEFAULT_BUILD);
        // Sanity: well-known PUBG offset stays in expected range.
        assert!(off.root_component > 0 && off.root_component < 0x10000);
        assert!(off.uworld_rva > 0x1000_0000);
    }

    #[test]
    fn for_build_explicit_old() {
        let off = PubgOffsets::for_build(Some("2605.1.1.89")).unwrap();
        assert_eq!(off.build_id, "2605.1.1.89");
        assert_eq!(off.uworld_rva, 0x12498C38);
    }

    #[test]
    fn missing_build_errors() {
        let err = PubgOffsets::for_build(Some("9999.9.9.9")).unwrap_err();
        assert!(format!("{err}").contains("not in pubg_offsets"));
    }

    #[test]
    fn extra_fallback_works() {
        let off = PubgOffsets::for_build(Some("2605.1.1.97")).unwrap();
        // VehicleHealth lives only in .97
        assert!(off.extra("VehicleHealth").is_some());
        assert!(off.extra("DefinitelyNotAField").is_none());
    }

    #[test]
    fn partial_build_loads() {
        // Partial dumps from pages 943-952 — only XenuineDecrypt/UWorld/GNames
        // known. for_build must not error; missing fields default to 0 / spec.
        let off = PubgOffsets::for_build(Some("2026-04-29")).unwrap();
        assert_eq!(off.uworld_rva, 0x1225F938);
        assert_eq!(off.gnames_rva, 0x124EF760);
        assert_eq!(off.gobjects_rva, 0); // not in partial dump
        // class field defaults still populated
        assert_eq!(off.root_component, 0x308);
        assert_eq!(off.gender, 0xB48);
    }

    #[test]
    fn gender_field_present() {
        let off = PubgOffsets::for_build(None).unwrap();
        assert_eq!(off.gender, 0xB48);
    }

    #[test]
    fn health_plaintext_path_when_flag_3() {
        let off = PubgOffsets::for_build(None).unwrap();
        // pool covers Actor+0xA10..0xA40. Health2 (plaintext path) = 0xA38.
        let mut pool = vec![0u8; 0x30];
        let h2_off = (off.health2 - 0xA10) as usize;
        let want: f32 = 47.5;
        pool[h2_off..h2_off + 4].copy_from_slice(&want.to_le_bytes());
        let v = decrypt::health(&off, &pool, 3);
        assert!((v - want).abs() < 0.01, "plaintext path got {v}");
    }

    #[test]
    fn health_falls_back_when_decrypt_fails() {
        let off = PubgOffsets::for_build(None).unwrap();
        // Pool full of zeros + flag != 3. Encrypted path produces 0.0
        // (finite, in [0..200]) -> returns that. Sanity check it doesn't NaN.
        let pool = vec![0u8; 0x30];
        let v = decrypt::health(&off, &pool, 0);
        assert!(v.is_finite());
        assert!((0.0..=200.0).contains(&v));
    }
}

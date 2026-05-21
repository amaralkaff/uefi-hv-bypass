//! Offset table for PUBG (TslGame.exe). Fetched from external dumper service.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Endpoint for offset dumper service. Replace with your private endpoint.
const DUMPER_URL: &str = "https://example.invalid/pubg/offsets.json";

/// Local cache path under user appdata.
fn cache_path() -> PathBuf {
    let mut p = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    // Random-looking subdir name (BattlEye file scan evasion)
    p.push("Microsoft\\Windows\\WER\\Temp");
    p.push("ofs.bin");
    p
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offsets {
    pub build_id: String,
    pub uworld: u64,
    pub gnames: u64,
    pub gobjects: u64,
    // GameInstance/PersistentLevel chain
    pub uworld_persistent_level: u32,
    pub uworld_owning_game_instance: u32,
    // ULevel
    pub level_actors: u32,
    pub level_actors_count: u32,
    // AActor
    pub actor_root_component: u32,
    pub root_component_world_location: u32,
    // APawn
    pub pawn_player_state: u32,
    pub pawn_mesh: u32,
    // USkeletalMeshComponent
    pub mesh_bone_array: u32,
    pub mesh_component_to_world: u32,
    // PUBG-specific
    pub character_health: u32,
    pub character_team: u32,
    pub character_name: u32,
}

/// Fetch offsets from remote dumper, fall back to cached copy on network error.
pub fn fetch() -> Result<Offsets> {
    match fetch_remote() {
        Ok(o) => {
            cache_save(&o).ok();
            Ok(o)
        }
        Err(e) => {
            log::warn!("dumper fetch failed ({e}); using cached");
            cache_load().context("no cache + dumper unreachable")
        }
    }
}

fn fetch_remote() -> Result<Offsets> {
    let body: Offsets = reqwest::blocking::get(DUMPER_URL)?.json()?;
    Ok(body)
}

fn cache_save(o: &Offsets) -> Result<()> {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(o)?;
    // TODO: XOR-obfuscate bytes before write; BattlEye file scans look for
    // signed JSON / known sigs.
    std::fs::write(&path, &bytes)?;
    Ok(())
}

fn cache_load() -> Result<Offsets> {
    let path = cache_path();
    let bytes = std::fs::read(&path)?;
    let o: Offsets = serde_json::from_slice(&bytes)?;
    Ok(o)
}

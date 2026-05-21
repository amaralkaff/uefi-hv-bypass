//! Player walker for PUBG. Pulls health (XOR-decrypted), team, position,
//! gender, name. Designed against `pubg_offsets.json`.
//!
//! **Battle Royale caveat** — PUBG's BR servers withhold replicated health
//! for non-teammates, so even after a successful decrypt enemy `health` will
//! always read 100.0 in BR. Only own pawn + squad members yield real values.
//! Deathmatch / training mode do not apply this filter and reveal full HP.

use crate::hv_pipe::Session;
use crate::sdk::dumper::read_batch;
use crate::sdk::pubg_offsets::{decrypt, PubgOffsets};
use anyhow::Result;
use nalgebra_glm as glm;

/// Health-decrypt pool covers `Actor+0xA10..Actor+0xA40` (48 bytes).
pub const HEALTH_POOL_BASE: u32 = 0xA10;
pub const HEALTH_POOL_BYTES: usize = 0x30;

#[derive(Debug, Clone)]
pub struct Player {
    pub actor_va: u64,
    pub player_state_va: u64,
    pub mesh_va: u64,
    pub root_component_va: u64,
    pub position: glm::Vec3,
    pub rotation: glm::Vec3,
    pub health: f32,
    pub team_number: i32,
    /// `Actor + 0xB48`. Used by ESP to pick the gender-specific bone-size
    /// table when drawing skeletons.
    pub gender: u8,
    /// Was the health value reached via the trusted plaintext path
    /// (`flag == 3`) or the encrypted-pool fallback. ESP can use this to
    /// flag locked-100 enemies in BR.
    pub health_trusted: bool,
    pub bones: Vec<glm::Vec3>,
}

impl Player {
    /// Two VMCALLs per actor:
    ///   1. SCATTER PlayerState + Mesh + RootComponent pointer triplet.
    ///   2. SCATTER position + team byte + flag byte + gender byte +
    ///      48-byte encrypted health pool.
    pub fn from_actor(session: &Session, actor_va: u64, off: &PubgOffsets) -> Result<Self> {
        let ptrs = read_batch(
            session,
            &[
                (actor_va + off.player_state as u64, 8),
                (actor_va + off.mesh as u64, 8),
                (actor_va + off.root_component as u64, 8),
            ],
        )?;
        let player_state_va = u64::from_le_bytes(ptrs[0][..8].try_into().unwrap());
        let mesh_va = u64::from_le_bytes(ptrs[1][..8].try_into().unwrap());
        let root_component_va = u64::from_le_bytes(ptrs[2][..8].try_into().unwrap());

        let mut position = glm::vec3(0.0, 0.0, 0.0);
        let rotation = glm::vec3(0.0, 0.0, 0.0);
        let mut team_number = 0i32;
        let mut gender = 0u8;
        let mut health = 100.0f32;
        let mut health_trusted = false;

        if root_component_va != 0 {
            let geo = read_batch(
                session,
                &[
                    (root_component_va + off.component_location as u64, 12),
                    (actor_va + off.team_number as u64, 4),
                    (actor_va + off.health_flag as u64, 1),
                    (actor_va + off.gender as u64, 1),
                    (actor_va + HEALTH_POOL_BASE as u64, HEALTH_POOL_BYTES),
                ],
            )?;
            position = glm::vec3(
                f32::from_le_bytes(geo[0][0..4].try_into().unwrap()),
                f32::from_le_bytes(geo[0][4..8].try_into().unwrap()),
                f32::from_le_bytes(geo[0][8..12].try_into().unwrap()),
            );
            team_number = i32::from_le_bytes(geo[1][..4].try_into().unwrap());
            let flag = geo[2][0];
            gender = geo[3][0];
            let pool = &geo[4][..HEALTH_POOL_BYTES];

            health_trusted = flag == 3;
            health = decrypt::health(off, pool, flag);
        }

        Ok(Player {
            actor_va,
            player_state_va,
            mesh_va,
            root_component_va,
            position,
            rotation,
            health,
            team_number,
            gender,
            health_trusted,
            bones: Vec::new(),
        })
    }

    pub fn distance_to(&self, other: &glm::Vec3) -> f32 {
        glm::distance(&self.position, other)
    }

    /// Read `APlayerState::PlayerName` (FString, UTF-16). 8-byte data ptr
    /// + 4-byte count. Caps at 64 chars.
    pub fn read_player_name(
        &self,
        session: &Session,
        off: &PubgOffsets,
    ) -> Result<Option<String>> {
        if self.player_state_va == 0 || off.player_name == 0 {
            return Ok(None);
        }
        let hdr = read_batch(
            session,
            &[(self.player_state_va + off.player_name as u64, 12)],
        )?;
        let data_ptr = u64::from_le_bytes(hdr[0][0..8].try_into().unwrap());
        let count = i32::from_le_bytes(hdr[0][8..12].try_into().unwrap()).max(0) as usize;
        if data_ptr == 0 || count == 0 || count > 64 {
            return Ok(None);
        }
        let bytes = count * 2;
        let buf = read_batch(session, &[(data_ptr, bytes)])?;
        let chunk = &buf[0];
        let mut chars: Vec<u16> = Vec::with_capacity(count);
        for i in 0..count {
            chars.push(u16::from_le_bytes(
                chunk[i * 2..i * 2 + 2].try_into().unwrap(),
            ));
        }
        if let Some(end) = chars.iter().position(|&c| c == 0) {
            chars.truncate(end);
        }
        Ok(Some(String::from_utf16_lossy(&chars)))
    }
}

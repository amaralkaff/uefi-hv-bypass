//! Player walker for PUBG. Pulls health (XOR-decrypted), team, position,
//! bones, name. Designed against the offsets in `pubg_offsets.json`.

use crate::hv_pipe::Session;
use crate::sdk::dumper::read_batch;
use crate::sdk::pubg_offsets::{decrypt, PubgOffsets};
use anyhow::Result;
use nalgebra_glm as glm;

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
    pub bones: Vec<glm::Vec3>,
}

impl Player {
    /// First SCATTER pulls four pointers off the actor (PlayerState, Mesh,
    /// RootComponent). Second pulls the encrypted health blob + flag,
    /// position+rotation off the root component, and the team-number byte.
    /// Two VMCALLs per actor — for ~100 entity scenes, batch via the planned
    /// `read_pawn_batch` helper.
    pub fn from_actor(session: &Session, actor_va: u64, off: &PubgOffsets) -> Result<Self> {
        // Pointer triplet
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

        // Geometry + state batch (variable-shape; collect into one call when
        // RootComponent valid).
        let mut position = glm::vec3(0.0, 0.0, 0.0);
        let rotation = glm::vec3(0.0, 0.0, 0.0);
        let mut team_number = 0i32;
        let mut health = 100.0f32;

        if root_component_va != 0 {
            let geo = read_batch(
                session,
                &[
                    (root_component_va + off.component_location as u64, 12),
                    (actor_va + off.team_number as u64, 4),
                    (actor_va + off.health_flag as u64, 1),
                    (actor_va + off.health1 as u64, 4),
                    (actor_va + off.health2 as u64, 4),
                    (actor_va + off.health3 as u64, 4),
                    (actor_va + off.health4 as u64, 4),
                    (actor_va + off.health5 as u64, 4),
                    (actor_va + off.health6 as u64, 4),
                ],
            )?;
            position = glm::vec3(
                f32::from_le_bytes(geo[0][0..4].try_into().unwrap()),
                f32::from_le_bytes(geo[0][4..8].try_into().unwrap()),
                f32::from_le_bytes(geo[0][8..12].try_into().unwrap()),
            );
            team_number = i32::from_le_bytes(geo[1][..4].try_into().unwrap());
            let flag = geo[2][0];
            let h: [u32; 6] = [
                u32::from_le_bytes(geo[3][..4].try_into().unwrap()),
                u32::from_le_bytes(geo[4][..4].try_into().unwrap()),
                u32::from_le_bytes(geo[5][..4].try_into().unwrap()),
                u32::from_le_bytes(geo[6][..4].try_into().unwrap()),
                u32::from_le_bytes(geo[7][..4].try_into().unwrap()),
                u32::from_le_bytes(geo[8][..4].try_into().unwrap()),
            ];
            // Decrypted health is the canonical PUBG path; falls back to raw
            // Health1 when the lane heuristic produces something insane.
            let decrypted = decrypt::health(off, &h, flag);
            if decrypted.is_finite() && (0.0..=200.0).contains(&decrypted) {
                health = decrypted;
            } else {
                // Some builds store hp directly in Health1 as float bytes.
                let raw = f32::from_bits(h[0]);
                if raw.is_finite() && (0.0..=200.0).contains(&raw) {
                    health = raw;
                }
            }
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
            bones: Vec::new(),
        })
    }

    pub fn distance_to(&self, other: &glm::Vec3) -> f32 {
        glm::distance(&self.position, other)
    }

    /// Read `APlayerState::PlayerName` (FString, UTF-16). 8-byte data ptr +
    /// 4-byte count. Caps at 64 chars.
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

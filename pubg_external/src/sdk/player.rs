//! Player struct walker. Pulls health, team, position from an actor VA.
//!
//! PUBG-specific health/team/name fields live in the ATslCharacter
//! derivative class, not stock ACharacter. Keep those wired through the
//! `Offsets` struct (sig-resolved) once we have a live game build to
//! pattern-match against. Until then this resolves the universally-stable
//! ACharacter -> Mesh -> RootComponent -> RelativeLocation chain.

use crate::hv_pipe::Session;
use crate::sdk::dumper::read_batch;
use crate::sdk::offsets::{
    AACTOR_ROOT_COMPONENT, ACHARACTER_MESH, APAWN_PLAYER_STATE,
    APLAYERSTATE_PLAYER_NAME, USCENECOMP_RELATIVE_LOCATION, USCENECOMP_RELATIVE_ROTATION,
};
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
    /// Populated once PUBG-specific health offset is sig-resolved. Default
    /// 100.0 keeps ESP fall-through filtering harmless until then.
    pub health: f32,
    /// Bone world positions (head/neck/spine/limbs). Empty until the
    /// USkeletalMeshComponent bone-array walk lands.
    pub bones: Vec<glm::Vec3>,
}

impl Player {
    /// First scatter pulls the four pointers off the actor (PlayerState,
    /// Mesh, RootComponent), then a second scatter pulls the location +
    /// rotation off RootComponent. Two VMCALLs per actor — to scale to 100+
    /// pawns the caller should batch across actors using one big SCATTER
    /// list (TODO: `read_pawn_batch`).
    pub fn from_actor(session: &Session, actor_va: u64) -> Result<Self> {
        let ptrs = read_batch(
            session,
            &[
                (actor_va + APAWN_PLAYER_STATE as u64, 8),
                (actor_va + ACHARACTER_MESH as u64, 8),
                (actor_va + AACTOR_ROOT_COMPONENT as u64, 8),
            ],
        )?;
        let player_state_va = u64::from_le_bytes(ptrs[0][..8].try_into().unwrap());
        let mesh_va = u64::from_le_bytes(ptrs[1][..8].try_into().unwrap());
        let root_component_va = u64::from_le_bytes(ptrs[2][..8].try_into().unwrap());

        let mut position = glm::vec3(0.0, 0.0, 0.0);
        let mut rotation = glm::vec3(0.0, 0.0, 0.0);
        if root_component_va != 0 {
            let geo = read_batch(
                session,
                &[
                    (root_component_va + USCENECOMP_RELATIVE_LOCATION as u64, 12),
                    (root_component_va + USCENECOMP_RELATIVE_ROTATION as u64, 12),
                ],
            )?;
            position = glm::vec3(
                f32::from_le_bytes(geo[0][0..4].try_into().unwrap()),
                f32::from_le_bytes(geo[0][4..8].try_into().unwrap()),
                f32::from_le_bytes(geo[0][8..12].try_into().unwrap()),
            );
            rotation = glm::vec3(
                f32::from_le_bytes(geo[1][0..4].try_into().unwrap()),
                f32::from_le_bytes(geo[1][4..8].try_into().unwrap()),
                f32::from_le_bytes(geo[1][8..12].try_into().unwrap()),
            );
        }

        Ok(Player {
            actor_va,
            player_state_va,
            mesh_va,
            root_component_va,
            position,
            rotation,
            health: 100.0,
            bones: Vec::new(),
        })
    }

    pub fn distance_to(&self, other: &glm::Vec3) -> f32 {
        glm::distance(&self.position, other)
    }

    /// Read `APlayerState::PlayerName` (FString) — first 8 bytes are the
    /// `TArray<TCHAR>` ptr, next 4 are count. UE4 FString is UTF-16 in
    /// PUBG; caller decodes after pulling the buffer.
    pub fn read_player_name(&self, session: &Session) -> Result<Option<String>> {
        if self.player_state_va == 0 {
            return Ok(None);
        }
        let hdr = read_batch(
            session,
            &[(
                self.player_state_va + APLAYERSTATE_PLAYER_NAME as u64,
                12,
            )],
        )?;
        let data_ptr = u64::from_le_bytes(hdr[0][0..8].try_into().unwrap());
        let count = i32::from_le_bytes(hdr[0][8..12].try_into().unwrap()).max(0) as usize;
        if data_ptr == 0 || count == 0 || count > 64 {
            return Ok(None);
        }
        let bytes = count * 2; // UTF-16
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

//! UWorld + ULevel walkers. Reads chained via SCATTER for one VMCALL per
//! frame slice.

use crate::hv_pipe::{Session, Target};
use crate::sdk::dumper::read_batch;
use crate::sdk::offsets::{
    Offsets, ULEVEL_ACTORS_COUNT, ULEVEL_ACTORS_PTR, UWORLD_GAME_STATE,
    UWORLD_OWNING_GAME_INSTANCE, UWORLD_PERSISTENT_LEVEL,
};
use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct UWorld {
    pub uworld_va: u64,
    pub level_va: u64,
    pub game_state_va: u64,
    pub game_instance_va: u64,
    pub actors_ptr: u64,
    pub actors_count: u32,
}

impl UWorld {
    /// Resolves: deref `GWorld` to UWorld VA, then scatter-read level +
    /// game state + game instance pointers, then scatter-read level's actor
    /// array meta. Three VMCALL hops worst case (one for `*GWorld`, one for
    /// the UWorld-level batch, one for ULevel.Actors batch).
    pub fn read(session: &Session, _target: &Target, off: &Offsets) -> Result<Self> {
        // *GWorld
        let uworld_buf = read_batch(session, &[(off.gworld, 8)])?;
        let uworld_va = u64::from_le_bytes(uworld_buf[0][..8].try_into().unwrap());
        if uworld_va == 0 {
            return Ok(UWorld::default());
        }

        // PersistentLevel + GameState + OwningGameInstance in one shot
        let world_batch = read_batch(
            session,
            &[
                (uworld_va + UWORLD_PERSISTENT_LEVEL as u64, 8),
                (uworld_va + UWORLD_GAME_STATE as u64, 8),
                (uworld_va + UWORLD_OWNING_GAME_INSTANCE as u64, 8),
            ],
        )?;
        let level_va = u64::from_le_bytes(world_batch[0][..8].try_into().unwrap());
        let game_state_va = u64::from_le_bytes(world_batch[1][..8].try_into().unwrap());
        let game_instance_va = u64::from_le_bytes(world_batch[2][..8].try_into().unwrap());

        // ULevel.Actors {ptr, count}
        let mut actors_ptr = 0u64;
        let mut actors_count = 0u32;
        if level_va != 0 {
            let level_batch = read_batch(
                session,
                &[
                    (level_va + ULEVEL_ACTORS_PTR as u64, 8),
                    (level_va + ULEVEL_ACTORS_COUNT as u64, 4),
                ],
            )?;
            actors_ptr = u64::from_le_bytes(level_batch[0][..8].try_into().unwrap());
            actors_count = u32::from_le_bytes(level_batch[1][..4].try_into().unwrap());
        }

        Ok(UWorld {
            uworld_va,
            level_va,
            game_state_va,
            game_instance_va,
            actors_ptr,
            actors_count,
        })
    }
}

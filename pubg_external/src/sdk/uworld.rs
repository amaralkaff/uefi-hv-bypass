//! UWorld + ULevel walker for PUBG (TslGame.exe).
//!
//! UE4 layout but with PUBG-specific offsets baked in `pubg_offsets.json`.
//! Static engine globals are RVAs from the image base, not sig-resolved,
//! because the per-build dumps include them directly.

use crate::hv_pipe::{Session, Target};
use crate::sdk::dumper::read_batch;
use crate::sdk::pubg_offsets::PubgOffsets;
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
    /// Resolve UWorld via `*(image_base + UWorld_RVA)`, then SCATTER-batch
    /// PersistentLevel + GameState + GameInstance, then SCATTER-batch ULevel
    /// actor array meta. Three VMCALLs worst case.
    pub fn read(session: &Session, target: &Target, off: &PubgOffsets) -> Result<Self> {
        let uworld_global_va = target.base + off.uworld_rva;
        let uworld_buf = read_batch(session, &[(uworld_global_va, 8)])?;
        let uworld_va = u64::from_le_bytes(uworld_buf[0][..8].try_into().unwrap());
        if uworld_va == 0 {
            return Ok(UWorld::default());
        }

        let world_batch = read_batch(
            session,
            &[
                (uworld_va + off.persistent_level as u64, 8),
                (uworld_va + off.game_state as u64, 8),
                (uworld_va + off.game_instance as u64, 8),
            ],
        )?;
        let level_va = u64::from_le_bytes(world_batch[0][..8].try_into().unwrap());
        let game_state_va = u64::from_le_bytes(world_batch[1][..8].try_into().unwrap());
        let game_instance_va = u64::from_le_bytes(world_batch[2][..8].try_into().unwrap());

        // ULevel.Actors: TArray<AActor*> at off.level_actors. Layout:
        //   [ptr u64][count i32][slack i32]
        let mut actors_ptr = 0u64;
        let mut actors_count = 0u32;
        if level_va != 0 {
            let level_batch = read_batch(
                session,
                &[(level_va + off.level_actors as u64, 12)],
            )?;
            actors_ptr =
                u64::from_le_bytes(level_batch[0][0..8].try_into().unwrap());
            actors_count = u32::from_le_bytes(
                level_batch[0][8..12].try_into().unwrap(),
            );
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

    /// Pull all `count` actor pointers from the level's actor array in one
    /// SCATTER call. Caller filters NULLs and class-checks downstream.
    pub fn read_actor_pointers(
        &self,
        session: &Session,
        max: usize,
    ) -> Result<Vec<u64>> {
        if self.actors_ptr == 0 || self.actors_count == 0 {
            return Ok(Vec::new());
        }
        let n = (self.actors_count as usize).min(max);
        let bytes = n * 8;
        let buf = read_batch(session, &[(self.actors_ptr, bytes)])?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let p = u64::from_le_bytes(
                buf[0][i * 8..(i + 1) * 8].try_into().unwrap(),
            );
            out.push(p);
        }
        Ok(out)
    }
}

//! UWorld + ULevel walkers. PT-walks done in VMM-root via hv_pipe.

use crate::hv_pipe::{self, Session, Target};
use crate::sdk::Offsets;
use anyhow::Result;

pub struct UWorld {
    pub uworld_va: u64,
    pub level_va: u64,
    pub actors_va: u64,
    pub actors_count: u32,
}

impl UWorld {
    pub fn read(session: &Session, target: &Target, off: &Offsets) -> Result<Self> {
        // TODO: chain reads via OPHION_OP_READ_MANY (single VMCALL = many addrs).
        // For scaffold: stub
        let _ = (session, target, off);
        Ok(UWorld {
            uworld_va: 0,
            level_va: 0,
            actors_va: 0,
            actors_count: 0,
        })
    }
}

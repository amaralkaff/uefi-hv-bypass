//! Player struct walker. Pulls health, team, position, bone array.

use crate::hv_pipe::Session;
use crate::sdk::Offsets;
use anyhow::Result;
use nalgebra_glm as glm;

#[derive(Debug, Clone)]
pub struct Player {
    pub actor_va: u64,
    pub name: String,
    pub team: i32,
    pub health: f32,
    pub position: glm::Vec3,
    pub bones: Vec<glm::Vec3>,
}

impl Player {
    pub fn from_actor(_session: &Session, _actor_va: u64, _off: &Offsets) -> Result<Self> {
        // TODO: batched OPHION_OP_READ_MANY for: name string, team, health,
        // root component world location, bone array head/neck/spine/limbs.
        Ok(Player {
            actor_va: 0,
            name: String::new(),
            team: 0,
            health: 0.0,
            position: glm::vec3(0.0, 0.0, 0.0),
            bones: Vec::new(),
        })
    }

    pub fn distance_to(&self, other: &glm::Vec3) -> f32 {
        glm::distance(&self.position, other)
    }
}

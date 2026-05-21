//! Cheat features: ESP, Aimbot, Loot ESP, Vehicle ESP.
//! Each feature is a tick(ctx) function called per-frame from overlay.

pub mod esp;
pub mod aimbot;
pub mod loot;
pub mod vehicle;

use crate::hv_pipe::{Session, Target};
use crate::sdk::Offsets;
use crate::sdk::player::Player;

pub struct FrameCtx<'a> {
    pub session: &'a Session,
    pub target: &'a Target,
    pub offsets: &'a Offsets,
    pub players: Vec<Player>,
    pub local_view_matrix: nalgebra_glm::Mat4,
    pub screen_w: f32,
    pub screen_h: f32,
}

#[derive(Default)]
pub struct Toggles {
    pub esp_enabled: bool,
    pub esp_box: bool,
    pub esp_skeleton: bool,
    pub esp_health: bool,
    pub esp_distance: bool,
    pub aimbot_enabled: bool,
    pub aimbot_fov: f32,
    pub aimbot_smooth: f32,
    pub aimbot_visibility_check: bool,
    pub loot_enabled: bool,
    pub vehicle_enabled: bool,
}

impl Toggles {
    pub fn defaults() -> Self {
        Self {
            esp_enabled: true,
            esp_box: true,
            esp_skeleton: false,
            esp_health: true,
            esp_distance: true,
            aimbot_enabled: false,
            aimbot_fov: 5.0,
            aimbot_smooth: 0.3,
            aimbot_visibility_check: true,
            loot_enabled: false,
            vehicle_enabled: false,
        }
    }
}

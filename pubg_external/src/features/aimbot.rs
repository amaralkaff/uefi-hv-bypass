//! Aimbot: nearest-to-crosshair target selection + smooth mouse aim.

use super::{FrameCtx, Toggles};
use nalgebra_glm as glm;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    mouse_event, MOUSEEVENTF_MOVE,
};

pub fn tick(ctx: &FrameCtx, toggles: &Toggles) {
    if !toggles.aimbot_enabled {
        return;
    }

    let crosshair = glm::vec2(ctx.screen_w * 0.5, ctx.screen_h * 0.5);
    let mut best: Option<(f32, glm::Vec2)> = None;

    for p in &ctx.players {
        if p.health <= 0.0 {
            continue;
        }
        // TODO: visibility check via vmm trace ray (line-of-sight bone vs crosshair)
        // For scaffold: skip vis check
        let Some(head) = aim_point(p) else { continue };
        let Some(screen) = w2s(&head, &ctx.local_view_matrix, ctx.screen_w, ctx.screen_h)
        else {
            continue;
        };
        let dist = glm::distance(&screen, &crosshair);
        if dist > toggles.aimbot_fov * 10.0 {
            continue;
        }
        if best.map_or(true, |b| dist < b.0) {
            best = Some((dist, screen));
        }
    }

    if let Some((_, target)) = best {
        let dx = (target.x - crosshair.x) * toggles.aimbot_smooth;
        let dy = (target.y - crosshair.y) * toggles.aimbot_smooth;
        unsafe {
            mouse_event(MOUSEEVENTF_MOVE, dx as i32, dy as i32, 0, 0);
        }
    }
}

fn aim_point(p: &crate::sdk::player::Player) -> Option<glm::Vec3> {
    // Head bone if available, else position + offset
    p.bones.first().copied().or(Some(p.position + glm::vec3(0.0, 0.0, 180.0)))
}

fn w2s(world: &glm::Vec3, vp: &glm::Mat4, w: f32, h: f32) -> Option<glm::Vec2> {
    let clip = vp * glm::vec4(world.x, world.y, world.z, 1.0);
    if clip.w < 0.1 {
        return None;
    }
    Some(glm::vec2(
        (clip.x / clip.w * 0.5 + 0.5) * w,
        (1.0 - (clip.y / clip.w * 0.5 + 0.5)) * h,
    ))
}

//! ESP: world-to-screen + draw box/skeleton/healthbar/distance/name.

use super::{FrameCtx, Toggles};
use imgui::Ui;
use nalgebra_glm as glm;

pub fn tick(ui: &Ui, ctx: &FrameCtx, toggles: &Toggles) {
    if !toggles.esp_enabled {
        return;
    }
    let draw = ui.get_background_draw_list();

    for p in &ctx.players {
        if p.health <= 0.0 {
            continue;
        }
        let Some(screen) = w2s(&p.position, &ctx.local_view_matrix, ctx.screen_w, ctx.screen_h)
        else {
            continue;
        };

        if toggles.esp_box {
            draw.add_rect(
                [screen.x - 20.0, screen.y - 50.0],
                [screen.x + 20.0, screen.y + 50.0],
                [0.0, 1.0, 0.0, 1.0],
            )
            .build();
        }

        if toggles.esp_health {
            let bar_w = 4.0;
            let bar_h = 100.0;
            let pct = (p.health / 100.0).clamp(0.0, 1.0);
            draw.add_rect(
                [screen.x - 26.0, screen.y - 50.0],
                [screen.x - 26.0 + bar_w, screen.y - 50.0 + bar_h],
                [0.0, 0.0, 0.0, 0.5],
            )
            .filled(true)
            .build();
            draw.add_rect(
                [screen.x - 26.0, screen.y - 50.0 + bar_h * (1.0 - pct)],
                [screen.x - 26.0 + bar_w, screen.y - 50.0 + bar_h],
                [pct, 1.0 - pct, 0.0, 1.0],
            )
            .filled(true)
            .build();
        }

        if toggles.esp_distance {
            let d = (p.position - ctx.local_view_matrix.column(3).xyz()).norm() / 100.0;
            draw.add_text(
                [screen.x + 24.0, screen.y - 50.0],
                [1.0, 1.0, 1.0, 1.0],
                format!("{:.0}m", d),
            );
        }
    }
}

/// World-to-screen using game's view-projection matrix.
fn w2s(world: &glm::Vec3, vp: &glm::Mat4, w: f32, h: f32) -> Option<glm::Vec2> {
    let clip = vp * glm::vec4(world.x, world.y, world.z, 1.0);
    if clip.w < 0.1 {
        return None;
    }
    let ndc_x = clip.x / clip.w;
    let ndc_y = clip.y / clip.w;
    Some(glm::vec2(
        (ndc_x * 0.5 + 0.5) * w,
        (1.0 - (ndc_y * 0.5 + 0.5)) * h,
    ))
}

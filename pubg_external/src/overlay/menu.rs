//! ImGui menu: feature toggles + sliders + status panel.

use crate::features::Toggles;
use imgui::Ui;

pub fn draw(ui: &Ui, toggles: &mut Toggles) {
    ui.window("config")
        .size([320.0, 480.0], imgui::Condition::FirstUseEver)
        .build(|| {
            if let Some(_t) = ui.tab_bar("tabs") {
                if let Some(_t) = ui.tab_item("ESP") {
                    ui.checkbox("enabled", &mut toggles.esp_enabled);
                    ui.checkbox("box", &mut toggles.esp_box);
                    ui.checkbox("skeleton", &mut toggles.esp_skeleton);
                    ui.checkbox("health", &mut toggles.esp_health);
                    ui.checkbox("distance", &mut toggles.esp_distance);
                }
                if let Some(_t) = ui.tab_item("Aimbot") {
                    ui.checkbox("enabled", &mut toggles.aimbot_enabled);
                    ui.slider("FOV (deg)", 1.0, 30.0, &mut toggles.aimbot_fov);
                    ui.slider("smooth", 0.05, 1.0, &mut toggles.aimbot_smooth);
                    ui.checkbox("visibility check", &mut toggles.aimbot_visibility_check);
                }
                if let Some(_t) = ui.tab_item("Misc") {
                    ui.checkbox("loot ESP", &mut toggles.loot_enabled);
                    ui.checkbox("vehicle ESP", &mut toggles.vehicle_enabled);
                }
            }
        });
}

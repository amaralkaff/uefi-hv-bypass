//! Loot ESP: highlights items on ground (medkits, armor, ammo, scopes).

use super::{FrameCtx, Toggles};
use imgui::Ui;

pub fn tick(_ui: &Ui, _ctx: &FrameCtx, toggles: &Toggles) {
    if !toggles.loot_enabled {
        return;
    }
    // TODO: walk PersistentLevel actors, filter by class name (LootBox, Item),
    // categorize by tier (heal/armor/scope/ammo), draw colored markers.
}

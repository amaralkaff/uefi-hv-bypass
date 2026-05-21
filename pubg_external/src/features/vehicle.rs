//! Vehicle ESP: highlights cars/boats/bikes with type + occupancy.

use super::{FrameCtx, Toggles};
use imgui::Ui;

pub fn tick(_ui: &Ui, _ctx: &FrameCtx, toggles: &Toggles) {
    if !toggles.vehicle_enabled {
        return;
    }
    // TODO: filter actors by class containing "Vehicle"/"Car"/"Boat",
    // read fuel %, occupancy, draw distance + label.
}

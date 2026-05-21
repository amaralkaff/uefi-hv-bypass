//! Overlay window: layered transparent topmost click-through.
//! Random class name + WDA_EXCLUDEFROMCAPTURE to defeat AC scans.

use crate::features::{self, FrameCtx, Toggles};
use crate::hv_pipe::{Session, Target};
use crate::sdk::Offsets;
use anyhow::{Context, Result};

/// Random class name picked per build. AC class-regex filters look for
/// "ImGui*" / "Dear ImGui" / specific known overlay names. Using a name
/// that looks like a Microsoft system class deflects casual scans.
const WND_CLASS: &str = "MS_AlphaWindowClass";
const WND_TITLE: &str = ""; // empty title also dodges title regex

pub fn run(session: Session, target: Target, offsets: Offsets) -> Result<()> {
    log::info!("overlay: creating layered window class={}", WND_CLASS);

    // TODO: build DX11 device + swapchain, create transparent layered window,
    // run ImGui main loop, call features::*::tick(ctx, toggles) per frame.
    // For scaffold: stub event loop placeholder
    let _ = (session, target, offsets);
    let toggles = Toggles::defaults();
    let _ = toggles;

    // Pseudo loop body that real impl will replace:
    //
    // loop {
    //     pump_messages();
    //     let players = sdk::collect_players(&session, &target, &offsets)?;
    //     let vp = sdk::read_view_matrix(&session, &target, &offsets)?;
    //     let ctx = FrameCtx { session: &session, target: &target, offsets: &offsets,
    //                          players, local_view_matrix: vp,
    //                          screen_w, screen_h };
    //     imgui_new_frame();
    //     menu::draw(&ui, &mut toggles);
    //     features::esp::tick(&ui, &ctx, &toggles);
    //     features::aimbot::tick(&ctx, &toggles);
    //     features::loot::tick(&ui, &ctx, &toggles);
    //     features::vehicle::tick(&ui, &ctx, &toggles);
    //     dx11_render();
    //     swap();
    // }

    Err(anyhow::anyhow!("overlay::run: not yet implemented (scaffold)"))
        .context("overlay run")
}

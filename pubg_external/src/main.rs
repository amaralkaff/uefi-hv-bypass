//! pubg_external entry point. Loads offsets, opens HV pipe, runs overlay.
//!
//! Architecture:
//!   main -> hv_pipe::register   (auth handshake via VMCALL)
//!        -> hv_pipe::resolve_target("TslGame.exe")
//!        -> sdk::PubgOffsets::for_build(env override or DEFAULT_BUILD)
//!        -> overlay::run         (DX11 ImGui, calls features::tick each frame)

use anyhow::{Context, Result};
use pubg_external::{hv_pipe, overlay, sdk};

fn main() -> Result<()> {
    env_logger::init();

    log::info!("pubg_external starting");

    let session = hv_pipe::register()
        .context("VMM register failed - is OphionDxe loaded + Ophion.sys running?")?;
    log::info!("VMM session key: 0x{:x}", session.key);

    let target = hv_pipe::resolve_target(&session, "TslGame.exe")
        .context("PUBG process not found")?;
    log::info!(
        "target pid={} base={:#x} size={:#x}",
        target.pid,
        target.base,
        target.size
    );

    // Build override via PUBG_BUILD env var; otherwise pick DEFAULT_BUILD.
    let build = std::env::var("PUBG_BUILD").ok();
    let offsets = sdk::PubgOffsets::for_build(build.as_deref())
        .context("offset load failed")?;
    log::info!(
        "offsets loaded: build={} uworld_rva=0x{:x}",
        offsets.build_id,
        offsets.uworld_rva
    );

    overlay::run(session, target, offsets)?;

    Ok(())
}

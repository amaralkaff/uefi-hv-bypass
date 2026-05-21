//! pubg_external entry point. Loads offsets, opens HV pipe, runs overlay.
//!
//! Architecture:
//!   main -> hv_pipe::register   (auth handshake via VMCALL)
//!        -> hv_pipe::resolve_target("TslGame.exe")
//!        -> sdk::offsets::fetch (external dumper or cached)
//!        -> overlay::run         (DX11 ImGui, calls features::tick each frame)

mod hv_pipe;
mod overlay;
mod sdk;
mod features;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    env_logger::init();

    log::info!("pubg_external starting");

    let session = hv_pipe::register()
        .context("VMM register failed - is OphionDxe loaded + Ophion.sys running?")?;
    log::info!("VMM session key: 0x{:x}", session.key);

    let target = hv_pipe::resolve_target(&session, "TslGame.exe")
        .context("PUBG process not found")?;
    log::info!("target pid={} base={:#x} size={:#x}", target.pid, target.base, target.size);

    let offsets = sdk::offsets::fetch().context("offset fetch failed")?;
    log::info!("offsets loaded: build={}", offsets.build_id);

    overlay::run(session, target, offsets)?;

    Ok(())
}

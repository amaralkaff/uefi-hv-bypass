# pubg_external

External PUBG cheat scaffold. Targets BattlEye.

## Architecture

```
[cheat exe (Rust)] -- IOCTL --> [Ophion.sys ring 0]
                                       |
                                       v
                              [trampoline @ UEFI runtime VA]
                                       |
                                       v
                                    VMCALL
                                       |
                                       v
                              [VMM in VMX-root]
                              - PT-walks guest CR3
                              - vmm_guest_read / write
                              - VmcallDispatch ops
```

All memory I/O happens in VMX-root host context. BattlEye scans of NT object
table, driver list, and process handles see nothing.

## Layout

```
pubg_external/
├── src/
│   ├── main.rs         entry: register session, resolve target, run overlay
│   ├── hv_pipe.rs      VMM VMCALL pipe via Ophion.sys
│   ├── overlay/        DX11 + ImGui transparent layered window
│   ├── sdk/            UWorld + ULevel + APawn + offsets
│   └── features/       esp, aimbot, loot, vehicle
└── Cargo.toml
```

## Stealth posture

- Random window class name (`MS_AlphaWindowClass`) — defeats `ImGui*` regex
- Empty window title — defeats title regex
- `WS_EX_LAYERED|WS_EX_TRANSPARENT|WS_EX_TOPMOST|WS_EX_TOOLWINDOW`
- `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` — defeats screenshot
- Random exe name per build (BattlEye basename hash blocklist)
- Offset cache hidden under `%LOCALAPPDATA%\Microsoft\Windows\WER\Temp\ofs.bin`

## Build

```
cd pubg_external
cargo build --release
```

Output: `target/release/pubg_external.exe`. Rename per launch.

## Prereqs

1. UEFI hypervisor active (see parent repo README boot setup)
2. EfiDSEFix.exe -d (DSE off for self-signed Ophion.sys)
3. `sc start Ophion` (ring 0 driver loaded)
4. PUBG running

## Status

Scaffold only. All hv_pipe ops + sdk walkers + overlay impl are TODO stubs.

# PUBG ESP Plan — Task Ladder

Locked 2026-05-22 via /grill-me. 25 decisions resolved. See `project_pubg_esp_plan.md` memory.

Workflow: direct commits to `main`. No PRs. Atomic conventional commits per step.

## Done

- [x] **Step #1** — `b934e70` chore: absorb Ophion driver into main repo (Q24-C)
- [x] **Step #2** — `946f9a1` feat(abi): add OPHION_OP_READ_SCATTER (0x0B) (Q3+Q10)
- [x] **Step #3** — `22368ef` feat(ophion): driver scaffolding for VMCALL relay (Q9-C name `\Device\MsftHidIo`, Q6-B FsContext, Q8-B BSP worker, Q2-B trampoline VA parse)
- [x] **Step #4** — `8db687c` feat(ophion): IOCTL_HV_REGISTER + `fa941d2` feat(vmm): dev hash bypass (Q5-D)
- [x] **Step #5** — `1d49cb7` feat(ophion): IOCTL_HV_RESOLVE + IOCTL_HV_UNREGISTER
- [x] **Step #6** — `a1ffe9a` feat(ophion): IOCTL_HV_READ_SCATTER (METHOD_OUT_DIRECT, MDL system VA)
- [x] **Step #7** — `7b3ef9b` feat(ophion): IOCTL_HV_WRITE_MANY (METHOD_BUFFERED, scatter ABI)
- [x] **Smoke #A+B** — `44dfb29` feat(pubg_external): wire hv_pipe to real IOCTLs + `hv_smoke.exe` harness. `cargo build --bin hv_smoke` green. Runtime cycle-loop deferred until driver loads on hardware.
- [x] **Step #8 (partial)** — `1cf9286` feat(vmm): per-CPU exit log (Q21-C lock-free 1KB ring/CPU) + `VmmSpin.h` test-and-set spinlock (Q20-B). Still TODO: per-resource session/proc/ept locks wired in VmcallHandler, NV crash flush, IOCTL_HV_GET_LOG returning merged dump, `read_ophn_log.ps1` parser.

## Open / Next

- [ ] **WDK toolset** — `WindowsKernelModeDriver10.0` PlatformToolset missing from VS18 BuildTools install. Driver build broken until WDK extension reinstalled. (Was working 2026-05-21.) Until then, all driver Steps are source-verified only.
- [ ] **Step #8 finish** — wire `s_session_lock`/`s_proc_cache_lock`/`s_ept_lock` via `VmmSpin.h` in `VmcallHandler.c` session table accesses; add VMX-abort + machine-check NV flush of `VmmPclSnapshot` to `OphnCrashDump` NV var; extend driver `IOCTL_HV_GET_LOG` to return merged per-CPU log; teach `scripts/read_ophn_log.ps1` to decode the magic+cpu_count+rec_per_cpu+rings blob.

## Track A — VMCALL pipe + ESP

- [ ] **Step #9** — pubg_external dumper (Q15-E)
  - `pubg_external/src/sdk/dumper.rs`: sig scan via SCATTER for GNames+GObjects+GWorld
  - FName string-table walk, UObject iter
  - Cache `ofs.bin` to `%LOCALAPPDATA%\...\WER\Temp\`
  - Invalidate keyed on `TslGame.exe` `IMAGE_NT_HEADERS.FileHeader.TimeDateStamp`

- [ ] **Step #10** — Lyra Stage 2 validation (Q23-B)
  - Pattern-scan finds GNames+GObjects+GWorld in Lyra
  - Walk UObject array, count `APawn` instances
  - Read first pawn's `USceneComponent::RelativeLocation`
  - W2S projection produces sane screen coords

- [ ] **Step #11** — pubg_external render
  - Two-thread Rust: read @ 60Hz, render @ display refresh (Q22-B)
  - Double-buffer Snapshot via `AtomicPtr` swap
  - ImGui draws box + skeleton + distance + health on visible Lyra pawns
  - WDA_EXCLUDEFROMCAPTURE, random class name (Q12-A)

## Track B — AP virt (parallel to A)

- [ ] **Step #B1** — UEFI MP services AP bring-up scaffolding (Q19-A)
  - `MongilLoader/OphionDxe/ApInit.c`: `MpServices->StartupAllAPs(OphxApVmxOnInit, ...)` before EBS
  - Per-AP VMCS template, shared EPTP (Q18-A)
  - `s_ap_armed[NUM_CPU]` retry guard

- [ ] **Step #B2** — SIPI + INIT exit handler
  - Handle exit reason 0x09 (INIT) and 0x0A (SIPI) in `VmExitHandler.c`
  - Read SIPI vector from exit qual, write guest RIP/CS, VMRESUME
  - Test: 12 cores all enter VMX root pre-EBS, Windows boots normally

- [ ] **Step #B3** — Phase 7d cloak re-light scoped to driver image (Q16-D)
  - New VMCALL op `OPHX_OP_CLOAK_RANGE`
  - Driver `DriverEntry` calls cloak after `IoCreateDevice`
  - Unlink own `LDR_DATA_TABLE_ENTRY` from 3 lists
  - Wipe `MmUnloadedDrivers` entry, zero PE header in pool

- [ ] **Step #B4** — 12-core stress harness
  - Run hv_smoke.exe + Cinebench/Prime95 in parallel for 30min
  - Watch for 0x101 CLOCK_WATCHDOG (should be gone)
  - Verify cloak survives PG via `read_ophn_log.ps1`

## Integration

- [ ] **Stage 3** — PUBG training (Q23-C)
  - Boot uefi-hv-bypass, EfiDSEFix, `sc start Ophion` w/ cloak active
  - Launch PUBG, enter training mode
  - pubg_external RESOLVE("TslGame.exe") + dumper + ESP
  - Idle 2h — watch for OphnLastErr, BSOD, BattlEye disconnect, process kill
  - Graduate to live match only after 2h+ clean

## Deferred (post-PoC)

- [ ] Pico HID aimbot path (Q13-C) — hardware required
- [ ] Loot ESP, vehicle ESP (Q14 future features)
- [ ] Production hash allow-list bake (Q5-A) — flip `OPHN_DEV_BUILD` off
- [ ] HWND/proc kernel-side hide via Ophion.sys

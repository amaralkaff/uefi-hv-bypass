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
- [x] **Step #8 (finish)** — `ff77148` `2a6e5d7` `75e9ab5` `ad09a1f` `1149439`: ABI op `OPHION_OP_GET_PERCPU_LOG (0x0C)` + VMM `handle_get_percpu_log` + `g_proc_cache_lock` + UNREGISTER under `g_session_lock` + `VmmSpin.h` BaseLib EnableInterrupts/DisableInterrupts switch + driver `IOCTL_HV_GET_VMM_PERCPU_LOG` (METHOD_BUFFERED, system-CR3 pool VA) + Rust `get_vmm_percpu_log` + `hv_smoke --percpu` + `read_ophn_log.ps1 -CrashDump` decoder. VMM build green (`OphionDxe.efi` rebuilt 109KB). NV crash-flush path still TODO (gRT->SetVariable post-EBS unreliable).

## Open / Next

- [ ] **WDK toolset** — `WindowsKernelModeDriver10.0` PlatformToolset missing from VS18 BuildTools install. Driver build broken until WDK extension reinstalled. (Was working 2026-05-21.) Until then, all driver Steps are source-verified only.
- [ ] **Step #8 NV-flush tail** — gRT->SetVariable from VMX-root post-EBS is unreliable, so `OphnCrashDump` write path still missing. Future plumbing: BSP-only #MC / VMX-abort handler queues a flush request, BSP guest context (e.g. ophion driver work item polling on NV-var sentinel) calls SetVariable from PASSIVE_LEVEL with the `VmmPclSnapshot` blob. PS1 `-CrashDump` decoder already lands on the matching layout.

- [x] **Step #9** — `2802739` `32e6cb5` feat(pubg_external): `sdk::dumper` PE walker + IDA sig parser + chunked SCATTER scan (1 MiB chunks, 64 B overlap) + Direct/RipRel32/Abs64 resolvers + cache file `%LOCALAPPDATA%\Microsoft\Windows\WER\Temp\ophion_dump_*.bin` (magic `OPHNDMP\0`, TimeDateStamp-keyed) + `dump_or_load()` cache-or-rebuild + `read_batch()` helper. `hv_smoke --dump <process>` drives PE walk + section enum + sanity-sig scan + cache round-trip end-to-end. 4/4 unit tests green (`cargo test --lib dumper`).
- [x] **Step #9 follow-up** — `e250eb3` feat(pubg_external): bake UE4-PUBG class offsets (Quebeux/TJ888 UE4 SDK dump: AActor/USceneComp/AController/APawn/ACharacter/APlayerController/APlayerState/AGameStateBase/UGameInstance/UPlayer/ULocalPlayer/UGameViewportClient/UWorld/ULevel/USkeletalMeshComponent/APlayerCameraManager) + engine_sigs() (GWorld/GNames/GObjects RipRel32 templates, PUBG-volatile) + `Offsets::resolve()` driving `dump_or_load`. UWorld walker (3 VMCALLs) and Player walker (2 VMCALLs/actor) wired against the new constants. `read_player_name` walks UTF-16 FString via SCATTER. ESP/aimbot scaffolds keep compiling (Player still exposes health=100.0 default + bones=empty until PUBG-specific health/bone-array sigs land).

## Track A — VMCALL pipe + ESP

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

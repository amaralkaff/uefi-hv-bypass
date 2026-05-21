# PUBG ESP Plan — Task Ladder

Locked 2026-05-22 via /grill-me. 25 decisions resolved. See `project_pubg_esp_plan.md` memory.

Workflow: direct commits to `main`. No PRs. Atomic conventional commits per step.

## Done

- [x] **Step #1** — `b934e70` chore: absorb Ophion driver into main repo (Q24-C)
- [x] **Step #2** — `946f9a1` feat(abi): add OPHION_OP_READ_SCATTER (0x0B) (Q3+Q10)

## Open — Q9 unresolved

- [ ] **Q9 device-name** — picked B (NV var) but recommendation was C (static obscure name). Decide: B or C?
  - B: NV var `OphnDev` written by VMM, driver reads at boot. Needs SE_SYSTEM_ENVIRONMENT_NAME (admin) from user side.
  - C: static `\Device\MsftHidIo`, no symlink. Open via `\\?\GLOBALROOT\Device\MsftHidIo`.

## Track A — VMCALL pipe + ESP

- [ ] **Step #3** — driver scaffolding
  - Random/obscure device name (Q9) — depends on decision above
  - Per-handle `FILE_OBJECT->FsContext` session (Q6-B)
  - BSP-pinned worker thread + queue (Q8-B)
  - Trampoline VA discovery via `NtCreateProfile` patch parse (Q2-B)
  - No IOCTLs yet — plumbing only
  - Smoke: device opens, worker starts, trampoline VA logged via `IOCTL_HV_GET_LOG`

- [ ] **Step #4** — `IOCTL_HV_REGISTER`
  - `METHOD_BUFFERED`
  - Dev-mode hash skip (`#ifdef OPHN_DEV_BUILD`, Q5-D)
  - `KeStackAttachProcess(user_proc)` before VMCALL (Q6-B)
  - Driver calls trampoline VA (Q1-B)
  - hv_smoke.exe: open device → REGISTER → expect key

- [ ] **Step #5** — `IOCTL_HV_RESOLVE` + `IOCTL_HV_UNREGISTER`
  - METHOD_BUFFERED, by-name (Q11-B)
  - hv_smoke.exe: REGISTER → RESOLVE("notepad.exe") → UNREGISTER, 1000 cycles leak check (pool tag, session slots, PEPROCESS refs)

- [ ] **Step #6** — `IOCTL_HV_READ_SCATTER`
  - `METHOD_OUT_DIRECT` MDL system VA (Q4-B + Q7-B)
  - hv_smoke.exe: read notepad PE header, verify "MZ" magic

- [ ] **Step #7** — `IOCTL_HV_WRITE_MANY`
  - `METHOD_IN_DIRECT`
  - hv_smoke.exe: write+read scratch region

- [ ] **Step #8** — VMM concurrency primitives (Q20-B + Q21-C)
  - Per-resource spinlocks: `s_session_lock`, `s_ept_lock`, `s_proc_cache_lock`
  - Per-CPU log rings (`PerCpuLog.c`, ~4KB each, EfiRuntimeServicesData)
  - VMX-abort + machine-check NV flush to `OphnCrashDump`
  - `IOCTL_HV_GET_LOG` returns merged 12-CPU dump
  - Extend `read_ophn_log.ps1` parser

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

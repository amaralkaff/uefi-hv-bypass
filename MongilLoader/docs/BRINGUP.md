# MongilLoader bring-up runbook

Phase-by-phase to take MongilLoader from empty scaffold to live Vanguard
ESP that survives a 30-day burner-account test.

## Prereqs

- Test bench (separate physical machine, recommended): see Grill 17 hardware
  list. Or main rig with VHD per phase (accept HWID poisoning risk for Layer 2).
- ReviOS 10 19045 (matches main rig OS).
- Secure Boot OFF, hypervisorlaunchtype OFF, testsigning OFF, Hyper-V uninstalled.
- Vanilla EfiGuard already installed (`EfiGuard-v1.4` from `.tools\EfiGuard\`).
- `bench-base.vhdx` snapshot captured (fresh ReviOS, no EfiGuard).
- `bench-vanilla.vhdx` snapshot captured (base + vanilla EfiGuard).
- `vgk_probe.exe` (`detect/vgk_replica/`) calibration done on bench-vanilla.

## Phase 1 — Empty MongilLoader

Goal: combined loader builds, replaces vanilla EfiGuard's Loader.efi,
chains to Windows successfully, detect/vgk_replica/ probes report clean.

Steps:

1. Clone EDK2:
   ```powershell
   cd C:\Users\AmangLy\Documents\learning
   git clone https://github.com/tianocore/edk2.git
   cd edk2
   git submodule update --init --recursive
   ```

2. Build:
   ```powershell
   cd ..\MongilLoader
   .\scripts\build.ps1 -Phase 1
   ```
   Expect: `build\Loader.efi` + `build\OphionDxe.efi`. Sizes ~30KB / ~20KB.

3. Snapshot bench-vanilla, install:
   ```powershell
   .\scripts\install_efi.ps1
   .\scripts\add_safe_mode_nvram.ps1
   ```

4. Reboot. F12 boot menu shows:
   - MongilLoader (combined loader at existing EfiGuard NVRAM slot)
   - EfiGuard Safe Mode (fallback to backed-up Loader.original.efi)
   - Windows Boot Manager (vanilla, bypasses EfiGuard entirely)

5. Test fallback FIRST: pick "EfiGuard Safe Mode". Confirm Windows boots
   without Ophion (DSE+PG still bypassed via vanilla EfiGuard).

6. Reboot, default-boot MongilLoader. Watch console for:
   ```
   [MongilLoader] v0.1.0 (combined EfiGuard + Ophion)
   [MongilLoader] loaded \EFI\EfiGuard\EfiGuardDxe.efi
   [MongilLoader] loaded \EFI\Ophion\OphionDxe.efi
   [OphionDxe] phase 1 scaffold loaded
   [MongilLoader] chaining to Windows Boot Manager...
   [OphionDxe] ExitBootServices fired (phase 1 stub, no VMM launched)
   ```

7. Windows boots normally. Run `vgk_probe.exe --check` — all probes PASS
   (no HV present yet, this is correct: phase 1 has no VMM).

8. Snapshot `bench-mongil-empty.vhdx`. Phase 1 done.

## Phase 2 — VMM port to UEFI memory

Goal: port Ophion's vmx.c into UEFI environment (EfiRuntimeServicesCode
allocation), BSP-only VMLAUNCH from ExitBootServices callback, Windows
boots inside Ophion VM with VMCS auto MSR save/load list configured.

Pending. Picks up when Phase 1 verified end-to-end.

(Phase 3+ outlines TBD post-Phase-2.)

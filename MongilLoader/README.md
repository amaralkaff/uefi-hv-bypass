# MongilLoader

UEFI loader bundling EfiGuard + Ophion VMM, chained to Windows bootmgr.

Replaces `\EFI\EfiGuard\Loader.efi`. Single NVRAM entry boots:

1. EfiGuardDxe — patches DSE + PatchGuard during winload (existing EfiGuard
   behavior, vendored unchanged).
2. OphionDxe — registers ExitBootServices notification, allocates VMM body in
   `EfiRuntimeServicesCode`, performs BSP VMLAUNCH right before boot services
   close. Per-CPU AP intercept handled later via SIPI VMEXIT.
3. Chain to `\EFI\Microsoft\Boot\bootmgfw.efi` (Windows boot manager).

## Phase status

| Phase | Status   | Scope                                                  |
|-------|----------|--------------------------------------------------------|
| 1     | scaffold | Empty OphionDxe chains through to Windows              |
| 2     | TODO     | Port Ophion VMM body to UEFI memory model              |
| 3     | TODO     | AP SIPI intercept (Voyager pattern)                    |
| 4     | TODO     | ntos.text patch hijacking NtCreateProfile             |
| 5     | TODO     | Vanguard live test (read-only ESP)                     |

## Layout

```
MongilLoader/
├── Loader/              combined EFI bootloader entry
│   ├── Loader.c          loads EfiGuardDxe, then OphionDxe, then chains
│   ├── Loader.h
│   └── Loader.inf
├── OphionDxe/           Ophion as UEFI DXE driver
│   ├── OphionDxe.c       entry, ExitBootServices hook
│   ├── VmmInit.c         allocates VMM body in EfiRuntimeServicesCode
│   ├── KiServiceTable.c  resolves NtCreateProfile via KeServiceDescriptorTable
│   ├── NtosPatch.c       writes trampoline to NtCreateProfile prologue
│   ├── EfiCompat.h       NT-style typedefs / helpers for porting Ophion C
│   └── OphionDxe.inf
├── include/             shared headers
│   ├── OphionAbi.h       VMCALL ABI (op-codes, magic, three-factor auth)
│   └── BuildInfo.h       auto-generated per-build (SHA hashes, syscall #)
├── scripts/
│   ├── build.ps1         edksetup + nmake wrapper
│   ├── install_efi.ps1   replaces \EFI\EfiGuard\Loader.efi on bench
│   ├── add_safe_mode_nvram.ps1   adds fallback NVRAM entry
│   └── resolve_syscall.py        extracts NtCreateProfile syscall # from ntos.exe
└── docs/
    ├── BRINGUP.md       phase-by-phase bring-up runbook
    └── THREAT_MODEL.md  vgk detection surface vs Ophion mitigations
```

## Build

Requires EDK2 set up at `..\edk2\`. EfiGuard sources vendored as git submodule at
`vendor/EfiGuard`.

```powershell
.\scripts\build.ps1               # phase 1 (empty OphionDxe)
.\scripts\build.ps1 -Phase 2      # later
```

Outputs `build\Loader.efi` + `build\OphionDxe.efi`.

## Install (test bench only)

```powershell
.\scripts\install_efi.ps1                 # replaces \EFI\EfiGuard\Loader.efi
.\scripts\add_safe_mode_nvram.ps1         # adds fallback NVRAM entry
```

`install_efi.ps1` backs up the original to `\EFI\EfiGuard\Loader.original.efi`.
Fallback NVRAM entry points to that file. F12 boot menu shows:

- MongilLoader (default boot order 1)
- EfiGuard Safe Mode (boot order 2 — original EfiGuard, no Ophion)
- Windows Boot Manager (boot order 3 — bypass EfiGuard entirely)

## Safety rules

- **Test bench only.** Never install on a system that runs Vanguard during
  phases 1-4 (kdump still enabled, dumps could capture Ophion).
- **Always test safe-mode NVRAM entry first.** Reboot → F12 → pick "EfiGuard
  Safe Mode" → confirm Windows boots without Ophion. Only then default-boot
  MongilLoader.
- **Kill DebugView before any Vanguard layer.** `OPHION_DEV_MODE` builds emit
  `DbgPrintEx`; DebugView running while vgk is up = ban evidence.

See `docs/BRINGUP.md` for the full runbook.

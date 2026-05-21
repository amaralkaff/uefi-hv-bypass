# learning workspace

UEFI hypervisor + game security research.

## Layout

```
learning/
├── MongilLoader/    Loader.efi + OphionDxe.efi (UEFI VMM source)
│   ├── Loader/        chains EfiGuardDxe -> OphionDxe -> Windows boot.efi
│   ├── OphionDxe/     VT-x VMM, EBS notify hook, EPT cloak
│   └── build/         compiled .efi + Phase_*_known_good snapshots
├── Ophion/          ring 0 hypervisor (companion driver, post-Windows-boot)
├── detect/          hypervisor stealth probes (vgk_probe, vmaware)
├── scripts/         read_ophn_log.ps1 (read NV var log post-boot)
├── edk2/            UEFI build env (gitignored)
└── .tools/          EfiGuard-v1.4 (DSE+PG bypass)
```

## Boot setup

1. `bcdedit /set hypervisorlaunchtype off`
2. Copy to ESP partition (S:\):
   - `S:\EFI\Mongil\Loader.efi`
   - `S:\EFI\Ophion\OphionDxe.efi`
   - `S:\EFI\EfiGuard\EfiGuardDxe.efi`
3. Add NVRAM entry:
   ```
   bcdedit /copy {bootmgr} /d "Mongil + Ophion"
   bcdedit /set <new-id> path \EFI\Mongil\Loader.efi
   bcdedit /set {fwbootmgr} displayorder <new-id> /addfirst
   ```

## Per-boot workflow

1. Pick "Mongil + Ophion" in firmware menu (or auto-loads if first)
2. `EfiGuardDxe` patches PG + DSE
3. `OphionDxe` arms VMM at EBS notify (BSP only)
4. Windows boots inside guest
5. `read_ophn_log.ps1` confirms `OphnLastErr=VMLAUNCH_SUCCESS`
6. `EfiDSEFix.exe -d` flips DSE off (per session)
7. `sc start Ophion` loads ring 0 driver

## Build

```powershell
# UEFI VMM
.\edk2\build_mongil.cmd

# Ring 0 driver
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" `
  Ophion\Ophion.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false
```

## Anti-cheat compatibility

Tested on Win10 19045 + i5-12400F (Alder Lake) + UEFI mode + Secure Boot off.

| AC                  | Game examples            | Status |
|---------------------|--------------------------|--------|
| Vanguard            | VALORANT, League         | BROKEN |
| Faceit AC           | CS2 competitive          | BROKEN |
| EAC                 | Apex, Fortnite, Rust     | OK     |
| BattlEye            | R6, PUBG, DayZ, Arma 3   | OK     |
| Ricochet            | CoD MW3, Warzone         | OK     |
| Easy Anti-Cheat EOS | Multiversus, MultiCloud  | OK     |
| nProtect GameGuard  | MapleStory, Lineage      | OK     |
| XignCode3           | NARAKA, BlackDesert      | OK     |
| xhunter1            | Mongil Star Dive, GHOST  | OK     |
| EQU8                | Splitgate, Tarisland     | OK     |
| Hyperion            | RuneScape                | OK     |
| ESEA                | CS legacy                | OK     |
| VAC                 | CS:GO, Dota2, TF2        | OK     |
| ACE                 | CrossFire, PUBG Mobile   | OK     |
| Byfron              | Roblox                   | OK     |
| BadlionAnticheat    | Minecraft                | OK     |
| FairFight           | Battlefield              | OK     |
| Sentry              | League legacy            | OK     |
| Hyper-V required    | Any VBS-on title         | BROKEN |

OK = verified no detection, no BSOD.
BROKEN = confirmed fails.

Vanguard fix path: Phase 3d-iv-b multi-core virt via ring 0 broadcast (open).

## Known limits

- BSP-only virt wedges under heavy AC load -> 0x101 CLOCK_WATCHDOG_TIMEOUT
- All 12 cores virt'd via ring 0 driver fixes this (Phase 3d-iv-b unfinished)

## Pitfalls

- KDU runtime DSE patch -> 0x109 PG BSOD. Use EfiGuard instead.
- CR0 pass-through (`mask=0`) lets guest break VMX fixed bits. Mask `FIXED0 | ~FIXED1 | WP`.
- `MmGetVirtualForPhysical` returns NULL for pool memory. Cache PML1 ptr at EPT split.
- `INVEPT` from PASSIVE_LEVEL fails. Use VMCALL via DPC broadcast.
- xhunter1 strips handle rights. Route reads via `IOCTL_HV_MEM_READ` (`MmCopyVirtualMemory`).

## Verify state

```powershell
& 'C:\Users\Administrator\Documents\learning\scripts\read_ophn_log.ps1'
```

Expect: `OphnLastErr=VMLAUNCH_SUCCESS`, `OphnFirstBad=absent`, `OphnExit n=2 reason=0xA`.

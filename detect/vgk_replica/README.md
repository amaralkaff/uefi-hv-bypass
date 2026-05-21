# vgk_replica - Vanguard-replica detection probe suite

User-mode (+ optional kernel companion) probe that replicates the checks
`vgk.sys` performs at runtime. Validates Ophion's stealth posture before
exposing any account to live Vanguard.

## Coverage

| Probe | Replicates                                      | Mode |
|-------|-------------------------------------------------|------|
| `cpuid_hv_present_bit`            | CPUID.1.ECX[31] cleared                   | usermode |
| `cpuid_leaf_0x40000000_zeroed`    | hxv `kHvSignatures` table                  | usermode |
| `cpuid_hyperv_root_partition`     | vmaware `is_root_partition`               | usermode |
| `cpuid_hv_signatures_full_scan`   | leaves 0x40000000..0x400000FF             | usermode |
| `msr_hv_synthetic_range_gp`       | Hyper-V / KVM MSRs must #GP                | kernel  |
| `msr_ia32_debugctl_lbr_set`       | vgk per-CPU canary LBR requirement         | kernel  |
| `cr4_smep_at_idle`                | vgk_cr4_enforcement_check SMEP             | kernel  |
| `cr4_smap_at_idle`                | SMAP enforcement                            | kernel  |
| `cr4_osxsave`                     | OSXSAVE required for XGETBV anti-debug     | kernel  |
| `timing_rdtsc_cpuid_delta`        | vmaware / hvdetecc timing attack           | usermode |
| `nic_mac_oui_not_banned`          | hxv `kOuiTable`                             | usermode |
| `smbios_uuid_wellformed`          | vgk SMBIOS UUID check                       | usermode |
| `smbios_vendor_strings`           | banned vendor substrings (QEMU/VBox/etc.)  | usermode |
| `topology_processor_count`        | low-core-count heuristic                    | usermode |
| `topology_apic_consistency`       | CPUID 0xB APIC info present                 | usermode |

## Build

```powershell
# user-mode only
.\build_probe.ps1

# include kernel companion (requires WDK)
.\build_probe.ps1 -Drv

# install to .\bin
.\build_probe.ps1 -Drv -Install
```

## Run

**Step 1 — calibrate (on CLEAN Windows, no HV active)**

```powershell
.\bin\vgk_probe.exe --calibrate
```

Captures bare-metal RDTSC-CPUID baseline to `%LOCALAPPDATA%\vgk_probe\baseline.json`.
Do this BEFORE installing MongilLoader/Ophion.

**Step 2 — load kernel companion (privileged probes)**

```powershell
sc.exe create VgkProbeDrv type=kernel binPath=C:\full\path\VgkProbeDrv.sys
sc.exe start VgkProbeDrv
```

**Step 3 — check (after enabling Ophion)**

```powershell
.\bin\vgk_probe.exe --check
.\bin\vgk_probe.exe --check --json > report.json
```

Exit codes: 0 = all PASS, 1 = at least one FAIL, 2 = SKIP (load probe_drv).

## SECURITY

`VgkProbeDrv` exposes user-mode RDMSR. **Dev test bench only.** Never load on
a system that runs Vanguard / other anti-cheats — it itself is a BYOVD primitive.

```powershell
# unload before any Vanguard activity
sc.exe stop VgkProbeDrv
sc.exe delete VgkProbeDrv
```

## Calibration policy

Baseline is CPU-specific. Re-run `--calibrate` whenever you move to a
different physical CPU (different test bench, replaced CPU). The threshold
is `3 * baseline_p99` for the RDTSC-CPUID timing probe.

## Output

Console (default):

```
=== vgk_probe v0.1.0 ===
[PASS       ] cpuid_hv_present_bit               (cpuid   )
[PASS       ] cpuid_leaf_0x40000000_zeroed       (cpuid   )
[FAIL       ] msr_hv_synthetic_range_gp          (msr     ) MSR 0x40000000 returned value 0x... (no #GP)
...
Summary: 12 pass / 1 fail / 0 skip
```

JSON (`--json`) suitable for CI parsing.

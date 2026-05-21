# Threat model — Ophion vs Vanguard (vgk.sys 12.x / 2026)

Derived from `full analysis.txt` (hxv 2026 dump) and confirmed via
`detect/vgk_replica/` probe coverage.

## Detection surface (vgk-side)

| vgk component                       | Threat to Ophion                | Mitigation                                                                                  |
|-------------------------------------|---------------------------------|---------------------------------------------------------------------------------------------|
| CPUID 0x40000000 + leaf 1 ECX[31]   | HV-vendor signature             | Ophion CPUID exit returns native zeros for 0x4000xxxx, clears bit 31 on leaf 1               |
| MSR 0x40000000-0x4FFFFFFF           | HV synthetic MSRs               | Ophion MSR exit injects #GP for entire range                                                 |
| RDTSC-CPUID-RDTSC timing            | HV-cost delta                   | STEALTH_COMPENSATE_TIMING returns compensated RDTSC after CPUID exit                          |
| CR4.SMEP/SMAP at idle               | per-CPU canary 50ms check        | host CR4 keeps SMEP+SMAP set; guest CR4 shadow preserves bits                                |
| IA32_DEBUGCTL bit 0 (LBR) at idle   | per-CPU canary LBR validator     | VMCS auto MSR save/load list isolates LBR ring between host/guest                            |
| PMC0/PMC1 branch-retired sample     | HV-cost via retired branches    | trap RDPMC, compensate by bare-metal cost constants (Phase 4)                                |
| LBR ring (32 MSR pairs)             | host branches visible            | VMCS auto save/load list: host runs DEBUGCTL=0, LBR ring cleared                             |
| PsLoadedModuleList walk every 1.5s  | enumerate kernel modules         | UEFI VMM body in EfiRuntimeServicesCode is NOT in PsLoadedModuleList                          |
| BYOVD image-load callback           | cert chain + name + bytes scan   | no NT driver loaded — channel is ntos.text patch to NtCreateProfile                          |
| MmCopyVirtualMemory hook (slot 7)   | external memory reads            | Ophion VMM uses manual PT walk in VMX-root; never calls NT API                              |
| Per-CPU canary integrity timer      | drift between samples            | VMM exits bounded <10us; TSC monotonic; LBR isolated via auto save/load list                |
| section-hash drift detector         | covers vgk's own .text/.rdata    | does not police ntos or third-party drivers (per hxv 4.42)                                    |
| HalCollectPmcCounters hook          | PMC stack walker                 | walker validates RIP in `0xFFFFF8011A211000..D19`; our VMCALL via NtCreateProfile body lands inside  |
| 15-slot syscall hook (sub_AD93B08)  | hooks ZwClose, MmCopyVM, etc.    | NtCreateProfile NOT in the 15 slots; channel invisible to PMC dispatcher                      |
| vgk_byovd_check_signing             | rejects test-cert drivers        | no driver loaded; ntos.text patch bypasses cert path                                          |
| Cat 21 process21regex               | "cheat hack inject" name scan    | cheat exe random name per build, no flagged substrings                                       |
| window classifier `g_windowlist_rules` | ImGui / fake-VAL / random-CMD  | overlay uses `MS_AlphaWindowClass` + benign title + `WS_EX_TOOLWINDOW`                       |
| USB blocklist (Arduino/CH340/etc.)  | input-injection HW              | read-only ESP v1, no HID injection                                                            |
| MAC OUI anti-VM table               | VMware/VBox/KVM OUIs            | bench HW uses real consumer NIC OUI                                                          |
| SMBIOS UUID well-formedness         | all-zeros/all-FFs flag           | real HW SMBIOS                                                                                |
| HWID drift detector                 | within-session changes            | per-account stable HWID; no per-boot rotation within a session                                |

## Open / deferred

| Item                                      | Status        |
|-------------------------------------------|---------------|
| PMC compensation (RDPMC trap)             | Phase 4       |
| Per-account HWID tooling                  | acc bring-up  |
| Behavioral ML mitigation                  | scope: read-only ESP minimizes; user discipline beyond stack |
| Anti-screenshot via WDA_EXCLUDEFROMCAPTURE | logged by vgk slot 14 but benign use accepted; revisit if tested-banned |

## Probe coverage validation

`vgk_probe.exe --check` runs all above mitigations against current bench
state. Layer 1 of test methodology: must report 0 FAIL with full kernel
probe_drv loaded before MongilLoader/Ophion installed (= bare metal posture).

After MongilLoader + Ophion installed, Layer 1 must STILL report 0 FAIL
(= stealth posture intact).

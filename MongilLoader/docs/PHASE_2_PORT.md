# Phase 2 — Ophion VMM port to UEFI DXE

Generated 2026-05-18 after Phase 0 baseline clean. Maps `Ophion/src/vmx.c` (kernel-driver VMM) to `MongilLoader/OphionDxe/` (UEFI DXE driver) line-by-line.

## Source files cataloged

```
Ophion/src/vmx.c        731 LOC  vmx_check_support, vmx_alloc_vmxon/vmcs, vmx_setup_vmcs,
                                  vmx_virtualize_cpu (per-core DPC entry), vmx_init (top-level)
Ophion/src/broadcast.c   77 LOC  KeGenericCallDpc fanout for per-core VMXON
Ophion/include/hv.h     117 LOC  prototypes + globals
Ophion/include/hv_types.h 184 LOC VIRTUAL_MACHINE_STATE struct (per-VCPU state)
```

## Windows kernel API → UEFI equivalent

| Windows kernel API | UEFI equivalent | Notes |
|---|---|---|
| `MmAllocateContiguousMemory(size, MAXULONG64)` | `EfiAllocateRuntimePages(pages)` | already in `EfiAlloc.c`. UEFI returns identity-mapped page. |
| `ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag)` | `EfiAllocateRuntimePages(pages)` | same backing — `EfiRuntimeServicesCode` |
| `MmFreeContiguousMemory(va)` | `EfiFreeRuntimePages(va, pages)` | already in `EfiAlloc.c` |
| `ExFreePoolWithTag(va, tag)` | `EfiFreeRuntimePages(va, pages)` | track page count alongside ptr |
| `RtlZeroMemory(buf, n)` | `ZeroMem(buf, n)` | `BaseMemoryLib` |
| `RtlCopyMemory(dst, src, n)` | `CopyMem(dst, src, n)` | `BaseMemoryLib` |
| `va_to_pa(va)` (`MmGetPhysicalAddress`) | identity in UEFI; VA == PA pre-ExitBootServices | **after** EBS + Windows CR3 swap, identity breaks. See "VA/PA contract change" below. |
| `pa_to_va(pa)` (`MmGetVirtualForPhysical`) | identity pre-EBS | **post-EBS:** must walk private host PT |
| `MmIsAddressValid(va)` | not available | walk CR3 PT manually if needed |
| `MmGetSystemRoutineAddress(L"Sym")` | not available | resolve later via ntoskrnl PE export scan after Windows boots; defer to Phase 4 |
| `KeQueryActiveProcessorCount(0)` | `gMpServices->GetNumberOfProcessors(...)` | boot-services-time only |
| `KeGetCurrentProcessorNumberEx(NULL)` | `gMpServices->WhoAmI(...)` OR `IA32_TSC_AUX & 0xFFF` | TSC_AUX path works post-EBS too (already used in `vmx_get_cpu_id`) |
| `KeGenericCallDpc(routine, ctx)` | `gMpServices->StartupAllAPs(...)` OR persistent INIT-SIPI-SIPI | **boot-services-time only.** Post-EBS APs are dormant until Windows wakes them. Phase 2 = BSP only; Phase 3 = AP SIPI intercept (Voyager pattern). |
| `KeSignalCallDpcDone/Synchronize` | n/a | rolled into MP-services semantics |
| `DbgPrintEx(...)` | `Print(L"...")` at boot, ring buffer at runtime | Print disappears post-EBS; use ring buffer in EfiRuntimeServicesData, expose via VMCALL |
| `RtlInitUnicodeString` | n/a | no `\Device\Foo` user-mode IOCTL channel from VMM |
| `KeStackAttachProcess` / `Unstack...` | n/a | no Windows EPROCESS at VMM-launch time |
| `IoCreateDevice` / `IoCreateSymbolicLink` | n/a | no usermode channel until Windows is up |

## Memory model deltas (the hard parts)

### VA/PA contract change at SetVirtualAddressMap

UEFI guarantees identity mapping while boot services are active. After the boot loader (bootmgfw → winload → ntoskrnl) calls `SetVirtualAddressMap`, our `EfiRuntimeServicesCode` pages get remapped to *virtual* addresses Windows chooses. From that point on:

- Physical addresses for VMXON/VMCS/EPT/bitmaps remain stable (still the same RAM).
- Their virtual addresses change.
- `__vmx_on(&vmxon_pa)`, `__vmx_vmptrld(&vmcs_pa)`, etc. take **PA** — these still work.
- C dereferences against stored `vmxon_va` / `vmcs_va` (from `EfiAllocateRuntimePages` return) fail unless we either:
  1. Build private host CR3 (`USE_PRIVATE_HOST_CR3`) and load it as `VMCS_HOST_CR3` before VMLAUNCH, or
  2. Re-derive VA after `SetVirtualAddressMap` via the runtime-services convert-pointer callback.

**Phase 2.5 plan**: Capture every allocation's PA at alloc time. Build private host PT mapping each allocation as `PA → PA` (identity in host CR3). VMCS_HOST_CR3 = our private CR3. VMM-root code accesses everything via PA-as-VA — never touches the Windows page tables.

### EPT identity map

`Ophion/src/ept.c::ept_init` builds a 512 GiB identity EPT with proper MTRR memory types. Direct port to UEFI is mostly mechanical (replace `ExAllocatePool2`/`MmAllocateContiguousMemory` with `EfiAllocateRuntimePages`). Two snags:

1. MTRR scan reads `IA32_MTRRCAP` + variable/fixed MTRRs. Same MSR layout, ports cleanly.
2. PML2 large-page split uses `ExAllocatePool2` for the dynamic split list. Same fix as above.

### Per-VCPU allocations

`vmx_init` loop allocates per-core: vmm_stack (32KB), msr_bitmap (4KB), io_bitmap_a (4KB), io_bitmap_b (4KB), vmxon_region (8KB+align), vmcs_region (8KB+align). For 12-core i5-12400F = 12 × ~60KB = ~720KB total in `EfiRuntimeServicesCode`.

## Multi-processor model deltas

| Concern | Ophion (Windows) | UEFI/Phase 2 | Phase 3 |
|---|---|---|---|
| BSP virtualize | DPC on core 0 | direct call from `VmmArm` | unchanged |
| AP virtualize | `KeGenericCallDpc` fanout | **deferred** | SIPI intercept (Voyager pattern). When NT issues SIPI to wake APs, EPT-trap the SIPI vector page, run our trampoline that does VMXON+VMLAUNCH per AP, then continue NT's SIPI handler |
| Per-core sync | `KeSignalCallDpcSynchronize` | n/a (BSP only) | spinlock on shared vcpu table |
| Core ID | `KeGetCurrentProcessorNumberEx` | `IA32_TSC_AUX & 0xFFF` (works) | same |

## What ports cleanly (no logical changes)

- `vmx_check_support()` — pure CPUID + MSR reads. Already mostly done in `OphionDxe.c::ProbeVmxSupport` and `VmmInit.c::VmmVmxSupported`.
- `vmx_adjust_controls()` — pure MSR arithmetic. Copy verbatim.
- `vmx_set_fixed_bits()` — pure CR0/CR4/MSR. Copy verbatim. Already in `VmmInit.c::VmmFixupCr0Cr4`.
- All `__vmx_vmwrite` calls in `vmx_setup_vmcs` — VMX intrinsics work identically.
- All segment_get_descriptor / segment_fill_vmcs logic — pure GDT walking.
- All asm_get_* helpers — same MASM source compiles under EDK2 with adjusted preprocessor.
- CR0 fixed-bit shadow + WP mask logic (lines 327-334 of vmx.c) — keep verbatim. See `feedback_vmx_cr0_shadow.md`.
- VMCS_CTRL_EXCEPTION_BITMAP = (1<<3) for #BP — keep for Phase 4 EPT hook.

## What requires logic changes

- `vmx_alloc_vmxon` / `vmx_alloc_vmcs` — allocator swap only. Skip `MmAllocateContiguousMemory`'s 2x+align trick (EFI's `AllocatePages` already returns 4KB-aligned). Single page per region.
- `vmx_init` — drop `KeGenericCallDpc(dpc_init_guest, NULL)`; replace with direct `vmx_virtualize_cpu(stack)` call on BSP only for Phase 2. Add Phase 3 SIPI intercept later.
- `broadcast_terminate_all` — drop entirely for Phase 2 (no graceful unload from VMM in EFI; this is one-way).
- `xhook_dpc_invept` — defer to Phase 4.

## Phase 2 minimal milestone (BSP-only VMLAUNCH)

Goal: prove VMLAUNCH on BSP from `VmmArm` callback, run guest = continued boot of bootmgfw → winload → ntoskrnl, hit one CPUID exit, log it, VMRESUME. No EPT hooks, no AP virtualization, no usermode channel.

Concrete file plan:

| File | Status | Phase 2 work |
|---|---|---|
| `MongilLoader/OphionDxe/OphionDxe.c` | scaffold | call `VmmInitialize` → `VmmVirtualizeBsp` from `VmmArm` |
| `MongilLoader/OphionDxe/VmmInit.c` | probe + alloc | + private host CR3, + private host GDT/IDT, + per-VCPU EPT |
| `MongilLoader/OphionDxe/VmmVmcs.c` (NEW) | -- | port `vmx_setup_vmcs` (450 LOC). Strip Windows-specific bits |
| `MongilLoader/OphionDxe/VmmEpt.c` (NEW) | -- | port `ept_init` + MTRR scan + identity 512G map |
| `MongilLoader/OphionDxe/VmmExit.c` (NEW) | -- | minimal `vmexit_handler` — CPUID passthrough + VMCALL(VMXOFF) |
| `MongilLoader/OphionDxe/asm/Vmx.S` (NEW) | -- | port `Ophion/asm/*.asm` to GAS or EDK2-MASM. asm_get_*, asm_vmx_save_state, asm_vmexit_handler |
| `MongilLoader/OphionDxe/HostCr3.c` (NEW) | -- | port `Ophion/src/hostcr3.c` — build private 4-level PT mapping our allocations identity (PA=VA) |
| `MongilLoader/OphionDxe/HostGdt.c` (NEW) | -- | port `Ophion/src/hostgdt.c` |
| `MongilLoader/OphionDxe/HostIdt.c` (NEW) | -- | port `Ophion/src/hostidt.c` — minimal IDT with NMI handler stub |

Phase 2 *anti-goals*: do not port stealth.c, modwatch.c, xhunter_hook.c, memreader.c yet. They depend on Windows-side context that doesn't exist at boot.

## VMCS_HOST_RIP target

Ophion uses `asm_vmexit_handler` (asm trampoline that saves GPRs to a `GUEST_REGS` struct on VMM stack, then calls C `vmexit_handler(regs, vcpu)`). Same pattern in UEFI port — only the .asm file location and assembler directives change. Build via EDK2 `[Sources]` + `.s` file.

## VMCS_HOST_RSP target

`(UINT64)vcpu->vmm_stack + VMM_STACK_SIZE - 16` (16-byte aligned). Top-8 of stack = vcpu pointer (assembly retrieves it). Same layout works in UEFI; no Windows dep.

## VMM_STACK as `EfiRuntimeServicesCode`?

Strictly the stack should be `EfiRuntimeServicesData` (write-targeted), not Code. Current `EfiAllocateRuntimePages` always uses `EfiRuntimeServicesCode`. Consider splitting into `EfiAllocateRuntimeData(pages)` + `EfiAllocateRuntimeCode(pages)`. Risk if all-in-Code: Windows may mark them NX in its post-EBS conversion, breaking VMM stack writes when CPU is in host mode. Verify by reading SDK contract — `EfiRuntimeServicesCode` historically permits R+W+X by VMM in host CR3 even after Windows marks Windows CR3's view NX.

**Action item**: review `MongilLoader/OphionDxe/EfiAlloc.c` after Phase 2 first VMLAUNCH attempt. If host-mode stack writes fault, add `EfiAllocateRuntimeData` variant and re-route stack/bitmap allocations.

## Risk budget for Phase 2.5 first launch

| Failure mode | Detect | Recover |
|---|---|---|
| VMLAUNCH error 0x...n | `VMCS_VM_INSTRUCTION_ERROR` read fallback | log via Print pre-EBS, abort boot-loader chain, reboot to {bootmgr} fallback |
| Bad host CR3 → #PF in host mode | triple-fault → reboot | NVRAM second entry = Windows Boot Manager ({bootmgr}). Already configured. |
| Bad VMCS_HOST_RIP | triple-fault | same |
| EPT misconfigured → vmexit handler can't read guest memory | log "EPT_violation guest_pa=0x..." pattern | adjust ept_init, retry |

NVRAM safety net = `{bootmgr}` second in displayorder. F12 fallback already proven this session.

## Build deltas

EDK2 project file (`MongilLoader/OphionDxe/OphionDxe.inf`) needs new entries:
- `[Sources]`: VmmVmcs.c, VmmEpt.c, VmmExit.c, HostCr3.c, HostGdt.c, HostIdt.c, asm/Vmx.S
- `[BuildOptions]`: same MSVC flags currently in OphionDxe.inf

Compiler flags: `/Od` for first attempt (debuggability), switch to `/O2` once VMLAUNCH stable.

# Phase 2 — Ophion VMM port to UEFI DXE

Generated 2026-05-18 after Phase 0 baseline clean. Maps `Ophion/src/vmx.c` (kernel-driver VMM) to `MongilLoader/OphionDxe/` (UEFI DXE driver) line-by-line.

## Status (2026-05-18 end of session)

**Phase 2 minimum-buildable milestone reached + hostcr3 deep-clone wired in.** All paths compile + link clean. VMLAUNCH not yet wired (deferred to Phase 2.5).

```
OphionDxe.efi   56832 bytes (was 22016 pre-port; jump from 24064 → 56832 came
                              from VmmHostCr3.c force-linking via touchpoints
                              in OphionDxe.c, pulling clone code through LTCG)
Loader.efi      10752 bytes (unchanged)
ESP staged at S:\EFI\Ophion\OphionDxe.efi
```

| File | Status | LOC | Notes |
|---|---|---:|---|
| `EfiCompat.h` | done | 78 | NT-style typedefs over EDK2 base; LIST_ENTRY uses BaseLib |
| `ia32.h` | done | 1122 | Verbatim from Ophion, NT include swapped for EfiCompat |
| `hv_types.h` | done | 184 | Verbatim |
| `asm/Asm*.asm` | done (7 files) | ~600 | Verbatim from Ophion `asm/`; ml64 + EDK2 toolchain |
| `VmmGlobals.c` | done | 21 | g_vcpu, g_ept, g_cpu_count, g_host_idt, g_host_nmi_pending |
| `VmmUtil.c` | done | 112 | va_to_pa identity, segment_get_descriptor, segment_fill_vmcs |
| `VmmLog.c` | done | 40 | hv_log via Print pre-EBS; ring buffer post-EBS deferred |
| `VmmEpt.c` | done | 343 | MTRR scan + identity 512G EPT, 2MB large pages |
| `VmmVmcs.c` | done | 476 | vmx_check_support, vmx_alloc_vmxon/vmcs, vmx_setup_vmcs, vmx_virtualize_cpu, vmx_init |
| `VmmExit.c` | done | 120 | Minimal CPUID passthrough, VMCALL VMXOFF dispatch, #UD on bad VMCALL |
| `VmmHostCr3.c` | done | 249 | Deep-clone PML4 → private host CR3; uses CopyMem (not memcpy) to avoid intrinsic. NOT yet wired into VMCS_HOST_CR3 — VmmVmcs.c still calls get_system_cr3() |
| `VmmInit.c` | done | 102 | VmmInitialize calls vmx_init(1) on BSP only |
| `HostGdt.c` | **DEFERRED** | 0 | Phase 2 uses system GDT. USE_PRIVATE_HOST_GDT branch dropped from VmmVmcs.c |
| `HostIdt.c` | **DEFERRED** | 0 | Phase 2 uses system IDT for HOST_IDTR_BASE |

## What Phase 2.5 still needs

1. **Wire VmmInitialize → hostcr3_build → vmx_virtualize_cpu**. Currently VmmInitialize stops after `vmx_init(1)` with `Print("alloc done; VMXON/VMLAUNCH deferred to phase 2.5")`. Need to add (in order):
   ```c
   if (!hostcr3_build()) { hv_log("hostcr3 build failed"); return; }
   // swap VmmVmcs.c::vmx_setup_vmcs to use hostcr3_get() instead of get_system_cr3()
   vmx_set_fixed_bits();
   asm_vmx_save_state();  // → vmx_virtualize_cpu(rsp) → VMXON/VMCLEAR/VMPTRLD/setup/VMLAUNCH
   ```
2. **Apply VMXE in CR4** — `vmx_set_fixed_bits()` does this; VmmInit currently skips it intentionally to keep pre-VMLAUNCH boot path side-effect-free.
3. **HOST_RIP target sanity check** — confirm `asm_vmexit_handler` lives in EfiRuntimeServicesCode-marked memory after Windows assumes paging, otherwise host-mode RIP fetches will fault. Should be the case since the entire DXE is loaded into runtime-marked pages, but worth a verify at first launch.
4. **First VMLAUNCH error code map** — when it fails, `VMCS_VM_INSTRUCTION_ERROR` will name the broken VMCS field. Log + iterate.

## What Phase 2.5 does NOT need (already in place this session)

- ✅ Per-VCPU VMXON region allocated, revision-id stamped
- ✅ Per-VCPU VMCS region allocated, revision-id stamped
- ✅ Per-VCPU MSR bitmap (with TSC + FEATURE_CONTROL + VMX-cap MSRs trapped)
- ✅ Per-VCPU IO bitmaps A/B
- ✅ Per-VCPU VMM stack (32KB), vcpu pointer at top-8
- ✅ EPT identity-map 512G with 2MB large pages, MTRR-aware memory typing
- ✅ Full vmx_setup_vmcs (host/guest state, EPTP, EPTE, exception bitmap, CR0 fixed-bit shadow + WP)
- ✅ Minimal vmexit handler (CPUID, VMCALL VMXOFF, #UD inject, RIP advance)
- ✅ VMCALL signature path via asm_vmx_vmcall (HVFS / VMCALL / NOHYPERV in r10/r11/r12)
- ✅ INVEPT / INVVPID wrappers
- ✅ Private host CR3 deep-clone (allocated, populated, fixed self-ref entry)

## Boot risk envelope for Phase 2.5

| Failure mode | Detect | Recover |
|---|---|---|
| VMLAUNCH error 0x...n | `VMCS_VM_INSTRUCTION_ERROR` read fallback | log via Print pre-EBS, abort boot-loader chain, reboot to {bootmgr} fallback |
| Bad host CR3 → #PF in host mode | triple-fault → reboot | NVRAM 2nd entry = Windows Boot Manager. Already configured. |
| Bad VMCS_HOST_RIP | triple-fault | same |
| EPT misconfigured → vmexit handler can't read guest memory | log "EPT_violation guest_pa=0x..." pattern | adjust ept_init, retry |
| Wrong RFLAGS at VMLAUNCH | failure code 7 (invalid host-state field) | inspect saved RFLAGS in asm_vmx_save_state |

Recovery escape hatch: F12 → Windows Boot Manager (still 2nd in NVRAM). Already proven this session.

## Multi-processor model (unchanged from earlier plan)

Phase 2 BSP-only is locked in. Phase 3 = Voyager-style SIPI intercept for AP virtualize. `g_cpu_count = 1` hard-coded for Phase 2.

## Build chain verified

```
EDK2 toolchain (VS2026) compiles 7 .asm files via ml64
+ 12 C files including the hv_types/ia32 headers
+ links against MdePkg BaseLib for LIST_ENTRY helpers + CpuDeadLoop

Output:
  OphionDxe.dll → OphionDxe.efi (DXE_DRIVER, x64, 24064 bytes)
  asm symbols verified in linker map (asm_vmexit_handler @ +0x4050,
  asm_vmx_save_state @ +0x4150, vmexit_handler @ +0x1bf8)
```

## Source files cataloged

```
Ophion/src/vmx.c        731 LOC  vmx_check_support, vmx_alloc_vmxon/vmcs, vmx_setup_vmcs,
                                  vmx_virtualize_cpu (per-core DPC entry), vmx_init (top-level)
Ophion/src/broadcast.c   77 LOC  KeGenericCallDpc fanout for per-core VMXON
Ophion/include/hv.h     117 LOC  prototypes + globals
Ophion/include/hv_types.h 184 LOC VIRTUAL_MACHINE_STATE struct (per-VCPU state)
```

## Windows kernel API → UEFI equivalent

| Windows kernel API | UEFI equivalent | Phase 2 status |
|---|---|---|
| `MmAllocateContiguousMemory(size, MAXULONG64)` | `EfiAllocateRuntimePages(pages)` | done |
| `ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag)` | `EfiAllocateRuntimePages(pages)` | done |
| `MmFreeContiguousMemory(va)` | `EfiFreeRuntimePages(va, pages)` | done (already in EfiAlloc.c) |
| `ExFreePoolWithTag(va, tag)` | `EfiFreeRuntimePages(va, pages)` | done — page count tracked |
| `RtlZeroMemory(buf, n)` | `ZeroMem(buf, n)` (BaseMemoryLib) | done |
| `RtlCopyMemory(dst, src, n)` | `CopyMem(dst, src, n)` | done |
| `va_to_pa(va)` (`MmGetPhysicalAddress`) | identity in UEFI; VA == PA pre-ExitBootServices | done (VmmUtil.c) |
| `pa_to_va(pa)` (`MmGetVirtualForPhysical`) | identity pre-EBS | done (VmmUtil.c) |
| `MmIsAddressValid(va)` | not available | not yet needed |
| `MmGetSystemRoutineAddress(L"Sym")` | not available | Phase 4 |
| `KeQueryActiveProcessorCount(0)` | `gMpServices->GetNumberOfProcessors(...)` | Phase 3 (BSP=1 for now) |
| `KeGetCurrentProcessorNumberEx(NULL)` | `IA32_TSC_AUX & 0xFFF` | done (works post-EBS too) |
| `KeGenericCallDpc(routine, ctx)` | `gMpServices->StartupAllAPs` OR SIPI intercept | Phase 3 |
| `DbgPrintEx(...)` | `Print(L"...")` pre-EBS, ring buffer post-EBS | done (Print only; ring buffer deferred) |

## Files referenced

| Path | Role |
|---|---|
| `MongilLoader/OphionDxe/Vmm*.c` | This phase's port |
| `MongilLoader/OphionDxe/asm/Asm*.asm` | Verbatim port from Ophion/asm/ |
| `Ophion/src/vmx.c` | Source-of-truth Windows-driver VMM |
| `Ophion/include/hv_types.h` + `ia32.h` | Headers (now duplicated into MongilLoader/OphionDxe/) |
| `MongilLoader/OphionDxe/OphionDxe.inf` | EDK2 build manifest with full source list |
| `edk2/build_mongil.cmd` | Toolchain wrapper |

## Next concrete actions (Phase 2.5)

1. Wire `VmmInitialize` to call `vmx_set_fixed_bits()` then `asm_vmx_save_state()` on BSP. Note: `asm_vmx_save_state` calls `vmx_virtualize_cpu(rsp)` → `__vmx_on(&vcpu->vmxon_pa)` → VMCS setup → `__vmx_vmlaunch`. On success, returns to `asm_vmx_restore_state`. On failure, falls through (logs error, vmxoff, continues boot).
2. Boot test on dev rig. Triple-fault path = reboot to {bootmgr} fallback (NVRAM 2nd entry). VMCS_VM_INSTRUCTION_ERROR will name the bad field on VMLAUNCH failure.
3. Iterate VmmVmcs.c::vmx_setup_vmcs until VMLAUNCH succeeds and a CPUID exit fires.
4. Once first exit fires + VMRESUME loop holds: Phase 2.5 done, port hostcr3.c next for isolation.

Ready to pick up Phase 2.5 next session.

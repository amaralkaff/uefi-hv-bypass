/*
 * VmmInit.c - top-level Ophion VMM bring-up entry called from OphionDxe.c::VmmArm
 *
 * Phase 2 (current): probe VMX support, call vmx_init() to allocate per-VCPU
 * regions (VMXON, VMCS, MSR bitmap, IO bitmap, vmm stack, EPT identity map).
 * Log + return — no VMXON, no VMLAUNCH.
 *
 * Phase 2.5 (next): call vmx_virtualize_cpu(rsp) on BSP from here. Real VMM
 * dispatcher in VmmExit.c. Apply CR0/CR4 fixed bits + VMXE before VMXON.
 *
 * Phase 3: AP SIPI intercept (Voyager pattern), per-AP virtualize from inside
 * the bootstrap trap, INVEPT broadcast.
 */
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "ia32.h"
#include "hv_types.h"

extern BOOLEAN vmx_init(UINT32 cpu_count);
extern BOOLEAN vmx_check_support(VOID);
extern VOID    vmx_set_fixed_bits(VOID);
extern BOOLEAN hostcr3_build(VOID);
extern UINT64  hostcr3_get(VOID);
extern BOOLEAN hostgdt_build(VOID);
extern UINT64  hostgdt_get_gdt_base(VOID);
extern UINT64  hostgdt_get_tss_base(VOID);
extern UINT16  hostgdt_get_tr_sel(VOID);
extern BOOLEAN hostidt_build(VOID);
extern UINT64  hostidt_get_base(VOID);
extern VOID    hv_log(IN CONST CHAR8 *fmt, ...);
extern UINTN   VmmMpGetCpuCount(VOID);
extern VOID    VmmLogVarSetf(IN CONST CHAR16 *Name, IN CONST CHAR8 *Fmt, ...);
extern BOOLEAN VmcsAllocMinimalLoadList(VOID);
extern UINT64  VmcsGetVmexitLoadListPa(VOID);
extern UINT32  VmcsGetVmexitLoadCount(VOID);
extern VOID    VmmPclInit(IN UINT32 cpu_count);

extern VIRTUAL_MACHINE_STATE *g_vcpu;
extern UINT32                 g_cpu_count;

//
// VmmVmxSupported — also in OphionDxe.c::ProbeVmxSupport but with EFI logging.
// Kept here for the VmmInitialize prologue print path.
//
BOOLEAN
VmmVmxSupported(VOID)
{
    int regs[4];
    __cpuid(regs, 1);
    if (!(regs[2] & (1 << 5))) {
        Print(L"[VmmInit] CPUID.1.ECX[5] = 0; VMX absent\n");
        return FALSE;
    }
    UINT64 fc = __readmsr(IA32_FEATURE_CONTROL);
    if ((fc & 1ULL) && !(fc & (1ULL << 2))) {
        Print(L"[VmmInit] FC=0x%llx locked w/o VMX-outside-SMX\n", fc);
        return FALSE;
    }
    if (!(fc & 1ULL)) {
        // BIOS didn't lock; we lock it ourselves with VMX bit set.
        UINT64 newfc = fc | 1ULL | (1ULL << 2);
        __writemsr(IA32_FEATURE_CONTROL, newfc);
        Print(L"[VmmInit] FC was unlocked; locked w/ VMX-outside-SMX\n");
    }
    return TRUE;
}

VOID
VmmInitialize(VOID)
{
    Print(L"[VmmInit] === Phase 2a: log-only bisect ===\n");

    // Bisect step 1: prove the OphionDxe load + EBS callback chain doesn't
    // itself hang the boot. If this version boots cleanly, the prior hang was
    // caused by vmx_init or hostcr3_build (alloc paths). Step 2 re-enables
    // vmx_init alone; step 3 re-enables hostcr3_build.
    if (!VmmVmxSupported()) {
        Print(L"[VmmInit] VMX not usable\n");
        return;
    }

    UINT64 cr0 = __readcr0();
    UINT64 cr4 = __readcr4();
    Print(L"[VmmInit] cr0=0x%llx cr4=0x%llx vmxe=%u  (alloc deferred)\n",
          cr0, cr4, (UINT32)((cr4 >> 13) & 1));

    // Phase 7c-4 stage A: probe LBR support so stage B can size the
    // VMEXIT_MSR_STORE / VMENTRY_MSR_LOAD lists safely. Bad MSR in load list
    // -> VMENTRY_FAILURE_MSR_LOADING (reason 34) -> BSP halt + boot freeze.
    // CPUID 0x1C: architectural LBR feature info (Alder Lake+).
    //   subleaf 0 EAX[7:0]   = supported LBR depth bitmask
    //   subleaf 0 EBX[7:0]   = LBR depth select
    // IA32_PERF_CAPABILITIES (0x345) bits 0-5 = LBR_FMT (legacy LBR fallback).
    // Only readable if CPUID.01H:ECX.PDCM (bit 15) = 1.
    {
        int leaf1[4];
        __cpuid(leaf1, 1);
        UINT32 pdcm = (leaf1[2] >> 15) & 1;

        int lbrinfo[4] = {0,0,0,0};
        __cpuidex(lbrinfo, 0x1C, 0);

        UINT64 perfcap = 0;
        if (pdcm) {
            perfcap = __readmsr(0x345);
        }

        VmmLogVarSetf(L"OphnLbr",
            "pdcm=%u cpuid1c_eax=%x ebx=%x ecx=%x edx=%x perfcap=0x%llx lbrfmt=0x%x",
            pdcm,
            (UINT32)lbrinfo[0], (UINT32)lbrinfo[1],
            (UINT32)lbrinfo[2], (UINT32)lbrinfo[3],
            perfcap,
            (UINT32)(perfcap & 0x3F));
    }

#if 1
    // Phase 3b: alloc per-AP state too. Real cpu count from MP services
    // discovered earlier in OphionDxeEntry. Fall back to 1 if 0 (paranoia).
    UINTN ncpu = VmmMpGetCpuCount();
    if (ncpu == 0 || ncpu > 64) ncpu = 1;
    VmmLogVarSetf(L"OphnInit", "vmx_init_cpus=%u", (UINT32)ncpu);
    if (!vmx_init((UINT32)ncpu)) {
        Print(L"[VmmInit] vmx_init failed\n");
        return;
    }
    Print(L"[VmmInit] vmx_init done; vmcs_pa=0x%llx vmxon_pa=0x%llx\n",
          g_vcpu ? g_vcpu[0].vmcs_pa  : 0,
          g_vcpu ? g_vcpu[0].vmxon_pa : 0);

    // Step #8 (Grill Q21-C): per-CPU exit log rings. Lock-free; each CPU
    // writes its own ring at vmexit entry. Snapshot exposed via
    // OPHION_OP_GET_LOG (driver IOCTL_HV_GET_LOG forwards) and future
    // crash NV flush.
    VmmPclInit((UINT32)ncpu);
#endif

#if 1
    // Phase 2c: enable hostcr3_build (after vmx_init succeeds).
    if (!hostcr3_build()) {
        Print(L"[VmmInit] hostcr3_build failed\n");
        return;
    }
    Print(L"[VmmInit] hostcr3_build done; pa=0x%llx\n", hostcr3_get());
#endif

    // Phase 2.5d: build private host GDT + TSS so VMCS_HOST_TR_SELECTOR
    // points to a valid descriptor (UEFI bare-metal leaves TR=0 → VMLAUNCH
    // err=0x8 invalid host-state).
    if (!hostgdt_build()) {
        Print(L"[VmmInit] hostgdt_build failed\n");
        return;
    }
    Print(L"[VmmInit] hostgdt: gdt=0x%llx tss=0x%llx tr=0x%x\n",
          hostgdt_get_gdt_base(), hostgdt_get_tss_base(),
          (UINT32)hostgdt_get_tr_sel());

    // Phase 2.7: build private host IDT. Without our own IDT, HOST_IDTR_BASE
    // points at firmware IDT in EfiBootServicesData → Windows reclaims post-EBS
    // → first NMI/exception in vmexit handler triple-faults → reboot loop.
    // Per MiniVisorPkg design (tandasat/MiniVisorPkg).
    if (!hostidt_build()) {
        Print(L"[VmmInit] hostidt_build failed\n");
        return;
    }
    Print(L"[VmmInit] hostidt: pa=0x%llx\n", hostidt_get_base());

    // Phase 7c-4b: alloc minimal VMEXIT_MSR_LOAD list (single entry =
    // IA32_DEBUGCTL=0). Hardware clears host DEBUGCTL on every VMEXIT
    // so host runs with LBR off. Mitigates vgk per-CPU LBR canary RIP
    // leak. DEBUGCTL=0 is always-legal WRMSR target → no VMX abort 4.
    // Single page allocation in EfiRuntimeServicesData survives EBS.
    if (!VmcsAllocMinimalLoadList()) {
        Print(L"[VmmInit] VmcsAllocMinimalLoadList failed\n");
        return;
    }
    VmmLogVarSetf(L"OphnMsrLoad",
                  "pa=0x%llx count=%u entry0_msr=0x1D9 entry0_data=0",
                  VmcsGetVmexitLoadListPa(),
                  VmcsGetVmexitLoadCount());
    Print(L"[VmmInit] msr_load_list pa=0x%llx count=%u\n",
          VmcsGetVmexitLoadListPa(), VmcsGetVmexitLoadCount());

    Print(L"[VmmInit] Phase 2a OK; bisect off\n");
}

UINT32
VmmGetVcpuCount(VOID)
{
    return g_cpu_count;
}

/*
 * OphionDxe.c - Ophion VMM as UEFI DXE driver (Phase 1 scaffold + Phase 2/4 stubs)
 *
 * Phase 1: registers ExitBootServices notification, prints log line, no VMM
 * launched. Toolchain + load order verification.
 *
 * Phase 2 (in progress): EfiAlloc + VmcsAutoMsr scaffolds linked in. VMM
 * body and BSP VMLAUNCH still stubs.
 *
 * Phase 4 stubs: KiServiceTable resolver + NtosPatch trampoline builder
 * (force-linked via entry-time touchpoints; full integration when VMM is up).
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <intrin.h>

#include "EfiCompat.h"

extern VOID *VmcsGetDefaultMsrLists(VOID);
extern UINTN EfiAllocCount(VOID);
extern VOID  VmmInitialize(VOID);
extern BOOLEAN vmx_smoke_test(VOID);
extern VOID    asm_vmx_save_state(VOID);
extern UINT32  VmmBspLaunched(VOID);
extern VOID    VmmLogVarSet(IN CONST CHAR16 *Name, IN CONST CHAR8 *Msg);
extern VOID    VmmLogVarSetf(IN CONST CHAR16 *Name, IN CONST CHAR8 *Fmt, ...);
extern VOID    hv_log_post_ebs(VOID);

extern UINT64 KiResolveServiceTable(IN UINT8 *ntos_base, IN UINTN ntos_size);
extern UINT64 KiResolveSyscallByNumber(IN UINT64 service_table_va, IN UINT16 syscall_num);
extern UINTN  NtosBuildTrampoline(IN UINT8 *out, IN UINT64 nt_va, IN CONST UINT8 *saved);
extern BOOLEAN hostcr3_build(VOID);
extern UINT64  hostcr3_get(VOID);
extern EFI_STATUS VmmMpInit(VOID);
extern UINTN      VmmMpGetCpuCount(VOID);
extern EFI_STATUS VmmMpDispatchTest(VOID);
extern EFI_STATUS VmmMpVmxSmokeAll(VOID);
extern EFI_STATUS VmmMpTscAuxTest(VOID);
extern EFI_STATUS VmmMpVirtualizeOne(UINTN processor_num);
extern EFI_STATUS ApInitVirtualizeAll(VOID);
extern UINT32     ApInitAttempted(VOID);
extern UINT64     ApInitArmedMask(VOID);
extern UINTN      ApInitSipiSnapshot(UINT32 *out_sipi, UINT32 *out_init,
                                     UINT16 *out_last_vec, UINTN max);
extern VOID       ApInitFlushSipiToNv(VOID);
extern UINT64 vmm_pt_walk(UINT64 cr3, UINT64 va);
extern UINTN  vmm_guest_read(UINT64 cr3, UINT64 va, VOID *dst, UINTN size);
extern BOOLEAN ept_preallocate_pools(VOID);
extern UINT8 *g_trampoline_page;
extern VOID  *g_trampoline_nt_ptr;
extern UINT64 g_trampoline_va;
extern UINT64 g_trampoline_phys;

//
// Phase 4d-iii: VirtualAddressChange callback. NT calls SetVirtualAddressMap
// to remap our trampoline page from UEFI-time identity VA to a high kernel
// VA. Convert the alias pointer + record new VA so the install path encodes
// the correct address. Real trampoline writes still go via g_trampoline_page
// (phys identity), executable from VMX-root host CR3.
//
VOID
EFIAPI
VirtAddrChangeNotify(IN EFI_EVENT Event, IN VOID *Context)
{
    if (g_trampoline_nt_ptr != NULL) {
        gRT->ConvertPointer(0, &g_trampoline_nt_ptr);
        g_trampoline_va = (UINT64)(UINTN)g_trampoline_nt_ptr;
    }
}

static EFI_EVENT  gExitBootServicesEvent = NULL;
static EFI_EVENT  gVirtualAddressChangeEvent = NULL;

// IA32 MSRs
#define IA32_FEATURE_CONTROL  0x0000003A
#define IA32_VMX_BASIC        0x00000480

#define CPUID_VMX_BIT  5

static BOOLEAN
ProbeVmxSupport(VOID)
{
    int regs[4];
    __cpuid(regs, 1);
    if (!(regs[2] & (1 << CPUID_VMX_BIT))) {
        Print(L"[OphionDxe] CPUID.1.ECX[5] = 0; VMX not supported\n");
        return FALSE;
    }
    UINT64 feat = __readmsr(IA32_FEATURE_CONTROL);
    BOOLEAN locked       = (feat >> 0) & 1;
    BOOLEAN vmx_in_smx   = (feat >> 1) & 1;
    BOOLEAN vmx_outside  = (feat >> 2) & 1;
    Print(L"[OphionDxe] FEATURE_CONTROL=0x%llx (lock=%u smx=%u outside=%u)\n",
          feat, locked, vmx_in_smx, vmx_outside);
    if (locked && !vmx_outside) {
        Print(L"[OphionDxe] FEATURE_CONTROL locked with outside-SMX disabled\n");
        return FALSE;
    }
    UINT64 basic = __readmsr(IA32_VMX_BASIC);
    Print(L"[OphionDxe] IA32_VMX_BASIC=0x%llx (rev_id=%u)\n",
          basic, (UINT32)(basic & 0x7FFFFFFFu));
    return TRUE;
}

//
// VmmArm - called right before boot services close.
//
// UEFI spec 7.5.6: EBS notify handlers must NOT call boot services that mutate
// the memory map. The OS loader has already called GetMemoryMap and frozen the
// MapKey; any AllocatePages/AllocatePool here invalidates the map -> hang.
//
// Phase 2 alloc work (vmx_init + hostcr3_build) moved to OphionDxeEntry below.
// This callback is now alloc-free. Phase 2.5 will add VMXON + VMLAUNCH on BSP
// here (those VMX intrinsics don't allocate).
//
static VOID
EFIAPI
VmmArm(IN EFI_EVENT Event, IN VOID *Context)
{
    static BOOLEAN s_armed = FALSE;
    Print(L"[OphionDxe] EBS notify: Phase 2.7 final\n");
    VmmLogVarSet(L"OphnLastErr", "ebs_entered_2.7");

    // EBS notify can fire twice: Windows winload calls ExitBootServices()
    // first with stale MapKey (returns EFI_INVALID_PARAMETER), then retries
    // after fresh GetMemoryMap. Without this guard the second call re-enters
    // vmx_smoke_test from non-root guest, guest issues VMXON, vmexit reason
    // 27 (EXECUTE_VMXON) hits default branch -> BSP halts. Guard arms once.
    if (s_armed) {
        VmmLogVarSet(L"OphnLastErr", "ebs_reentry_skipped");
        hv_log_post_ebs();
        return;
    }
    s_armed = TRUE;

    BOOLEAN ok = vmx_smoke_test();
    if (!ok) {
        VmmLogVarSet(L"OphnLastErr", "smoke_FAIL");
        // Phase 7d-spoof-coexist: VMX may already be owned by NOVA mp.efi.
        // hv_log_post_ebs to silence Print which calls dead ConOut post-EBS.
        // Then return — boot continues without Ophion VMM, spoofer chain
        // still works.
        hv_log_post_ebs();
        return;
    }
    VmmLogVarSet(L"OphnLastErr", "smoke_ok_pre_launch");

    // CRITICAL: silence hv_log BEFORE vmlaunch. Print() in vmexit handler
    // (default branch / NMI handler) post-EBS calls dead ConOut → BSP wedges
    // → boot hangs after Windows logo.
    hv_log_post_ebs();

    asm_vmx_save_state();

    VmmLogVarSet(L"OphnPostLaunch", "control_returned");
    if (VmmBspLaunched()) {
        VmmLogVarSet(L"OphnLastErr", "VMLAUNCH_SUCCESS");
    }
}

EFI_STATUS
EFIAPI
OphionDxeEntry(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS Status;

    Print(L"[OphionDxe] phase 2/4 scaffold loaded (msr_lists=%p)\n",
          VmcsGetDefaultMsrLists());

    // Phase 3a: discover MP topology before VMX init. Logged to OphnMp NV var.
    // Failure here is non-fatal — Phase 2.7 BSP-only path still works.
    VmmMpInit();

    // Phase 3c: prove AP fanout via StartupAllAPs (log-only). Must run BEFORE
    // any per-vcpu VMX state mutation (none here yet — vmx_init runs after).
    // Result in OphnApDispatch NV var.
    VmmMpDispatchTest();

    // Force-link Phase 4 helpers so they survive the linker's dead-strip pass.
    // These are no-ops at runtime; the real call sites land in VMM context.
    if ((UINTN)KiResolveServiceTable == 0) Print(L"unreachable\n");
    if ((UINTN)KiResolveSyscallByNumber == 0) Print(L"unreachable\n");
    if ((UINTN)NtosBuildTrampoline == 0) Print(L"unreachable\n");
    // Force-link Phase 2.5 helpers (hostcr3 deep-clone). Wired into VMCS_HOST_CR3
    // when Phase 2.5 enables VMLAUNCH from VmmInitialize.
    if ((UINTN)hostcr3_build == 0) Print(L"unreachable\n");
    if ((UINTN)hostcr3_get == 0)   Print(L"unreachable\n");
    // Force-link Phase 4a guest PT walker.
    if ((UINTN)vmm_pt_walk == 0)    Print(L"unreachable\n");
    if ((UINTN)vmm_guest_read == 0) Print(L"unreachable\n");

    // Phase 4b: allocate trampoline page in EfiRuntimeServicesCode (survives
    // EBS). Single 4KB page; trampoline is ~58 bytes. Populated from VMX-root
    // when OPHS resolve sets NCP target VA.
    g_trampoline_page = (UINT8 *)EfiAllocateRuntimePages(1);
    if (g_trampoline_page) {
        SetMem(g_trampoline_page, 4096, 0xCC);  // int3 fill
        g_trampoline_phys  = (UINT64)(UINTN)g_trampoline_page; // immutable phys
        g_trampoline_nt_ptr = (VOID *)g_trampoline_page;       // converted by SVM
        g_trampoline_va    = (UINT64)(UINTN)g_trampoline_page; // pre-SVM = phys
        Print(L"[OphionDxe] trampoline page = %p\n", g_trampoline_page);
    } else {
        Print(L"[OphionDxe] trampoline alloc failed\n");
    }

    // Phase 7d: pre-allocate EPT split + alt-page pools. VMX-root post-EBS
    // cannot call EfiAllocateRuntimePages (gBS invalid + ring discipline).
    // Pools sized to support ~4 simultaneous cloaks. Init order matters:
    // must run after gBS available, before EBS notify.
    if (!ept_preallocate_pools()) {
        Print(L"[OphionDxe] EPT pre-alloc pools failed\n");
    } else {
        Print(L"[OphionDxe] EPT pools allocated\n");
    }

    // Phase 2: do all alloc work HERE at DXE load time. Boot services fully
    // available; memory map not yet finalized. EBS callback (VmmArm) is then
    // alloc-free and won't corrupt the OS loader's GetMemoryMap snapshot.
    BOOLEAN vmx_ok = ProbeVmxSupport();
    Print(L"[OphionDxe] VMX usable: %s\n", vmx_ok ? L"yes" : L"no");
    if (vmx_ok) {
        VmmInitialize();
        Print(L"[OphionDxe] runtime alloc count = %u\n", (UINT32)EfiAllocCount());

        // Phase 3d-ii: AP VMX smoke test. Each AP runs VMXON+VMCLEAR+VMPTRLD+
        // VMWRITE+VMREAD+VMXOFF on its own per-vcpu region. No VMLAUNCH yet.
        // Records per-AP stage in OphnApVmx NV var. Non-fatal on failure.
        VmmMpVmxSmokeAll();

        // Phase 3d-iii-a: AP TSC_AUX writeable test. Confirms wrmsr to
        // IA32_TSC_AUX is permitted from AP context. Reads firmware-provided
        // TSC_AUX (pre), writes myid, reads back (post). Records to OphnApTsc.
        VmmMpTscAuxTest();

        // Phase 3d-iv-b DISABLED: AP1 virt at DXE causes Windows hang on
        // INIT-SIPI (SIPI handler real-mode entry unstable, undebuggable
        // without serial console). Saved baseline in
        // MongilLoader/build/Phase_3_partial_known_good/. Re-enable only
        // on bench HW with serial console + working VMCALL readback.
        // VmmMpVirtualizeOne(1);

        // Step #B1 (Grill Q19-A): multi-AP virtualize entry. Linked but NOT
        // called — same blocker as Phase 3d-iv-b above. ApInitVirtualizeAll
        // would walk every enabled AP through VmmMpVirtualizeOne with the
        // s_ap_armed[] retry guard, but Step #B2 (SIPI/INIT exit handler)
        // must land first or Windows freezes during multi-core wake. Force
        // -link so the linker doesn't dead-strip the entry; bench HW with
        // serial console can flip it on once Step #B2 is verified.
        if ((UINTN)ApInitVirtualizeAll == 0) Print(L"unreachable\n");
        if ((UINTN)ApInitAttempted == 0)     Print(L"unreachable\n");
        if ((UINTN)ApInitArmedMask == 0)     Print(L"unreachable\n");
        if ((UINTN)ApInitSipiSnapshot == 0)  Print(L"unreachable\n");
        if ((UINTN)ApInitFlushSipiToNv == 0) Print(L"unreachable\n");
    }

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,
                                TPL_CALLBACK,
                                VmmArm,
                                NULL,
                                &gEfiEventExitBootServicesGuid,
                                &gExitBootServicesEvent);
    if (EFI_ERROR(Status)) {
        Print(L"[OphionDxe] CreateEventEx = %r\n", Status);
        return Status;
    }

    // Phase 4d-iii: register VirtualAddressChange callback. NT calls
    // SetVirtualAddressMap during winload (post-EBS) to remap UEFI runtime
    // pages from boot-time identity VAs to high kernel VAs. Without this,
    // g_trampoline_va stays at the UEFI-time identity VA (e.g. 0x39F74000),
    // and the inline-jmp patch in ntos.text would jump to an unmapped address
    // when NT context calls NtCreateCrossVmEvent.
    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,
                                TPL_NOTIFY,
                                VirtAddrChangeNotify,
                                NULL,
                                &gEfiEventVirtualAddressChangeGuid,
                                &gVirtualAddressChangeEvent);
    if (EFI_ERROR(Status)) {
        Print(L"[OphionDxe] CreateEventEx(VirtAddrChange) = %r\n", Status);
        // non-fatal — Phase 4d-i still works pre-EBS, install just won't be
        // safe to trigger from NT context until callback runs
    }
    return EFI_SUCCESS;
}

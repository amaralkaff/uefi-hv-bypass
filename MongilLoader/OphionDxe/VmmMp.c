/*
 * VmmMp.c - EFI MP Services discovery + AP dispatch for Phase 3 AP virtualization.
 *
 * Phase 3a: locate gEfiMpServiceProtocolGuid, query GetNumberOfProcessors. Cache
 * protocol pointer + counts. Log to OphnMp NV var.
 *
 * Phase 3c: VmmMpDispatchTest — log-only AP fanout via StartupAllAPs to prove
 * the dispatch path works on real HW before adding VMX. Each AP writes its
 * APIC id + TSC_AUX into a per-id slot; BSP aggregates to OphnApDispatch.
 *
 * Phase 3d-e (later): per-AP VMXON+VMLAUNCH with Wait-for-SIPI guest activity.
 *
 * UEFI MP Services (PI 1.7 vol 2 §13.4): always present in modern firmware.
 * Locate at DXE_RUNTIME_DRIVER load time. Protocol pointer stays valid
 * pre-EBS only — AP dispatch must happen before ExitBootServices fires.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MpService.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "ia32.h"
#include "hv_types.h"

extern VOID VmmLogVarSet(IN CONST CHAR16 *Name, IN CONST CHAR8 *Msg);
extern VOID VmmLogVarSetf(IN CONST CHAR16 *Name, IN CONST CHAR8 *Fmt, ...);
extern VOID    asm_enable_vmx(VOID);
extern VOID    vmx_set_fixed_bits(VOID);
extern VOID    asm_vmx_save_state(VOID);
extern VIRTUAL_MACHINE_STATE *g_vcpu;
extern UINT32                 g_cpu_count;

EFI_MP_SERVICES_PROTOCOL *g_mp = NULL;
UINTN g_mp_cpu_count     = 0;
UINTN g_mp_enabled_count = 0;
UINTN g_mp_bsp_id        = 0;

#define AP_LOG_MAX 64
typedef struct {
    UINT64  tsc;
    UINT32  myid;
    UINT32  tscaux;
    UINT32  done;
    UINT32  pad;
} AP_LOG;

static AP_LOG g_ap_log[AP_LOG_MAX];

EFI_STATUS
VmmMpInit(VOID)
{
    EFI_STATUS Status;

    Status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid, NULL, (VOID **)&g_mp);
    if (EFI_ERROR(Status)) {
        VmmLogVarSetf(L"OphnMp", "locate_failed status=0x%llx", (UINT64)Status);
        Print(L"[VmmMp] LocateProtocol(MpServices) = %r\n", Status);
        return Status;
    }

    UINTN ncpu = 0, nenabled = 0;
    Status = g_mp->GetNumberOfProcessors(g_mp, &ncpu, &nenabled);
    if (EFI_ERROR(Status)) {
        VmmLogVarSetf(L"OphnMp", "gnp_failed status=0x%llx", (UINT64)Status);
        Print(L"[VmmMp] GetNumberOfProcessors = %r\n", Status);
        return Status;
    }

    UINTN bsp = 0;
    EFI_STATUS who_status = g_mp->WhoAmI(g_mp, &bsp);
    if (EFI_ERROR(who_status)) {
        bsp = (UINTN)-1;
    }

    g_mp_cpu_count     = ncpu;
    g_mp_enabled_count = nenabled;
    g_mp_bsp_id        = bsp;

    VmmLogVarSetf(L"OphnMp", "cpus=%u enabled=%u bsp=%u",
                  (UINT32)ncpu, (UINT32)nenabled, (UINT32)bsp);
    Print(L"[VmmMp] cpus=%u enabled=%u bsp=%u\n",
          (UINT32)ncpu, (UINT32)nenabled, (UINT32)bsp);

    return EFI_SUCCESS;
}

//
// AP procedure: each AP writes its own slot. No locking — slot index = myid,
// each AP has unique id so writes don't race. SetVariable is NOT called from
// AP context (some firmware serializes, some doesn't); BSP aggregates after
// StartupAllAPs returns.
//
// SDM/UEFI: AP procedure runs at TPL_APPLICATION-equivalent. Safe to call
// __readmsr (CPU op, not boot service).
//
static VOID EFIAPI
ap_log_proc(IN VOID *Arg)
{
    (VOID)Arg;
    UINTN myid = (UINTN)-1;
    if (g_mp != NULL) {
        g_mp->WhoAmI(g_mp, &myid);
    }
    if (myid < AP_LOG_MAX) {
        g_ap_log[myid].tsc    = __rdtsc();
        g_ap_log[myid].myid   = (UINT32)myid;
        g_ap_log[myid].tscaux = (UINT32)(__readmsr(0xC0000103) & 0xFFF);
        g_ap_log[myid].done   = 1;
    }
}

EFI_STATUS
VmmMpDispatchTest(VOID)
{
    if (g_mp == NULL || g_mp_cpu_count == 0) {
        VmmLogVarSet(L"OphnApDispatch", "skip_no_mp");
        return EFI_NOT_READY;
    }

    // Clear log slots (BSP only, before StartupAllAPs).
    for (UINTN i = 0; i < AP_LOG_MAX; i++) {
        g_ap_log[i].done = 0;
    }

    UINTN failed_count = 0;
    UINTN *failed_list = NULL;

    // SingleThread=FALSE → run on all APs in parallel.
    // Timeout 1s — each AP just writes a slot, should be microseconds.
    EFI_STATUS s = g_mp->StartupAllAPs(g_mp,
                                       ap_log_proc,
                                       FALSE,
                                       NULL,         // no event = blocking
                                       1000000,      // 1s timeout
                                       NULL,
                                       &failed_list);

    // Aggregate from BSP, serialized.
    UINT64 mask = 0;
    UINT32 n_done = 0;
    for (UINTN i = 0; i < g_mp_cpu_count && i < AP_LOG_MAX; i++) {
        if (g_ap_log[i].done) {
            mask |= (1ULL << i);
            n_done++;
        }
    }

    if (failed_list != NULL) {
        for (UINTN i = 0; failed_list[i] != END_OF_CPU_LIST; i++) {
            failed_count++;
        }
    }

    VmmLogVarSetf(L"OphnApDispatch",
                  "ran=%u expected=%u mask=0x%llx failed=%u status=0x%llx",
                  n_done, (UINT32)(g_mp_cpu_count - 1), mask,
                  (UINT32)failed_count, (UINT64)s);

    Print(L"[VmmMp] dispatch: ran=%u expected=%u mask=0x%llx status=%r\n",
          n_done, (UINT32)(g_mp_cpu_count - 1), mask, s);

    return s;
}

UINTN
VmmMpGetCpuCount(VOID)
{
    return g_mp_cpu_count;
}

//
// AP VMX smoke test procedure (Phase 3d-ii). Each AP:
//   1. Read TSC_AUX → core_id (matches Ophion vmx_get_cpu_id pattern).
//   2. asm_enable_vmx (sets CR4.VMXE).
//   3. vmx_set_fixed_bits (CR0/CR4 fixed-bit fixup per VMX MSRs).
//   4. __vmx_on(&vcpu->vmxon_pa) — must succeed.
//   5. __vmx_vmclear / vmptrld / vmwrite / vmread on benign field.
//   6. __vmx_off.
//   7. Record per-slot status. Failures recorded with stage tag.
// No VMLAUNCH yet — Phase 3d-iii.
//
typedef struct {
    UINT32 stage;       // 0=ok, 1=VMXON_fail, 2=VMCLEAR_fail, 3=VMPTRLD_fail, 4=VMWRITE_fail, 5=VMREAD_fail, 6=core_oor
    UINT32 core_id;
    UINT64 vmxon_pa;
} AP_VMX_RESULT;

static AP_VMX_RESULT g_ap_vmx[AP_LOG_MAX];

static VOID EFIAPI
ap_vmx_smoke_proc(IN VOID *Arg)
{
    (VOID)Arg;
    UINTN myid = (UINTN)-1;
    if (g_mp != NULL) g_mp->WhoAmI(g_mp, &myid);
    if (myid >= AP_LOG_MAX) return;

    // Use myid as slot AND vcpu index. AP UEFI ID == NT logical CPU usually,
    // but for smoke test all that matters is unique per AP. Bound check.
    if (myid >= g_cpu_count) {
        g_ap_vmx[myid].stage = 6;
        return;
    }

    g_ap_vmx[myid].core_id  = (UINT32)myid;
    g_ap_vmx[myid].vmxon_pa = g_vcpu[myid].vmxon_pa;

    asm_enable_vmx();
    vmx_set_fixed_bits();

    UINT64 vmxon_pa = g_vcpu[myid].vmxon_pa;
    if (__vmx_on(&vmxon_pa)) {
        g_ap_vmx[myid].stage = 1;
        return;
    }

    UINT64 vmcs_pa = g_vcpu[myid].vmcs_pa;
    if (__vmx_vmclear(&vmcs_pa)) {
        __vmx_off();
        g_ap_vmx[myid].stage = 2;
        return;
    }

    if (__vmx_vmptrld(&vmcs_pa)) {
        __vmx_off();
        g_ap_vmx[myid].stage = 3;
        return;
    }

    if (__vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL)) {
        __vmx_off();
        g_ap_vmx[myid].stage = 4;
        return;
    }

    UINT64 readback = 0;
    if (__vmx_vmread(VMCS_GUEST_VMCS_LINK_POINTER, &readback)) {
        __vmx_off();
        g_ap_vmx[myid].stage = 5;
        return;
    }

    __vmx_off();
    g_ap_vmx[myid].stage = 0;
}

EFI_STATUS
VmmMpVmxSmokeAll(VOID)
{
    if (g_mp == NULL || g_mp_cpu_count == 0 || g_vcpu == NULL) {
        VmmLogVarSet(L"OphnApVmx", "skip_prereq");
        return EFI_NOT_READY;
    }

    // Init slots: stage=0xFF means AP never ran.
    for (UINTN i = 0; i < AP_LOG_MAX; i++) {
        g_ap_vmx[i].stage    = 0xFF;
        g_ap_vmx[i].core_id  = 0;
        g_ap_vmx[i].vmxon_pa = 0;
    }

    UINTN *failed_list = NULL;
    EFI_STATUS s = g_mp->StartupAllAPs(g_mp,
                                       ap_vmx_smoke_proc,
                                       FALSE,
                                       NULL,
                                       2000000,   // 2s timeout
                                       NULL,
                                       &failed_list);

    UINT64 ok_mask = 0, fail_mask = 0;
    UINT32 n_ok = 0, n_fail = 0, last_fail_stage = 0xFF, last_fail_core = 0;
    for (UINTN i = 0; i < g_mp_cpu_count && i < AP_LOG_MAX; i++) {
        if (g_ap_vmx[i].stage == 0) {
            ok_mask |= (1ULL << i);
            n_ok++;
        } else if (g_ap_vmx[i].stage != 0xFF) {
            fail_mask |= (1ULL << i);
            n_fail++;
            last_fail_stage = g_ap_vmx[i].stage;
            last_fail_core  = (UINT32)i;
        }
    }

    VmmLogVarSetf(L"OphnApVmx",
                  "ok=%u fail=%u ok_mask=0x%llx fail_mask=0x%llx last_stage=%u last_core=%u status=0x%llx",
                  n_ok, n_fail, ok_mask, fail_mask,
                  last_fail_stage, last_fail_core, (UINT64)s);

    Print(L"[VmmMp] AP VMX smoke: ok=%u fail=%u status=%r\n", n_ok, n_fail, s);
    return s;
}

//
// Phase 3d-iii-a: AP TSC_AUX writeable test. Each AP records firmware-provided
// TSC_AUX value (pre), writes its own UEFI WhoAmI id (myid), reads back (post).
// Confirms wrmsr to IA32_TSC_AUX is permitted from AP context AND that future
// vmx_virtualize_cpu logic indexing g_vcpu[TSC_AUX & 0xFFF] will match myid.
// No VMX, no boot service calls.
//
typedef struct {
    UINT32 myid;
    UINT32 pre_lo;
    UINT32 post_lo;
    UINT32 done;
} AP_TSC_RESULT;

static AP_TSC_RESULT g_ap_tsc[AP_LOG_MAX];

static VOID EFIAPI
ap_tsc_aux_proc(IN VOID *Arg)
{
    (VOID)Arg;
    UINTN myid = (UINTN)-1;
    if (g_mp != NULL) g_mp->WhoAmI(g_mp, &myid);
    if (myid >= AP_LOG_MAX) return;

    UINT32 pre = (UINT32)(__readmsr(0xC0000103) & 0xFFFFFFFFu);
    __writemsr(0xC0000103, (UINT64)myid);
    UINT32 post = (UINT32)(__readmsr(0xC0000103) & 0xFFFFFFFFu);

    g_ap_tsc[myid].myid    = (UINT32)myid;
    g_ap_tsc[myid].pre_lo  = pre;
    g_ap_tsc[myid].post_lo = post;
    g_ap_tsc[myid].done    = 1;
}

EFI_STATUS
VmmMpTscAuxTest(VOID){
    if (g_mp == NULL || g_mp_cpu_count == 0) {
        VmmLogVarSet(L"OphnApTsc", "skip_no_mp");
        return EFI_NOT_READY;
    }

    for (UINTN i = 0; i < AP_LOG_MAX; i++) {
        g_ap_tsc[i].done = 0;
    }

    UINTN *failed_list = NULL;
    EFI_STATUS s = g_mp->StartupAllAPs(g_mp,
                                       ap_tsc_aux_proc,
                                       FALSE,
                                       NULL,
                                       1000000,
                                       NULL,
                                       &failed_list);

    UINT32 n_ok = 0, n_match = 0, n_mismatch = 0, n_pre_zero = 0;
    UINT32 first_pre = 0, last_pre = 0, last_post = 0, last_id = 0;
    UINT64 ok_mask = 0;
    for (UINTN i = 0; i < g_mp_cpu_count && i < AP_LOG_MAX; i++) {
        if (!g_ap_tsc[i].done) continue;
        n_ok++;
        ok_mask |= (1ULL << i);
        if (g_ap_tsc[i].pre_lo == 0) n_pre_zero++;
        if (g_ap_tsc[i].post_lo == g_ap_tsc[i].myid) n_match++; else n_mismatch++;
        if (n_ok == 1) first_pre = g_ap_tsc[i].pre_lo;
        last_pre = g_ap_tsc[i].pre_lo;
        last_post = g_ap_tsc[i].post_lo;
        last_id = g_ap_tsc[i].myid;
    }

    VmmLogVarSetf(L"OphnApTsc",
                  "ran=%u match=%u mismatch=%u pre_zero=%u first_pre=0x%x last_id=%u last_pre=0x%x last_post=0x%x mask=0x%llx status=0x%llx",
                  n_ok, n_match, n_mismatch, n_pre_zero,
                  first_pre, last_id, last_pre, last_post,
                  ok_mask, (UINT64)s);

    Print(L"[VmmMp] AP TSC_AUX: ran=%u match=%u mismatch=%u pre_zero=%u status=%r\n",
          n_ok, n_match, n_mismatch, n_pre_zero, s);

    return s;
}

//
// Phase 3d-iii-b: AP virtualize procedure. Sets TSC_AUX=myid then drops into
// asm_vmx_save_state. On VMLAUNCH success, AP returns to caller (in non-root).
// On failure, vmx_virtualize_cpu sets vcpu->launched=FALSE + vcpu->launch_err.
// NV writes from this proc forbidden (AP context). BSP reads result from
// g_vcpu[myid] after StartupThisAP returns.
//
static VOID EFIAPI
ap_virtualize_proc(IN VOID *Arg)
{
    (VOID)Arg;
    UINTN myid = (UINTN)-1;
    if (g_mp != NULL) g_mp->WhoAmI(g_mp, &myid);
    if (myid == (UINTN)-1 || myid >= AP_LOG_MAX) return;
    if (myid >= g_cpu_count) return;

    // Set TSC_AUX so vmx_virtualize_cpu indexes g_vcpu[myid] not g_vcpu[0].
    __writemsr(0xC0000103, (UINT64)myid);

    asm_vmx_save_state();
    // After successful VMLAUNCH AP returns here in VMX non-root mode (guest).
    // After failure also returns here (asm restores GPRs + RFLAGS).
}

EFI_STATUS
VmmMpVirtualizeOne(UINTN processor_num)
{
    if (g_mp == NULL || g_vcpu == NULL || g_cpu_count == 0) {
        VmmLogVarSet(L"OphnAp1Vmx", "skip_prereq");
        return EFI_NOT_READY;
    }
    if (processor_num >= g_mp_cpu_count || processor_num >= AP_LOG_MAX) {
        VmmLogVarSet(L"OphnAp1Vmx", "bad_proc_num");
        return EFI_INVALID_PARAMETER;
    }
    if (processor_num == g_mp_bsp_id) {
        VmmLogVarSet(L"OphnAp1Vmx", "skip_is_bsp");
        return EFI_INVALID_PARAMETER;
    }

    BOOLEAN finished = FALSE;
    EFI_STATUS s = g_mp->StartupThisAP(g_mp,
                                       ap_virtualize_proc,
                                       processor_num,
                                       NULL,           // blocking
                                       3000000,        // 3s timeout
                                       NULL,
                                       &finished);

    BOOLEAN launched = (g_vcpu[processor_num].launched != 0);
    UINT64  err      = g_vcpu[processor_num].launch_err;

    VmmLogVarSetf(L"OphnAp1Vmx",
                  "proc=%u finished=%u launched=%u err=0x%llx status=0x%llx",
                  (UINT32)processor_num, (UINT32)finished,
                  (UINT32)launched, err, (UINT64)s);

    Print(L"[VmmMp] virtualize one (proc=%u): finished=%u launched=%u err=0x%llx status=%r\n",
          (UINT32)processor_num, (UINT32)finished, (UINT32)launched, err, s);

    return s;
}

UINTN
VmmMpGetEnabledCount(VOID)
{
    return g_mp_enabled_count;
}

UINTN
VmmMpGetBspId(VOID)
{
    return g_mp_bsp_id;
}

EFI_MP_SERVICES_PROTOCOL *
VmmMpGetProtocol(VOID)
{
    return g_mp;
}


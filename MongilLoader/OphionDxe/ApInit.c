/*
 * ApInit.c — Step #B1 (Grill Q19-A + Q18-A): multi-AP UEFI MP-services
 * virtualization wrapper.
 *
 * Builds on existing VmmMp.c per-AP machinery:
 *
 *   VmmMpInit()            — locates EFI MP services, caches counts (DXE entry)
 *   VmmMpVmxSmokeAll()     — Phase 3d-ii: per-AP VMXON+VMCLEAR+VMPTRLD+VMXOFF
 *   VmmMpVirtualizeOne(N)  — single-AP virtualize via asm_vmx_save_state
 *
 * What this file adds (Step #B1):
 *
 *   ApInitVirtualizeAll()  — iterate every enabled AP except the BSP, drive
 *                            VmmMpVirtualizeOne() through the s_ap_armed[]
 *                            retry guard, aggregate per-AP launched/err state
 *                            into the OphnApAll NV variable.
 *
 *   ApInitArmedMask()      — bitmask of APs whose s_ap_armed slot is set
 *                            (mirrors BSP `s_armed` from OphionDxe.c::VmmArm).
 *
 * Design (locked via /grill-me):
 *
 *   Q19-A : pre-EBS bring-up via UEFI MP services. APs enter VMX root in a
 *           known UEFI idle state — no live-state capture race, no PG/AC
 *           interference, simple guest VMCS init.
 *   Q18-A : single shared EPTP. All cores reuse the EPT tree allocated by
 *           VmmInit; cloak coverage is automatic. INVEPT broadcast happens
 *           via the existing VMCALL→DPC ring.
 *   Q20-B : per-resource spinlocks remain unchanged. ApInit only mutates
 *           s_ap_armed[] (atomic byte slot per CPU, no contention).
 *
 * NOT in scope here:
 *
 *   * SIPI / INIT exit handler  → Step #B2 (VmmExit.c reasons 0x09 + 0x0A).
 *     Today's BSP path returns to non-root after VMLAUNCH; APs do the same.
 *     When Windows IPIs an AP for INIT-SIPI-SIPI, the AP must vmexit, the
 *     handler updates guest RIP/CS from the SIPI vector, then VMRESUME.
 *     Without that handler, AP virt freezes Windows during multi-core wake
 *     (which is why the existing OphionDxe.c VmmMpVirtualizeOne(1) call is
 *     gated off — see Phase 3d-iv-b note). This file ships the entry but
 *     does NOT call it from DXE entry; the caller must opt in.
 *
 *   * 12-core stress harness    → Step #B4.
 *
 *   * Phase 7d cloak relight on driver image → Step #B3.
 *
 * Status codes packed into OphnApAll NV var:
 *
 *   ok=N      successfully armed and launched
 *   already=N s_ap_armed slot was already set (idempotent retry)
 *   skip=N    BSP id, disabled CPU, or out-of-range slot
 *   fail=N    StartupThisAP returned EFI_SUCCESS but vcpu->launched == 0
 *   err=N     StartupThisAP returned an EFI error (timeout / device err)
 *
 * Safe to call once per boot; subsequent calls are no-ops via s_ap_armed.
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MpService.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "ia32.h"
#include "hv_types.h"

#define APINIT_MAX_CPUS 64

extern VOID    VmmLogVarSet(IN CONST CHAR16 *Name, IN CONST CHAR8 *Msg);
extern VOID    VmmLogVarSetf(IN CONST CHAR16 *Name, IN CONST CHAR8 *Fmt, ...);
extern UINTN   VmmMpGetCpuCount(VOID);
extern UINTN   VmmMpGetEnabledCount(VOID);
extern UINTN   VmmMpGetBspId(VOID);
extern EFI_MP_SERVICES_PROTOCOL *VmmMpGetProtocol(VOID);
extern EFI_STATUS VmmMpVirtualizeOne(UINTN processor_num);
extern VIRTUAL_MACHINE_STATE *g_vcpu;
extern UINT32                 g_cpu_count;

/*
 * Per-AP arming guard. Mirrors the BSP `s_armed` static in OphionDxe.c::VmmArm
 * which exists because UEFI EBS callbacks fire twice (Windows winload retries
 * after stale-MapKey). With APs in the picture the same retry can land on
 * every CPU; without per-CPU guards each retry reissues VMXON from a guest
 * context AP, exit reason 27 (EXECUTE_VMXON) hits the default branch, the
 * BSP halts on aggregate.
 *
 * Byte slot per CPU keeps writes atomic (single STORE) so we do not need a
 * spinlock around the check-and-set.
 */
static volatile UINT8 s_ap_armed[APINIT_MAX_CPUS];

/*
 * Aggregate counters. Reset on each ApInitVirtualizeAll() call so a retry
 * (after a fix on bench HW) reports a clean count.
 */
static UINT32 g_ap_ok      = 0;
static UINT32 g_ap_already = 0;
static UINT32 g_ap_skip    = 0;
static UINT32 g_ap_fail    = 0;
static UINT32 g_ap_err     = 0;
static UINT64 g_ap_ok_mask = 0;
static UINT64 g_ap_fail_mask = 0;

/*
 * Returns a bitmask of APs whose s_ap_armed slot is set. Useful for both the
 * VMM smoke harness and for confirming idempotent retry behaviour after a
 * partial failure.
 */
UINT64
ApInitArmedMask(VOID)
{
    UINT64 mask = 0;
    for (UINTN i = 0; i < APINIT_MAX_CPUS; i++) {
        if (s_ap_armed[i]) mask |= (1ULL << i);
    }
    return mask;
}

/*
 * Has Step #B1 been driven yet? Distinct from "every AP launched" — even if
 * every AP failed we still flag the run as attempted.
 */
static UINT32 g_apinit_attempted = 0;

UINT32
ApInitAttempted(VOID)
{
    return g_apinit_attempted;
}

/*
 * Drive every enabled AP through VmmMpVirtualizeOne(). Idempotent — APs
 * already past their s_ap_armed gate are counted as `already=` and skipped
 * without re-entering VMX intrinsics.
 *
 * Caller responsibilities:
 *   - VmmMpInit() must have run (g_mp protocol cached).
 *   - vmx_init() must have populated g_vcpu[].
 *   - This must run BEFORE gBS->ExitBootServices(); MP services protocol
 *     pointer goes invalid post-EBS.
 *
 * Returns the EFI_STATUS of the LAST per-AP StartupThisAP call. Per-AP
 * results are recorded in OphnApAll NV var. EFI_NOT_READY means the
 * prerequisites aren't satisfied (caller should not flag it as a hard fail).
 */
EFI_STATUS
ApInitVirtualizeAll(VOID)
{
    EFI_MP_SERVICES_PROTOCOL *mp = VmmMpGetProtocol();
    UINTN cpu_count = VmmMpGetCpuCount();
    UINTN bsp_id    = VmmMpGetBspId();

    g_apinit_attempted = 1;

    if (mp == NULL || cpu_count == 0 || g_vcpu == NULL) {
        VmmLogVarSet(L"OphnApAll", "skip_prereq");
        return EFI_NOT_READY;
    }

    g_ap_ok = g_ap_already = g_ap_skip = g_ap_fail = g_ap_err = 0;
    g_ap_ok_mask = g_ap_fail_mask = 0;

    EFI_STATUS last_status = EFI_SUCCESS;

    for (UINTN i = 0; i < cpu_count && i < APINIT_MAX_CPUS; i++) {
        if (i == bsp_id) {
            g_ap_skip++;
            continue;
        }
        if (i >= g_cpu_count) {
            /*
             * vmx_init sized g_vcpu[] from VmmMpGetCpuCount(); a higher i
             * here means MP topology grew between init and now (shouldn't
             * happen pre-EBS on a single boot) — refuse rather than index
             * past the array.
             */
            g_ap_skip++;
            continue;
        }
        if (s_ap_armed[i]) {
            g_ap_already++;
            continue;
        }

        EFI_STATUS s = VmmMpVirtualizeOne(i);
        last_status = s;

        if (EFI_ERROR(s)) {
            g_ap_err++;
            g_ap_fail_mask |= (1ULL << i);
            continue;
        }

        if (g_vcpu[i].launched) {
            s_ap_armed[i] = 1;
            g_ap_ok++;
            g_ap_ok_mask |= (1ULL << i);
        } else {
            g_ap_fail++;
            g_ap_fail_mask |= (1ULL << i);
        }
    }

    VmmLogVarSetf(L"OphnApAll",
                  "ok=%u already=%u skip=%u fail=%u err=%u "
                  "ok_mask=0x%llx fail_mask=0x%llx last=0x%llx",
                  g_ap_ok, g_ap_already, g_ap_skip, g_ap_fail, g_ap_err,
                  g_ap_ok_mask, g_ap_fail_mask, (UINT64)last_status);

    Print(L"[ApInit] virt: ok=%u already=%u skip=%u fail=%u err=%u status=%r\n",
          g_ap_ok, g_ap_already, g_ap_skip, g_ap_fail, g_ap_err, last_status);

    return last_status;
}

/*
 * Lightweight accessors for the VMM smoke harness / CPUID 0x40000000 leaves.
 * Kept separate from the NV-var blob so a query path doesn't need to parse
 * the formatted string.
 */
UINT32 ApInitOkCount(VOID)      { return g_ap_ok;      }
UINT32 ApInitAlreadyCount(VOID) { return g_ap_already; }
UINT32 ApInitFailCount(VOID)    { return g_ap_fail;    }
UINT32 ApInitErrCount(VOID)     { return g_ap_err;     }
UINT64 ApInitOkMask(VOID)       { return g_ap_ok_mask; }
UINT64 ApInitFailMask(VOID)     { return g_ap_fail_mask; }

/*
 * Step #B2 telemetry: snapshot per-AP SIPI / INIT counters from the per-vcpu
 * state populated by VmmExit.c. Caller is BSP-only post-virt; we cannot write
 * NV vars from AP vmexit context (race with NT). Returns the number of CPUs
 * the snapshot covered (= min(g_cpu_count, max)).
 *
 * out_sipi[i] : count of SIPI vmexits CPU i has handled
 * out_init[i] : count of INIT_SIGNAL vmexits CPU i has handled
 * out_last_vec[i] : low byte of the most recent SIPI vector observed by CPU i
 *
 * Slots beyond g_cpu_count are zeroed so callers can format a fixed-width
 * table without bounds dancing.
 */
UINTN
ApInitSipiSnapshot(
    OUT UINT32 *out_sipi,
    OUT UINT32 *out_init,
    OUT UINT16 *out_last_vec,
    IN  UINTN  max
    )
{
    if (g_vcpu == NULL || max == 0) return 0;
    UINTN n = (g_cpu_count < max) ? g_cpu_count : max;
    for (UINTN i = 0; i < n; i++) {
        if (out_sipi)     out_sipi[i]     = g_vcpu[i].sipi_seen;
        if (out_init)     out_init[i]     = g_vcpu[i].init_seen;
        if (out_last_vec) out_last_vec[i] = (UINT16)g_vcpu[i].last_sipi_vec;
    }
    for (UINTN i = n; i < max; i++) {
        if (out_sipi)     out_sipi[i]     = 0;
        if (out_init)     out_init[i]     = 0;
        if (out_last_vec) out_last_vec[i] = 0;
    }
    return n;
}

/*
 * BSP-side helper: aggregate ApInitSipiSnapshot into a single OphnApSipi NV
 * variable for post-boot inspection via read_ophn_log.ps1.
 *
 * Called only from BSP, only pre-EBS (gRT->SetVariable post-EBS is unreliable
 * from VMX root). The natural caller is the same DXE entry path that drives
 * ApInitVirtualizeAll, AFTER Step #B2 SIPI handlers have processed initial
 * AP wake from MP-services start-up. Today both ApInitVirtualizeAll and this
 * flush are force-linked but not invoked at DXE entry — flipping them on is
 * a Step #B4 stress-harness milestone.
 */
VOID
ApInitFlushSipiToNv(VOID)
{
    if (g_vcpu == NULL || g_cpu_count == 0) {
        VmmLogVarSet(L"OphnApSipi", "no_vcpu");
        return;
    }

    UINT32 total_sipi = 0, total_init = 0;
    UINTN  n = (g_cpu_count < APINIT_MAX_CPUS) ? g_cpu_count : APINIT_MAX_CPUS;
    for (UINTN i = 0; i < n; i++) {
        total_sipi += g_vcpu[i].sipi_seen;
        total_init += g_vcpu[i].init_seen;
    }

    VmmLogVarSetf(L"OphnApSipi",
                  "cpus=%u total_sipi=%u total_init=%u "
                  "ok_mask=0x%llx fail_mask=0x%llx",
                  (UINT32)n, total_sipi, total_init,
                  g_ap_ok_mask, g_ap_fail_mask);
}

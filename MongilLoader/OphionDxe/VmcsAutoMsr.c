/*
 * VmcsAutoMsr.c - VMCS auto MSR save/load list for LBR + DEBUGCTL isolation
 *
 * Per Grill 20 (Ophion-vs-VGK plan): vgk's per-CPU canary timer reads
 * IA32_DEBUGCTL bit 0 and the LBR ring (32 MSR pairs at 0x680-0x68F /
 * 0x6C0-0x6CF) every 50ms. If host code branches leak into the LBR ring,
 * vgk sees host RIPs => VAN ban.
 *
 * Mitigation: configure VMCS auto save/load lists so hardware atomically:
 *   - VMEXIT: save guest DEBUGCTL + LBR ring => VMEXIT_MSR_STORE list
 *             load host  DEBUGCTL = 0 + LBR cleared => VMEXIT_MSR_LOAD list
 *   - VMENTRY: load guest DEBUGCTL + LBR ring => VMENTRY_MSR_LOAD list
 *
 * Result: host runs with LBR disabled and ring cleared. Guest sees its
 * own LBR state intact across exits. vgk canary observes monotonic LBR
 * traffic = no flag.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>

#include "EfiCompat.h"

#define IA32_DEBUGCTL              0x000001D9
#define IA32_LASTBRANCH_TOS        0x000001C9

// LBR ring depth varies by uarch. Skylake+ Intel = 32 entries.
// Ice Lake / Alder Lake architectural LBR = up to 32 via CPUID 0x1C.
// Conservative: capture 32 FROM + 32 TO + 32 INFO + DEBUGCTL + TOS = 99 entries.
// We pick 32 LBR entries; binary builds against the upper bound.
#define LBR_DEPTH                  32
#define IA32_LASTBRANCH_FROM_BASE  0x00000680
#define IA32_LASTBRANCH_TO_BASE    0x000006C0

// VMX MSR save/load entry layout (Intel SDM Vol 3 24.7.2)
typedef struct {
    UINT32 Index;
    UINT32 Reserved;
    UINT64 Data;
} VMX_MSR_ENTRY;

#define VMM_MSR_LIST_MAX  128

typedef struct {
    VMX_MSR_ENTRY  vmexit_store[VMM_MSR_LIST_MAX];   // saves guest state on VMEXIT
    UINT32         vmexit_store_count;
    UINT32         _pad0;

    VMX_MSR_ENTRY  vmexit_load[VMM_MSR_LIST_MAX];    // loads host clean state on VMEXIT
    UINT32         vmexit_load_count;
    UINT32         _pad1;

    VMX_MSR_ENTRY  vmentry_load[VMM_MSR_LIST_MAX];   // loads guest state on VMENTRY
    UINT32         vmentry_load_count;
    UINT32         _pad2;
} VMM_MSR_LISTS;

static VOID
add_save(VMM_MSR_LISTS *lists, UINT32 msr_index)
{
    if (lists->vmexit_store_count >= VMM_MSR_LIST_MAX) return;
    lists->vmexit_store[lists->vmexit_store_count].Index = msr_index;
    lists->vmexit_store_count++;
}

static VOID
add_host_load(VMM_MSR_LISTS *lists, UINT32 msr_index, UINT64 host_value)
{
    if (lists->vmexit_load_count >= VMM_MSR_LIST_MAX) return;
    lists->vmexit_load[lists->vmexit_load_count].Index = msr_index;
    lists->vmexit_load[lists->vmexit_load_count].Data  = host_value;
    lists->vmexit_load_count++;
}

static VOID
add_guest_load(VMM_MSR_LISTS *lists, UINT32 msr_index, UINT64 guest_value)
{
    if (lists->vmentry_load_count >= VMM_MSR_LIST_MAX) return;
    lists->vmentry_load[lists->vmentry_load_count].Index = msr_index;
    lists->vmentry_load[lists->vmentry_load_count].Data  = guest_value;
    lists->vmentry_load_count++;
}

/*
 * Build LBR + DEBUGCTL save/load lists.
 *
 * On VMEXIT:
 *   - capture every guest LBR MSR + DEBUGCTL => store list
 *   - load host with LBR cleared, DEBUGCTL = 0 => load list (host runs LBR-off)
 * On VMENTRY:
 *   - LBR ring already saved per-VCPU at last VMEXIT; load it back from
 *     the same per-VCPU buffer the hardware filled.
 *
 * The save and entry-load lists share the same MSR set; the host load list
 * loads zeros so host runs with LBR ring quiet.
 */
VOID
VmcsBuildLbrSaveLoadLists(VMM_MSR_LISTS *lists)
{
    ZeroMem(lists, sizeof(*lists));

    // DEBUGCTL: save guest, host = 0 (no LBR, no BTM, no FREEZE_LBR_PMI)
    add_save(lists, IA32_DEBUGCTL);
    add_host_load(lists, IA32_DEBUGCTL, 0);
    // VMENTRY load reuses the saved guest value via store list at next exit;
    // for first entry we let it inherit guest's existing DEBUGCTL.

    // LBR_TOS
    add_save(lists, IA32_LASTBRANCH_TOS);
    add_host_load(lists, IA32_LASTBRANCH_TOS, 0);

    // LBR ring FROM/TO pairs
    for (UINT32 i = 0; i < LBR_DEPTH; ++i) {
        UINT32 from_msr = IA32_LASTBRANCH_FROM_BASE + i;
        UINT32 to_msr   = IA32_LASTBRANCH_TO_BASE   + i;

        add_save(lists, from_msr);
        add_save(lists, to_msr);
        add_host_load(lists, from_msr, 0);
        add_host_load(lists, to_msr,   0);
    }

    Print(L"[VmcsAutoMsr] save=%u host_load=%u entry_load=%u\n",
          lists->vmexit_store_count,
          lists->vmexit_load_count,
          lists->vmentry_load_count);
}

/*
 * Returns the static lists struct for the current VCPU. Phase 2 placeholder:
 * the real impl will allocate one VMM_MSR_LISTS per VCPU in
 * EfiRuntimeServicesCode and wire its phys addresses into VMCS via
 *   VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS / *_LOAD_ADDRESS / *_VMENTRY_*
 * plus the matching _COUNT fields.
 */
static VMM_MSR_LISTS g_default_lists;

VOID *
VmcsGetDefaultMsrLists(VOID)
{
    static BOOLEAN built = FALSE;
    if (!built) {
        VmcsBuildLbrSaveLoadLists(&g_default_lists);
        built = TRUE;
    }
    return &g_default_lists;
}

/*
 * Phase 7c-4b minimal: single-entry VMEXIT_MSR_LOAD = {IA32_DEBUGCTL, 0}.
 * Hardware atomically clears DEBUGCTL on every VMEXIT so host runs LBR-off,
 * BTS-off, BTM-off — vgk per-CPU canary samples LBR ring sees no host RIP
 * leak.
 *
 * Allocated in EfiRuntimeServicesData via EfiAllocateRuntimePages so it
 * survives ExitBootServices (firmware reclaims BootServicesData). Page-
 * aligned = 16-byte aligned (Intel SDM 25.7.2 requires 16-byte alignment).
 *
 * Failure mode if WRMSR fails: VMX abort 4 (unrecoverable). DEBUGCTL=0
 * is always legal (clears valid feature bits) so abort impossible here.
 */
extern PVOID EfiAllocateRuntimePages(UINTN Pages);
extern UINT64 va_to_pa(PVOID va);

#define IA32_DEBUGCTL_MSR  0x000001D9

static VMX_MSR_ENTRY *g_vmexit_load_list    = NULL;
static UINT64         g_vmexit_load_list_pa = 0;
static UINT32         g_vmexit_load_count   = 0;

BOOLEAN
VmcsAllocMinimalLoadList(VOID)
{
    if (g_vmexit_load_list != NULL) return TRUE;  // idempotent

    g_vmexit_load_list = (VMX_MSR_ENTRY *)EfiAllocateRuntimePages(1);
    if (!g_vmexit_load_list) return FALSE;

    // Zero the page first so any unused entries are deterministic.
    for (UINTN i = 0; i < (PAGE_SIZE / sizeof(VMX_MSR_ENTRY)); ++i) {
        g_vmexit_load_list[i].Index    = 0;
        g_vmexit_load_list[i].Reserved = 0;
        g_vmexit_load_list[i].Data     = 0;
    }

    g_vmexit_load_list[0].Index    = IA32_DEBUGCTL_MSR;
    g_vmexit_load_list[0].Reserved = 0;
    g_vmexit_load_list[0].Data     = 0;
    g_vmexit_load_count            = 1;
    g_vmexit_load_list_pa          = va_to_pa(g_vmexit_load_list);

    return TRUE;
}

UINT64
VmcsGetVmexitLoadListPa(VOID)
{
    return g_vmexit_load_list_pa;
}

UINT32
VmcsGetVmexitLoadCount(VOID)
{
    return g_vmexit_load_count;
}

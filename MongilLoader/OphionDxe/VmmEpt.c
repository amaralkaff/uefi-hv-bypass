/*
 * VmmEpt.c - identity-mapped EPT for UEFI. Ported from Ophion/src/ept.c.
 *
 * Phase 2 deltas vs Ophion vanilla:
 *   - MmAllocateContiguousMemory(...) → EfiAllocateRuntimePages(pages)
 *     Each VMM_EPT_PAGE_TABLE is ~2MB (514 4KB-aligned tables). UEFI's
 *     AllocatePages already returns page-aligned PA; no manual alignment.
 *   - va_to_pa / pa_to_va are identity in UEFI (see VmmUtil.c).
 *   - hv_log uses Print() pre-EBS (see VmmLog.c).
 *   - ept_split_large_page* deferred — only needed for Phase 4 EPT hooks.
 *
 * Identity-maps 512 GiB physical 1:1 with 2MB large pages, MTRR-aware memory typing.
 */
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <intrin.h>
#include "EfiCompat.h"
#include "ia32.h"
#include "hv_types.h"

extern VOID hv_log(IN CONST CHAR8 *fmt, ...);
UINT64 va_to_pa(PVOID va);
PVOID  pa_to_va(UINT64 pa);
PVMM_EPT_DYNAMIC_SPLIT ept_take_preallocated_split(VOID);

extern EPT_STATE             *g_ept;
extern VIRTUAL_MACHINE_STATE *g_vcpu;
extern UINT32                 g_cpu_count;

#define EPT_PT_PAGES  ((sizeof(VMM_EPT_PAGE_TABLE) + PAGE_SIZE - 1) / PAGE_SIZE)

BOOLEAN
ept_check_features(VOID)
{
    IA32_VMX_EPT_VPID_CAP_REGISTER vpid_reg;
    IA32_MTRR_DEF_TYPE_REGISTER    mtrr_def;

    vpid_reg.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);
    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (!vpid_reg.PageWalkLength4 || !vpid_reg.MemoryTypeWriteBack || !vpid_reg.Pde2MbPages) {
        hv_log("[hv] EPT: missing required features (PW4=%d WB=%d 2MB=%d)\n",
               vpid_reg.PageWalkLength4, vpid_reg.MemoryTypeWriteBack, vpid_reg.Pde2MbPages);
        return FALSE;
    }

    g_ept->ad_supported = vpid_reg.EptAccessedAndDirtyFlags ? TRUE : FALSE;

    g_ept->invvpid_supported              = vpid_reg.Invvpid ? TRUE : FALSE;
    g_ept->invvpid_individual_addr        = vpid_reg.InvvpidIndividualAddress ? TRUE : FALSE;
    g_ept->invvpid_single_context         = vpid_reg.InvvpidSingleContext ? TRUE : FALSE;
    g_ept->invvpid_all_contexts           = vpid_reg.InvvpidAllContexts ? TRUE : FALSE;
    g_ept->invvpid_single_retaining_globals =
        vpid_reg.InvvpidSingleContextRetainingGlobals ? TRUE : FALSE;

    if (!mtrr_def.MtrrEnable) {
        hv_log("[hv] EPT: MTRR not enabled\n");
        return FALSE;
    }

    return TRUE;
}

UINT8
ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page)
{
    SIZE_T page_addr = is_large_page ? pfn * SIZE_2_MB : pfn * PAGE_SIZE;
    UINT8  target_type = (UINT8)-1;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++) {
        MTRR_RANGE_DESCRIPTOR *range = &g_ept->mem_ranges[i];

        if (page_addr >= range->phys_base && page_addr < range->phys_end) {
            if (range->fixed) {
                target_type = range->mem_type;
                break;
            }
            if (target_type == MEMORY_TYPE_UNCACHEABLE) {
                target_type = range->mem_type;
                break;
            }
            if (target_type == MEMORY_TYPE_WRITE_THROUGH ||
                range->mem_type == MEMORY_TYPE_WRITE_THROUGH) {
                if (target_type == MEMORY_TYPE_WRITE_BACK) {
                    target_type = MEMORY_TYPE_WRITE_THROUGH;
                    continue;
                }
            }
            target_type = range->mem_type;
        }
    }

    if (target_type == (UINT8)-1)
        target_type = g_ept->default_type;

    return target_type;
}

BOOLEAN
ept_build_mtrr_map(VOID)
{
    IA32_MTRR_CAPABILITIES_REGISTER mtrr_cap;
    IA32_MTRR_DEF_TYPE_REGISTER     mtrr_def;
    IA32_MTRR_PHYSBASE_REGISTER     cur_base;
    IA32_MTRR_PHYSMASK_REGISTER     cur_mask;
    MTRR_RANGE_DESCRIPTOR          *desc;

    mtrr_cap.AsUInt = __readmsr(IA32_MTRR_CAPABILITIES);
    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (!mtrr_def.MtrrEnable) {
        g_ept->default_type = MEMORY_TYPE_UNCACHEABLE;
        return TRUE;
    }

    g_ept->default_type = (UINT8)mtrr_def.DefaultMemoryType;

    if (mtrr_cap.FixedRangeSupported && mtrr_def.FixedRangeMtrrEnable) {
        // FIX64K_00000: 8 x 64KB
        IA32_MTRR_FIXED_RANGE_TYPE k64 = { __readmsr(IA32_MTRR_FIX64K_00000) };
        for (UINT32 i = 0; i < 8; i++) {
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->mem_type  = k64.s.Types[i];
            desc->phys_base = 0x10000ULL * i;
            desc->phys_end  = 0x10000ULL * i + 0x10000 - 1;
            desc->fixed     = TRUE;
        }
        // FIX16K_80000/A0000: 16 x 16KB
        for (UINT32 i = 0; i < 2; i++) {
            IA32_MTRR_FIXED_RANGE_TYPE k16 = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };
            for (UINT32 j = 0; j < 8; j++) {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type  = k16.s.Types[j];
                desc->phys_base = 0x80000 + (i * 0x20000) + (j * 0x4000);
                desc->phys_end  = desc->phys_base + 0x4000 - 1;
                desc->fixed     = TRUE;
            }
        }
        // FIX4K_C0000..F8000: 64 x 4KB
        for (UINT32 i = 0; i < 8; i++) {
            IA32_MTRR_FIXED_RANGE_TYPE k4 = { __readmsr(IA32_MTRR_FIX4K_C0000 + i) };
            for (UINT32 j = 0; j < 8; j++) {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type  = k4.s.Types[j];
                desc->phys_base = 0xC0000 + (i * 0x8000) + (j * 0x1000);
                desc->phys_end  = desc->phys_base + 0x1000 - 1;
                desc->fixed     = TRUE;
            }
        }
    }

    for (UINT32 i = 0; i < mtrr_cap.VariableRangeCount; i++) {
        cur_base.AsUInt = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
        cur_mask.AsUInt = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

        if (cur_mask.Valid) {
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->phys_base = cur_base.PageFrameNumber * PAGE_SIZE;

            unsigned long mask_bits;
            _BitScanForward64(&mask_bits, cur_mask.PageFrameNumber * PAGE_SIZE);

            desc->phys_end = desc->phys_base + ((1ULL << mask_bits) - 1ULL);
            desc->mem_type = (UINT8)cur_base.Type;
            desc->fixed    = FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
ept_valid_for_large_page(SIZE_T pfn)
{
    SIZE_T start_addr = pfn * SIZE_2_MB;
    SIZE_T end_addr   = start_addr + SIZE_2_MB - 1;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++) {
        MTRR_RANGE_DESCRIPTOR *range = &g_ept->mem_ranges[i];

        if ((start_addr <= range->phys_end && end_addr > range->phys_end) ||
            (start_addr < range->phys_base && end_addr >= range->phys_base)) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN
ept_setup_pml2(PVMM_EPT_PAGE_TABLE page_table, PEPT_PML2_ENTRY new_entry, SIZE_T pfn)
{
    UNREFERENCED_PARAMETER(page_table);
    new_entry->PageFrameNumber = pfn;

    new_entry->MemoryType = ept_get_memory_type(pfn, TRUE);

    if (!ept_valid_for_large_page(pfn)) {
        // Crosses MTRR boundary — Phase 4 split-to-4KB needed for EPT hooks.
        // Phase 2 just leaves it as 2MB with the chosen memory type.
    }
    return TRUE;
}

PVMM_EPT_PAGE_TABLE
ept_alloc_identity_map(VOID)
{
    PVMM_EPT_PAGE_TABLE page_table;
    EPT_PML2_ENTRY      pml2_tmpl;

    page_table = (PVMM_EPT_PAGE_TABLE)EfiAllocateRuntimePages(EPT_PT_PAGES);
    if (!page_table)
        return NULL;

    page_table->PML4[0].ReadAccess    = 1;
    page_table->PML4[0].WriteAccess   = 1;
    page_table->PML4[0].ExecuteAccess = 1;
    page_table->PML4[0].PageFrameNumber = va_to_pa(&page_table->PML3[0]) / PAGE_SIZE;

    for (SIZE_T i = 0; i < VMM_EPT_PML3E_COUNT; i++) {
        page_table->PML3[i].ReadAccess    = 1;
        page_table->PML3[i].WriteAccess   = 1;
        page_table->PML3[i].ExecuteAccess = 1;
        page_table->PML3[i].PageFrameNumber = va_to_pa(&page_table->PML2[i][0]) / PAGE_SIZE;
    }

    pml2_tmpl.AsUInt        = 0;
    pml2_tmpl.ReadAccess    = 1;
    pml2_tmpl.WriteAccess   = 1;
    pml2_tmpl.ExecuteAccess = 1;
    pml2_tmpl.LargePage     = 1;

    __stosq((SIZE_T *)&page_table->PML2[0], pml2_tmpl.AsUInt,
            VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

    for (SIZE_T group = 0; group < VMM_EPT_PML3E_COUNT; group++) {
        for (SIZE_T entry_idx = 0; entry_idx < VMM_EPT_PML2E_COUNT; entry_idx++) {
            ept_setup_pml2(page_table,
                           &page_table->PML2[group][entry_idx],
                           (group * VMM_EPT_PML2E_COUNT) + entry_idx);
        }
    }

    return page_table;
}

BOOLEAN
ept_init(VOID)
{
    EPT_POINTER eptp = {0};

    g_ept = (EPT_STATE *)EfiAllocateRuntimePages(
        (sizeof(EPT_STATE) + PAGE_SIZE - 1) / PAGE_SIZE);
    if (!g_ept)
        return FALSE;

    InitializeListHead(&g_ept->hooked_pages);

    if (!ept_check_features())
        return FALSE;

    if (!ept_build_mtrr_map())
        return FALSE;

    for (UINT32 i = 0; i < g_cpu_count; i++) {
        PVMM_EPT_PAGE_TABLE page_table = ept_alloc_identity_map();
        if (!page_table) {
            hv_log("[hv] EPT: failed to allocate page table for core %u\n", i);
            return FALSE;
        }

        g_vcpu[i].ept_page_table = page_table;

        eptp.MemoryType                 = MEMORY_TYPE_WRITE_BACK;
        eptp.EnableAccessAndDirtyFlags  = g_ept->ad_supported;
        eptp.PageWalkLength             = 3;  // 4-level walk (value = levels - 1)
        eptp.PageFrameNumber            = va_to_pa(&page_table->PML4) / PAGE_SIZE;

        g_vcpu[i].ept_pointer = eptp;
    }

    hv_log("[hv] EPT initialized for %u processors\n", g_cpu_count);
    return TRUE;
}

PEPT_PML2_ENTRY
ept_get_pml2(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    SIZE_T dir   = ADDRMASK_EPT_PML2_INDEX(phys_addr);
    SIZE_T dir_p = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    SIZE_T pml4  = ADDRMASK_EPT_PML4_INDEX(phys_addr);

    if (pml4 > 0)
        return NULL;

    return &page_table->PML2[dir_p][dir];
}

PEPT_PML1_ENTRY
ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    SIZE_T dir   = ADDRMASK_EPT_PML2_INDEX(phys_addr);
    SIZE_T dir_p = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    SIZE_T pml4  = ADDRMASK_EPT_PML4_INDEX(phys_addr);

    if (pml4 > 0)
        return NULL;

    PEPT_PML2_ENTRY pml2 = &page_table->PML2[dir_p][dir];
    if (pml2->LargePage)
        return NULL;

    PEPT_PML2_POINTER ptr = (PEPT_PML2_POINTER)pml2;
    PEPT_PML1_ENTRY  pml1 = (PEPT_PML1_ENTRY)pa_to_va(ptr->PageFrameNumber * PAGE_SIZE);
    if (!pml1)
        return NULL;

    return &pml1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
}

//
// Phase 7d helper for VMM exit handlers (typed via void* in headers to keep
// hv_types.h free of EPT structure cycles).
//
VOID *
ept_pml1_for_gphys_bsp(UINT64 gphys)
{
    if (!g_vcpu) return NULL;
    return (VOID *)ept_get_pml1(g_vcpu[0].ept_page_table, gphys);
}

extern UINT8 asm_invept(UINT32 type, PVOID descriptor);
extern UINT8 asm_invvpid(UINT32 type, PVOID descriptor);

VOID
ept_invept_single(EPT_POINTER ept_ptr)
{
    INVEPT_DESCRIPTOR desc = {0};
    desc.EptPointer = ept_ptr;
    asm_invept(InveptSingleContext, &desc);
}

VOID
ept_invept_all(VOID)
{
    INVEPT_DESCRIPTOR desc = {0};
    asm_invept(InveptAllContexts, &desc);
}

VOID
vpid_invvpid_single(UINT16 vpid)
{
    INVVPID_DESCRIPTOR desc = {0};
    desc.Vpid = vpid;
    asm_invvpid(InvvpidSingleContext, &desc);
}

//
// Phase 7d step 1: EPT 4KB split.
//
// Splits a 2MB large-page PML2 entry into 512 4KB PML1 entries for fine-grained
// EPT permission control. Required for code cloaking — single 4KB ntos.text
// page needs distinct read-vs-execute views via MTF single-step.
//
// Idempotent: if already split (LargePage=0), returns TRUE without re-allocating.
// Allocation lives in EfiRuntimeServicesData, survives ExitBootServices.
// Inherits memory type / pat / suppress-ve attributes from the parent 2MB entry
// to avoid changing cache behavior.
//
// Caller must INVEPT after calling this to flush stale TLB entries pointing at
// the now-replaced 2MB mapping.
//
BOOLEAN
ept_split_2mb_to_4kb(PVMM_EPT_PAGE_TABLE page_table, UINT64 phys_addr)
{
    PEPT_PML2_ENTRY pml2 = ept_get_pml2(page_table, phys_addr);
    if (!pml2) return FALSE;
    if (!pml2->LargePage) return TRUE;  // already split, nothing to do

    EPT_PML2_ENTRY old_entry = *pml2;
    UINT64         base_pfn  = old_entry.PageFrameNumber * 512;  // 2MB-PFN -> 4KB-PFN base

    // Phase 7d post-EBS safety: NEVER call EfiAllocateRuntimePages from VMX
    // root — gBS is invalid post-EBS and any boot-services call freezes.
    // Use pre-allocated split slot from DXE entry pool.
    PVMM_EPT_DYNAMIC_SPLIT split = ept_take_preallocated_split();
    if (!split) return FALSE;

    split->u.Entry = pml2;  // remember which PML2 entry we replaced (for unsplit)

    EPT_PML1_ENTRY pml1_tmpl = {0};
    pml1_tmpl.ReadAccess    = 1;
    pml1_tmpl.WriteAccess   = 1;
    pml1_tmpl.ExecuteAccess = 1;
    pml1_tmpl.MemoryType    = old_entry.MemoryType;
    pml1_tmpl.IgnorePat     = old_entry.IgnorePat;
    pml1_tmpl.SuppressVe    = old_entry.SuppressVe;

    for (UINTN i = 0; i < VMM_EPT_PML1E_COUNT; ++i) {
        split->PML1[i].AsUInt          = pml1_tmpl.AsUInt;
        split->PML1[i].PageFrameNumber = base_pfn + i;
    }

    EPT_PML2_POINTER new_pml2 = {0};
    new_pml2.ReadAccess      = 1;
    new_pml2.WriteAccess     = 1;
    new_pml2.ExecuteAccess   = 1;
    new_pml2.PageFrameNumber = va_to_pa(&split->PML1[0]) / PAGE_SIZE;

    pml2->AsUInt = new_pml2.AsUInt;

    InsertHeadList(&g_ept->hooked_pages, &split->SplitList);

    return TRUE;
}

//
// Phase 7d post-EBS safety: pre-allocate split table pool + alt-page pool
// at DXE entry (gBS valid). VMX-root cloak install reserves from pool.
//
#define EPT_SPLIT_POOL_SIZE  4
#define ALT_PAGE_POOL_SIZE   4

static PVMM_EPT_DYNAMIC_SPLIT g_split_pool[EPT_SPLIT_POOL_SIZE] = {0};
static UINT8                  g_split_pool_used[EPT_SPLIT_POOL_SIZE] = {0};
static UINT8                 *g_alt_page_pool[ALT_PAGE_POOL_SIZE] = {0};
static UINT8                  g_alt_page_pool_used[ALT_PAGE_POOL_SIZE] = {0};

BOOLEAN
ept_preallocate_pools(VOID)
{
    UINTN split_pages = (sizeof(VMM_EPT_DYNAMIC_SPLIT) + PAGE_SIZE - 1) / PAGE_SIZE;
    for (UINTN i = 0; i < EPT_SPLIT_POOL_SIZE; ++i) {
        g_split_pool[i] = (PVMM_EPT_DYNAMIC_SPLIT)EfiAllocateRuntimePages(split_pages);
        if (!g_split_pool[i]) return FALSE;
    }
    for (UINTN i = 0; i < ALT_PAGE_POOL_SIZE; ++i) {
        g_alt_page_pool[i] = (UINT8 *)EfiAllocateRuntimePages(1);
        if (!g_alt_page_pool[i]) return FALSE;
    }
    return TRUE;
}

PVMM_EPT_DYNAMIC_SPLIT
ept_take_preallocated_split(VOID)
{
    for (UINTN i = 0; i < EPT_SPLIT_POOL_SIZE; ++i) {
        if (!g_split_pool_used[i] && g_split_pool[i]) {
            g_split_pool_used[i] = 1;
            return g_split_pool[i];
        }
    }
    return NULL;
}

UINT8 *
ept_take_preallocated_alt_page(VOID)
{
    for (UINTN i = 0; i < ALT_PAGE_POOL_SIZE; ++i) {
        if (!g_alt_page_pool_used[i] && g_alt_page_pool[i]) {
            g_alt_page_pool_used[i] = 1;
            return g_alt_page_pool[i];
        }
    }
    return NULL;
}

//
// Phase 7d step 2: EPT cloak install.
//
// Installs a 2-view cloak on a 4KB physical page:
//   - exec view: alt_phys (caller-supplied, holds patched bytes), X=1 R=0 W=0
//   - read view: real_phys (untouched original), R=1 X=0  (set on first
//     EPT violation, restored after MTF single-step)
//
// On entry the target's PML2 region must already be split via
// ept_split_2mb_to_4kb. Caller must drive INVEPT broadcast across all virt'd
// cores (currently BSP only — Phase 3 partial leaves APs bare-metal so they
// hit real phys directly, which is fine because the patch path is never
// fetched from APs while cheat is BSP-pinned).
//
// Returns: pointer to the modified PML1 entry on success, NULL on failure.
// The pointer is stored alongside real_pfn/alt_pfn in g_cloaks[] so the
// violation handler can identify cloaked entries without walking lists.
//

#define OPHION_MAX_CLOAKS  8

typedef struct {
    BOOLEAN          active;
    UINT64           target_gphys;   // 4KB-aligned phys addr of cloaked page
    UINT64           real_pfn;
    UINT64           alt_pfn;
    PEPT_PML1_ENTRY  pml1_entry;     // BSP only for now (Phase 3 partial)
} OPHION_CLOAK;

OPHION_CLOAK g_cloaks[OPHION_MAX_CLOAKS] = {0};

PEPT_PML1_ENTRY
ept_install_cloak(UINT64 target_gphys, UINT64 alt_pfn)
{
    PVMM_EPT_PAGE_TABLE pt = g_vcpu[0].ept_page_table;
    if (!pt) return NULL;

    if (!ept_split_2mb_to_4kb(pt, target_gphys)) return NULL;

    PEPT_PML1_ENTRY pml1 = ept_get_pml1(pt, target_gphys);
    if (!pml1) return NULL;

    UINT64 real_pfn = pml1->PageFrameNumber;

    // Find free slot.
    OPHION_CLOAK *slot = NULL;
    for (UINTN i = 0; i < OPHION_MAX_CLOAKS; ++i) {
        if (!g_cloaks[i].active) { slot = &g_cloaks[i]; break; }
    }
    if (!slot) return NULL;

    slot->target_gphys = target_gphys & ~0xFFFULL;
    slot->real_pfn     = real_pfn;
    slot->alt_pfn      = alt_pfn;
    slot->pml1_entry   = pml1;
    slot->active       = TRUE;

    // Switch to exec-only view. Memory type / suppress-ve / pat preserved
    // from split-time template (already set by ept_split_2mb_to_4kb).
    pml1->ReadAccess      = 0;
    pml1->WriteAccess     = 0;
    pml1->ExecuteAccess   = 1;
    pml1->PageFrameNumber = alt_pfn;

    ept_invept_single(g_vcpu[0].ept_pointer);

    hv_log("[hv] cloak: gphys=0x%llx real_pfn=0x%llx alt_pfn=0x%llx\n",
           target_gphys, real_pfn, alt_pfn);

    return pml1;
}

//
// Phase 7d helper: lookup cloak slot by PML1 entry pointer. Used by
// EPT_VIOLATION handler to fetch the real_pfn for swap-on-read.
//
OPHION_CLOAK *
ept_find_cloak_by_pml1(PEPT_PML1_ENTRY pml1)
{
    for (UINTN i = 0; i < OPHION_MAX_CLOAKS; ++i) {
        if (g_cloaks[i].active && g_cloaks[i].pml1_entry == pml1)
            return &g_cloaks[i];
    }
    return NULL;
}

//
// Phase 7d step 3 helpers (called from VmmExit.c). Encapsulate cloak swap
// transitions so the dispatcher stays compact.
//
// On EPT violation (read attempt on exec-only cloaked page):
//   set PML1 to {real_pfn, R=1, X=0}, save alt_pfn for MTF restore.
//
// On MTF (after single-step):
//   set PML1 back to {alt_pfn, R=0, X=1}.
//
// Both helpers expect caller to drive INVEPT (single-context) afterwards.
//
BOOLEAN
ept_cloak_violation_swap_to_read(UINT64 gphys, UINT64 *out_alt_pfn,
                                 VOID **out_pml1)
{
    PEPT_PML1_ENTRY pml1 =
        (PEPT_PML1_ENTRY)ept_pml1_for_gphys_bsp(gphys & ~0xFFFULL);
    if (!pml1) return FALSE;

    OPHION_CLOAK *c = ept_find_cloak_by_pml1(pml1);
    if (!c) return FALSE;

    if (out_alt_pfn) *out_alt_pfn = c->alt_pfn;
    if (out_pml1)    *out_pml1    = pml1;

    // Phase 7d bugfix: during single-step window, expose REAL page with full
    // permissions (R=1 W=1 X=1). Reason: ntos.text page holds many kernel
    // functions besides our NCP target. After swap, ANY instruction fetch
    // on this page from BSP needs to succeed. If we set X=0, we re-violate
    // immediately on the next kernel insn fetch -> infinite vmexit loop /
    // freeze. Cost: one instruction window where BSP could fetch real (clean)
    // NCP bytes instead of patched. Tradeoff: fetcher would be PG itself
    // (typically reads clean bytes anyway), and the trampoline call path
    // hits this page very rarely vs PG scan rate -> acceptable tiny race.
    pml1->ReadAccess      = 1;
    pml1->WriteAccess     = 1;
    pml1->ExecuteAccess   = 1;
    pml1->PageFrameNumber = c->real_pfn;
    return TRUE;
}

VOID
ept_cloak_mtf_swap_to_exec(VOID *pml1_void, UINT64 alt_pfn)
{
    PEPT_PML1_ENTRY pml1 = (PEPT_PML1_ENTRY)pml1_void;
    if (!pml1) return;
    pml1->ReadAccess      = 0;
    pml1->WriteAccess     = 0;
    pml1->ExecuteAccess   = 1;
    pml1->PageFrameNumber = alt_pfn;
}

EPT_POINTER
ept_get_eptp_bsp(VOID)
{
    EPT_POINTER zero = {0};
    if (!g_vcpu) return zero;
    return g_vcpu[0].ept_pointer;
}

/*
 * VmmGuestPt.c - guest virtual address page-table walker for VMX-root context.
 *
 * Translates a guest VA → guest PA by manually walking the 4-level page table
 * pointed to by guest CR3. Designed to run from a vmexit handler.
 *
 * Why manual walk: we cannot use NT's MmGetPhysicalAddress / MmMapIoSpace from
 * VMX-root — the VMM has no NT primitives. Phase 4 KiServiceTable resolution +
 * NtCreateProfile patch + cross-process memory reads all need GVA→GPA translation.
 *
 * GPA→HPA: identity under our current EPT (1:1 for first 512GB). After Phase
 * 4 EPT 4KB-split, GPA→HPA still identity for non-cloaked pages. Reading the
 * resulting HPA via host CR3: our flat-1GB-identity host CR3 maps phys 0..512GB
 * 1:1 to host VA — so dereferencing `(UINT64 *)gpa` from VMX-root reads guest
 * physical memory directly.
 *
 * Limitations:
 *   - Walks classic 4-level (PML4) only. PML5 / 5-level paging not supported
 *     (Alder Lake i5-12400F doesn't enable 5-level by default in Win10).
 *   - Returns 0 for non-present, large-page or 1GB pages handled correctly.
 *   - No SMAP/SMEP awareness — VMX-root reads bypass both.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include "EfiCompat.h"
#include "ia32.h"

// Page table entry mask: bits 12..51 carry physical address for non-large
// pages. For 1GB / 2MB pages, low bits (29..0 / 20..0) cleared by mask.
#define PT_PA_MASK_4KB   0x000FFFFFFFFFF000ULL
#define PT_PA_MASK_2MB   0x000FFFFFFFE00000ULL
#define PT_PA_MASK_1GB   0x000FFFFFC0000000ULL

#define PTE_PRESENT      (1ULL << 0)
#define PTE_LARGE_PAGE   (1ULL << 7)

#define INDEX_PML4(va)   (((va) >> 39) & 0x1FF)
#define INDEX_PDPT(va)   (((va) >> 30) & 0x1FF)
#define INDEX_PD(va)     (((va) >> 21) & 0x1FF)
#define INDEX_PT(va)     (((va) >> 12) & 0x1FF)

#define OFFSET_4KB(va)   ((va) & 0xFFFULL)
#define OFFSET_2MB(va)   ((va) & 0x1FFFFFULL)
#define OFFSET_1GB(va)   ((va) & 0x3FFFFFFFULL)

// guest CR3 carries low control bits; mask to PA.
#define CR3_PA_MASK      0x000FFFFFFFFFF000ULL

UINT64
vmm_pt_walk(UINT64 cr3, UINT64 va)
{
    UINT64 pml4_pa = cr3 & CR3_PA_MASK;
    UINT64 *pml4   = (UINT64 *)(UINTN)pml4_pa;       // host CR3 identity map
    UINT64 pml4e   = pml4[INDEX_PML4(va)];
    if (!(pml4e & PTE_PRESENT)) return 0;

    UINT64 pdpt_pa = pml4e & PT_PA_MASK_4KB;
    UINT64 *pdpt   = (UINT64 *)(UINTN)pdpt_pa;
    UINT64 pdpte   = pdpt[INDEX_PDPT(va)];
    if (!(pdpte & PTE_PRESENT)) return 0;
    if (pdpte & PTE_LARGE_PAGE) {
        return (pdpte & PT_PA_MASK_1GB) | OFFSET_1GB(va);
    }

    UINT64 pd_pa = pdpte & PT_PA_MASK_4KB;
    UINT64 *pd   = (UINT64 *)(UINTN)pd_pa;
    UINT64 pde   = pd[INDEX_PD(va)];
    if (!(pde & PTE_PRESENT)) return 0;
    if (pde & PTE_LARGE_PAGE) {
        return (pde & PT_PA_MASK_2MB) | OFFSET_2MB(va);
    }

    UINT64 pt_pa = pde & PT_PA_MASK_4KB;
    UINT64 *pt   = (UINT64 *)(UINTN)pt_pa;
    UINT64 pte   = pt[INDEX_PT(va)];
    if (!(pte & PTE_PRESENT)) return 0;

    return (pte & PT_PA_MASK_4KB) | OFFSET_4KB(va);
}

//
// Read N bytes from guest VA using guest CR3. Returns count read; short reads
// possible at page boundaries (caller must loop). Out parameter dst lives in
// VMM-host space (any pointer, including stack).
//
// Crosses page boundaries by re-walking each page. Slow but correct.
//
UINTN
vmm_guest_read(UINT64 cr3, UINT64 va, VOID *dst, UINTN size)
{
    UINT8 *out = (UINT8 *)dst;
    UINTN  done = 0;
    while (done < size) {
        UINT64 cur_va  = va + done;
        UINT64 page_pa = vmm_pt_walk(cr3, cur_va);
        if (page_pa == 0) break;

        UINTN  page_off = (UINTN)(cur_va & 0xFFFULL);
        UINTN  in_page  = 0x1000 - page_off;
        UINTN  remain   = size - done;
        UINTN  chunk    = (remain < in_page) ? remain : in_page;

        UINT8 *src_host = (UINT8 *)(UINTN)page_pa;   // identity map via host CR3
        CopyMem(out + done, src_host, chunk);

        done += chunk;
    }
    return done;
}

//
// Read 1/2/4/8-byte primitives. Returns 0 on read failure (ambiguous with
// genuine zero data — callers that care should read into a buffer + check
// vmm_guest_read returned full size).
//
UINT8
vmm_guest_read8(UINT64 cr3, UINT64 va)
{
    UINT8 v = 0;
    if (vmm_guest_read(cr3, va, &v, 1) != 1) return 0;
    return v;
}

UINT16
vmm_guest_read16(UINT64 cr3, UINT64 va)
{
    UINT16 v = 0;
    if (vmm_guest_read(cr3, va, &v, 2) != 2) return 0;
    return v;
}

UINT32
vmm_guest_read32(UINT64 cr3, UINT64 va)
{
    UINT32 v = 0;
    if (vmm_guest_read(cr3, va, &v, 4) != 4) return 0;
    return v;
}

UINT64
vmm_guest_read64(UINT64 cr3, UINT64 va)
{
    UINT64 v = 0;
    if (vmm_guest_read(cr3, va, &v, 8) != 8) return 0;
    return v;
}

//
// Write N bytes from src to guest VA via guest CR3. Mirrors vmm_guest_read.
// Returns count written. Used by VMCALL dispatch to write response back to
// caller buffer in the cheat exe address space.
//
UINTN
vmm_guest_write(UINT64 cr3, UINT64 va, CONST VOID *src, UINTN size)
{
    CONST UINT8 *in = (CONST UINT8 *)src;
    UINTN done = 0;
    while (done < size) {
        UINT64 cur_va  = va + done;
        UINT64 page_pa = vmm_pt_walk(cr3, cur_va);
        if (page_pa == 0) break;

        UINTN page_off = (UINTN)(cur_va & 0xFFFULL);
        UINTN in_page  = 0x1000 - page_off;
        UINTN remain   = size - done;
        UINTN chunk    = (remain < in_page) ? remain : in_page;

        UINT8 *dst_host = (UINT8 *)(UINTN)page_pa;
        CopyMem(dst_host, in + done, chunk);

        done += chunk;
    }
    return done;
}

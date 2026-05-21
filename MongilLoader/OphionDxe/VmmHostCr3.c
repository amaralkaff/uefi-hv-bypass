/*
 * VmmHostCr3.c - private host CR3 with flat identity mapping 0-512GB.
 *
 * Phase 2.6: replaced previous deep-clone of firmware PML4 with flat
 * identity-mapped 1GB huge pages.
 *
 * Why deep-clone failed: firmware PML4 entries point at PDPT/PD/PT pages that
 * live in EfiBootServicesData. Windows reclaims those after EBS. On the first
 * vmexit, CPU walks HOST_CR3 → hits a reclaimed PT page filled with garbage
 * → triple fault → reboot loop. Symptom: VMLAUNCH success, guest runs briefly,
 * machine reboots itself with no error captured.
 *
 * Why flat 1GB identity works: the only mappings the VMM-host needs are its
 * own allocations (OphionDxe text/data + per-VCPU regions), all of which live
 * in EfiRuntimeServicesCode pages with PA < 4GB on this rig. A single PML4
 * entry [0] pointing to one PDPT with 512 1GB entries covers PA range
 * 0x0..0x7FFFFFFFFF (512 GiB). Two pages total, 8KB.
 *
 * Requires PDPE 1GB pages (CPUID.80000001:EDX[26]=1) — universal on Ivy Bridge+.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>

#include "EfiCompat.h"

extern PVOID EfiAllocateRuntimePages(UINTN Pages);
extern UINT64 va_to_pa(PVOID va);
extern VOID  hv_log(IN CONST CHAR8 *fmt, ...);

#define PTE_P    (1ULL << 0)
#define PTE_RW   (1ULL << 1)
#define PTE_PS   (1ULL << 7)   // 1GB page in PDPT, 2MB page in PD

static UINT64 *g_host_pml4    = NULL;
static UINT64 *g_host_pdpt    = NULL;
static UINT64  g_host_pml4_pa = 0;

BOOLEAN
hostcr3_build(VOID)
{
    g_host_pml4 = (UINT64 *)EfiAllocateRuntimePages(1);
    g_host_pdpt = (UINT64 *)EfiAllocateRuntimePages(1);
    if (!g_host_pml4 || !g_host_pdpt) {
        hv_log("[hv] hostcr3: alloc failed\n");
        return FALSE;
    }
    ZeroMem(g_host_pml4, 4096);
    ZeroMem(g_host_pdpt, 4096);

    UINT64 pdpt_pa = (UINT64)(UINTN)g_host_pdpt;
    g_host_pml4[0] = pdpt_pa | PTE_P | PTE_RW;

    // 512 1GB identity entries: PA range 0..512GB linear (i << 30)
    for (UINT64 i = 0; i < 512; i++) {
        g_host_pdpt[i] = (i << 30) | PTE_P | PTE_RW | PTE_PS;
    }

    g_host_pml4_pa = (UINT64)(UINTN)g_host_pml4;
    hv_log("[hv] hostcr3: flat 1GB identity 0-512GB pml4_pa=0x%llx\n",
           g_host_pml4_pa);
    return TRUE;
}

UINT64 hostcr3_get(VOID)     { return g_host_pml4_pa; }
VOID   hostcr3_destroy(VOID) { /* runtime-pages, no free in Phase 2.6 */ }

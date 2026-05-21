/*
 * VmmHostGdt.c - private host GDT + TSS + TR for VMLAUNCH host-state.
 *
 * UEFI bare-metal leaves TR=0. SDM 26.2.3 forbids host TR=0 (must select
 * a valid TSS in the GDT). Allocate our own GDT (copy of UEFI's + appended
 * TSS descriptor) and a 4KB TSS, point VMCS_HOST_GDTR_BASE / TR_SELECTOR /
 * TR_BASE at them.
 *
 * All allocations via EfiAllocateRuntimePages so they survive into VMM
 * runtime + are included in hostcr3 deep-clone.
 *
 * GDT / TSS contents are only consulted on VMEXIT (CPU loads HOST_GDTR /
 * HOST_TR from VMCS) — VMLAUNCH itself just checks the selector / base
 * fields are well-formed. So we don't need lgdt / ltr in firmware mode;
 * we only need the GDT to actually contain the descriptor we advertise.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>

#include "EfiCompat.h"

extern PVOID  EfiAllocateRuntimePages(UINTN Pages);
extern UINT64 asm_get_gdt_base(VOID);
extern UINT16 asm_get_gdt_limit(VOID);
extern VOID   hv_log(IN CONST CHAR8 *fmt, ...);

static UINT8  *g_host_gdt    = NULL;
static UINT8  *g_host_tss    = NULL;
static UINT64  g_host_gdt_pa = 0;
static UINT64  g_host_tss_pa = 0;
static UINT16  g_host_tr_sel = 0;

BOOLEAN
hostgdt_build(VOID)
{
    UINT64 src_base  = asm_get_gdt_base();
    UINT16 src_limit = asm_get_gdt_limit();

    if (src_limit > 0xF00) {
        hv_log("[hv] hostgdt: src GDT limit too big 0x%x\n", (UINT32)src_limit);
        return FALSE;
    }

    g_host_gdt = (UINT8 *)EfiAllocateRuntimePages(1);
    g_host_tss = (UINT8 *)EfiAllocateRuntimePages(1);
    if (!g_host_gdt || !g_host_tss) {
        hv_log("[hv] hostgdt: alloc failed\n");
        return FALSE;
    }
    ZeroMem(g_host_gdt, 4096);
    ZeroMem(g_host_tss, 4096);

    // Copy current UEFI GDT into our buffer.
    CopyMem(g_host_gdt, (VOID *)(UINTN)src_base, src_limit + 1u);

    // Place 64-bit TSS descriptor at the next 8-byte-aligned slot beyond the
    // current limit. Avoids stomping any in-use UEFI descriptor.
    UINT16 tr_sel = (UINT16)((src_limit + 1u + 7u) & ~7u);
    if (tr_sel < 0x40) tr_sel = 0x40;     // floor; we always need >= NULL slot
    if (tr_sel + 15u >= 4096) {
        hv_log("[hv] hostgdt: no room for TSS desc\n");
        return FALSE;
    }

    // Build 16-byte 64-bit TSS descriptor at the chosen slot.
    UINT64  tss_base  = (UINT64)(UINTN)g_host_tss;
    UINT32  tss_limit = 0x67;  // standard 64-bit TSS limit (104 bytes - 1)
    UINT64 *desc      = (UINT64 *)(g_host_gdt + tr_sel);

    desc[0] =  ((UINT64)tss_limit & 0xFFFFULL)                       /* limit[15:0]  */
            | ((tss_base & 0xFFFFFFULL) << 16)                       /* base[23:0]   */
            | (0x9ULL << 40)                                          /* type = avail 64-bit TSS */
            | (0ULL  << 44)                                           /* S=0 (system) */
            | (0ULL  << 45)                                           /* DPL=0        */
            | (1ULL  << 47)                                           /* P=1          */
            | ((UINT64)((tss_limit >> 16) & 0xFULL) << 48)            /* limit[19:16] */
            | (0ULL  << 52)                                           /* AVL=0        */
            | (0ULL  << 55)                                           /* G=0          */
            | (((tss_base >> 24) & 0xFFULL) << 56);                   /* base[31:24]  */
    desc[1] =  (tss_base >> 32) & 0xFFFFFFFFULL;                      /* base[63:32]  */

    g_host_gdt_pa = (UINT64)(UINTN)g_host_gdt;
    g_host_tss_pa = tss_base;
    g_host_tr_sel = tr_sel;

    hv_log("[hv] hostgdt built: gdt=0x%llx tss=0x%llx tr_sel=0x%x\n",
           g_host_gdt_pa, g_host_tss_pa, (UINT32)g_host_tr_sel);
    return TRUE;
}

UINT64 hostgdt_get_gdt_base(VOID) { return g_host_gdt_pa; }
UINT64 hostgdt_get_tss_base(VOID) { return g_host_tss_pa; }
UINT16 hostgdt_get_tr_sel  (VOID) { return g_host_tr_sel; }

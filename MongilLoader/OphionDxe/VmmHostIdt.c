/*
 * VmmHostIdt.c - private host IDT for VMX-root mode (Phase 2.7)
 *
 * Per MiniVisorPkg's design (https://github.com/tandasat/MiniVisorPkg) the
 * vmexit handler must run with HOST_IDTR pointing at OUR IDT, not firmware's.
 * After EBS Windows reclaims firmware IDT pages → first NMI/exception in
 * host mode triggers triple-fault → reboot loop. Matches our exact symptom.
 *
 * Layout: 256 16-byte 64-bit interrupt-gate descriptors, all pointing to
 * default handler (hlt loop). NMI/#DF/#GP overridden to specific handlers
 * declared in asm/AsmHostIdt.asm.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>

#include "EfiCompat.h"

extern PVOID EfiAllocateRuntimePages(UINTN Pages);
extern VOID  hv_log(IN CONST CHAR8 *fmt, ...);
extern UINT16 asm_get_cs(VOID);
extern VOID asm_host_nmi_handler(VOID);
extern VOID asm_host_df_handler(VOID);
extern VOID asm_host_gp_handler(VOID);
extern VOID asm_host_default_handler(VOID);

#define IDT_NUM_ENTRIES   256
#define IDT_TYPE_INT_GATE 0xE  // 64-bit interrupt gate (IF cleared on entry)

typedef struct {
    UINT16 OffsetLow;
    UINT16 Selector;
    UINT8  Ist : 3;
    UINT8  Reserved0 : 5;
    UINT8  Type : 4;
    UINT8  Zero : 1;
    UINT8  Dpl : 2;
    UINT8  Present : 1;
    UINT16 OffsetMid;
    UINT32 OffsetHigh;
    UINT32 Reserved1;
} HOST_IDT_GATE;

static HOST_IDT_GATE *g_host_idt    = NULL;
static UINT64         g_host_idt_pa = 0;

static VOID
host_idt_set(UINT32 vector, VOID *handler, UINT16 cs_sel)
{
    HOST_IDT_GATE *g = &g_host_idt[vector];
    UINT64 addr = (UINT64)(UINTN)handler;
    g->OffsetLow  = (UINT16)(addr & 0xFFFF);
    g->Selector   = cs_sel;
    g->Ist        = 0;
    g->Reserved0  = 0;
    g->Type       = IDT_TYPE_INT_GATE;
    g->Zero       = 0;
    g->Dpl        = 0;
    g->Present    = 1;
    g->OffsetMid  = (UINT16)((addr >> 16) & 0xFFFF);
    g->OffsetHigh = (UINT32)((addr >> 32) & 0xFFFFFFFF);
    g->Reserved1  = 0;
}

BOOLEAN
hostidt_build(VOID)
{
    g_host_idt = (HOST_IDT_GATE *)EfiAllocateRuntimePages(1);
    if (!g_host_idt) {
        hv_log("[hv] hostidt: alloc failed\n");
        return FALSE;
    }
    ZeroMem(g_host_idt, 4096);

    UINT16 cs_sel = asm_get_cs();

    for (UINT32 v = 0; v < IDT_NUM_ENTRIES; v++) {
        host_idt_set(v, (VOID *)asm_host_default_handler, cs_sel);
    }
    host_idt_set(2,  (VOID *)asm_host_nmi_handler,     cs_sel);
    host_idt_set(8,  (VOID *)asm_host_df_handler,      cs_sel);
    host_idt_set(13, (VOID *)asm_host_gp_handler,      cs_sel);

    g_host_idt_pa = (UINT64)(UINTN)g_host_idt;
    hv_log("[hv] hostidt built: pa=0x%llx cs=0x%x\n",
           g_host_idt_pa, (UINT32)cs_sel);
    return TRUE;
}

UINT64 hostidt_get_base(VOID) { return g_host_idt_pa; }

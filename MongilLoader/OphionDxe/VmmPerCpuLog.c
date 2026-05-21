/*
 * VmmPerCpuLog.c - per-CPU exit log ring implementation.
 *
 * Allocated once at VMM init, sized to g_cpu_count. Writers are the per-CPU
 * VMX-root vmexit handler; each CPU writes only its own ring so there is
 * no cross-CPU contention and no spinlock is needed.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

#include "EfiCompat.h"
#include "VmmPerCpuLog.h"

extern VOID hv_log(IN CONST CHAR8 *fmt, ...);

static VMM_PCL_RING *g_rings;
static UINT32        g_cpu_n;

VOID
VmmPclInit(IN UINT32 cpu_count)
{
    if (g_rings || cpu_count == 0) {
        return;
    }

    UINTN bytes = (UINTN)cpu_count * sizeof(VMM_PCL_RING);
    g_rings = (VMM_PCL_RING *)AllocateRuntimeZeroPool(bytes);
    if (!g_rings) {
        hv_log("[pcl] AllocateRuntimeZeroPool failed for %u rings\n", cpu_count);
        return;
    }
    g_cpu_n = cpu_count;
    hv_log("[pcl] initialized %u rings, %u records each, %u bytes total\n",
           cpu_count, (UINT32)VMM_PCL_RECORDS_PER_CPU, (UINT32)bytes);
}

VOID
VmmPclRecord(IN UINT32 cpu, IN UINT16 exit_reason, IN UINT64 exit_qual,
             IN UINT64 guest_rip, IN UINT32 tag)
{
    if (!g_rings || cpu >= g_cpu_n) {
        return;
    }

    VMM_PCL_RING *r = &g_rings[cpu];
    UINT32 idx = r->head;
    if (idx >= VMM_PCL_RECORDS_PER_CPU) {
        idx = 0;
    }

    VMM_PCL_RECORD *e = &r->records[idx];
    e->tsc          = AsmReadTsc();
    e->guest_rip    = guest_rip;
    e->exit_qual    = exit_qual;
    e->exit_reason  = exit_reason;
    e->reserved16   = 0;
    e->tag          = tag;

    UINT32 next = idx + 1;
    if (next >= VMM_PCL_RECORDS_PER_CPU) {
        next = 0;
    }
    r->head = next;
    r->seq++;
}

UINTN
VmmPclRequiredSize(VOID)
{
    if (!g_rings) {
        return 0;
    }
    return sizeof(UINT64) + sizeof(UINT32) + sizeof(UINT32)
         + (UINTN)g_cpu_n * sizeof(VMM_PCL_RING);
}

UINTN
VmmPclSnapshot(OUT VOID *dst, IN UINTN dst_size)
{
    UINTN need = VmmPclRequiredSize();
    if (!g_rings || !dst || dst_size < need) {
        return 0;
    }

    UINT8 *p = (UINT8 *)dst;
    *(UINT64 *)p = VMM_PCL_MAGIC;       p += sizeof(UINT64);
    *(UINT32 *)p = g_cpu_n;             p += sizeof(UINT32);
    *(UINT32 *)p = VMM_PCL_RECORDS_PER_CPU; p += sizeof(UINT32);

    CopyMem(p, g_rings, (UINTN)g_cpu_n * sizeof(VMM_PCL_RING));
    return need;
}

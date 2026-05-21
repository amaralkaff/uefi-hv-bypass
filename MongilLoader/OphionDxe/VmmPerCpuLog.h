/*
 * VmmPerCpuLog.h - per-CPU lock-free exit log ring (Grill Q21-C).
 *
 * Each CPU writes its own ring; no locking needed because the ring's
 * writer is the same logical thread (the CPU executing in VMX-root for
 * its vmexits). A reader (driver IOCTL_HV_GET_LOG, future crash dump
 * path) snapshots all rings under a memory barrier.
 *
 * Ring sizing: 32 records x 32 bytes = 1 KB per CPU. For typical
 * 12-core box that is 12 KB total, comfortably fits in a single
 * EfiRuntimeServicesData allocation.
 */
#pragma once

#include <Uefi.h>
#include "hv_types.h"

#define VMM_PCL_RECORDS_PER_CPU   32
#define VMM_PCL_MAGIC             0x4F50484E50434C00ULL  // "OPHNPCL\0"

typedef struct {
    UINT64 tsc;
    UINT64 guest_rip;
    UINT64 exit_qual;
    UINT16 exit_reason;
    UINT16 reserved16;
    UINT32 tag;          // free-form (dispatcher-defined op id, etc.)
} VMM_PCL_RECORD;

typedef struct {
    UINT32         head;        // next slot to write (mod VMM_PCL_RECORDS_PER_CPU)
    UINT32         seq;         // monotonic write count (incl. wrap)
    VMM_PCL_RECORD records[VMM_PCL_RECORDS_PER_CPU];
} VMM_PCL_RING;

VOID VmmPclInit(IN UINT32 cpu_count);
VOID VmmPclRecord(IN UINT32 cpu, IN UINT16 exit_reason, IN UINT64 exit_qual,
                  IN UINT64 guest_rip, IN UINT32 tag);

/*
 * Snapshot all rings to dst as a contiguous blob:
 *   [hdr: magic u64][cpu_count u32][rec_per_cpu u32][ring 0][ring 1]...
 *
 * Returns bytes written (0 if dst_size too small).
 */
UINTN VmmPclSnapshot(OUT VOID *dst, IN UINTN dst_size);

UINTN VmmPclRequiredSize(VOID);   // bytes needed for full snapshot

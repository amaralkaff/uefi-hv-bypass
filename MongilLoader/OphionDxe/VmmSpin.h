/*
 * VmmSpin.h - minimal test-and-set spinlock for VMX-root mode.
 *
 * No KeAcquireSpinLock available in DXE. Acquire disables interrupts and
 * spins on a UINT8 with InterlockedCompareExchange8. Caller restores IRQ
 * state via VmmSpinRelease.
 *
 * Usage (Step #8, Grill Q20-B):
 *   static VMM_SPIN g_session_lock;
 *   UINT64 flags = VmmSpinAcquire(&g_session_lock);
 *   ...critical section...
 *   VmmSpinRelease(&g_session_lock, flags);
 *
 * Lock order to avoid deadlock: session -> proc_cache -> ept -> log
 * (log is per-CPU, lock-free; included here only for completeness).
 *
 * NOTE: uses BaseLib EnableInterrupts/DisableInterrupts (NASM impls in
 * MdePkg) instead of MSVC _enable/_disable intrinsics, which are not
 * linkable in EDK2 DXE without a CRT.
 */
#pragma once

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <intrin.h>

typedef volatile CHAR8 VMM_SPIN;

static __inline UINT64
VmmSpinAcquire(VMM_SPIN *lock)
{
    UINT64 flags = __readeflags();
    DisableInterrupts();
    while (_InterlockedCompareExchange8(lock, 1, 0) != 0) {
        _mm_pause();
    }
    return flags;
}

static __inline VOID
VmmSpinRelease(VMM_SPIN *lock, UINT64 flags)
{
    // Release: store 0; barrier provided by Interlocked op semantics.
    _InterlockedExchange8(lock, 0);
    if (flags & 0x200ULL) {
        EnableInterrupts();
    }
}
